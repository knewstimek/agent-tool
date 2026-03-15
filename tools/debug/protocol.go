package debug

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-dap"
)

// dapClient wraps a DAP connection (stdio pipes or TCP) and provides
// thread-safe request/response handling with sequence number management.
type dapClient struct {
	reader  *bufio.Reader
	writer  io.Writer
	writeMu sync.Mutex // serializes writes to the adapter

	seq atomic.Int32 // monotonically increasing request sequence number

	// pendingMu guards the pending map. Requests register a response channel
	// before sending, and the event loop delivers responses by request_seq.
	pendingMu sync.Mutex
	pending   map[int]chan dap.Message
}

// newDAPClient creates a DAP client wrapping the given reader/writer pair.
func newDAPClient(r io.Reader, w io.Writer) *dapClient {
	c := &dapClient{
		reader:  bufio.NewReader(r),
		writer:  w,
		pending: make(map[int]chan dap.Message),
	}
	return c
}

// nextSeq returns the next sequence number for a request.
func (c *dapClient) nextSeq() int {
	return int(c.seq.Add(1))
}

// sendRequest sends a DAP request and waits for its response.
// The caller must set the Seq field before calling this.
func (c *dapClient) sendRequest(msg dap.Message, timeout time.Duration) (dap.Message, error) {
	seq := getSeq(msg)
	ch := make(chan dap.Message, 1)

	// Register pending response channel before sending
	c.pendingMu.Lock()
	c.pending[seq] = ch
	c.pendingMu.Unlock()

	// Cleanup on exit
	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, seq)
		c.pendingMu.Unlock()
	}()

	// Ensure type/command fields are populated — go-dap does NOT auto-fill these.
	autoSetRequestFields(msg)

	// Send the request
	c.writeMu.Lock()
	err := dap.WriteProtocolMessage(c.writer, msg)
	c.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to send DAP request: %w", err)
	}

	// Wait for response
	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("DAP request timed out after %v (seq=%d)", timeout, seq)
	}
}

// sendRequestAsync sends a DAP request without waiting for its response.
// Returns a channel that will receive the response when it arrives, and a
// cleanup function that must be called when the channel is no longer needed.
func (c *dapClient) sendRequestAsync(msg dap.Message) (chan dap.Message, func(), error) {
	seq := getSeq(msg)
	ch := make(chan dap.Message, 1)

	c.pendingMu.Lock()
	c.pending[seq] = ch
	c.pendingMu.Unlock()

	cleanup := func() {
		c.pendingMu.Lock()
		delete(c.pending, seq)
		c.pendingMu.Unlock()
	}

	autoSetRequestFields(msg)

	c.writeMu.Lock()
	err := dap.WriteProtocolMessage(c.writer, msg)
	c.writeMu.Unlock()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to send DAP request: %w", err)
	}

	return ch, cleanup, nil
}

// deliverResponse routes a response to the waiting request goroutine.
// Called by the event loop when a response message is received.
func (c *dapClient) deliverResponse(msg dap.Message, requestSeq int) {
	c.pendingMu.Lock()
	ch, ok := c.pending[requestSeq]
	c.pendingMu.Unlock()
	if ok {
		// Non-blocking send — if the requester already timed out, drop silently
		select {
		case ch <- msg:
		default:
		}
	}
}

// readMessage reads a single DAP message from the connection.
// Non-standard events (e.g. debugpy's "debugpySockets") cause
// go-dap's DecodeProtocolMessage to return DecodeProtocolMessageFieldError.
// We handle reverse requests (e.g. vsdbg's "handshake") and skip
// unrecognized events so the event loop doesn't die.
func (c *dapClient) readMessage() (dap.Message, error) {
	for {
		content, err := dap.ReadBaseMessage(c.reader)
		if err != nil {
			return nil, err
		}
		msg, err := dap.DecodeProtocolMessage(content)
		if err != nil {
			if _, ok := err.(*dap.DecodeProtocolMessageFieldError); ok {
				// Try to handle reverse requests (adapter→client).
				// Some adapters (e.g. vsdbg) send non-standard reverse
				// requests and block until they receive a response.
				c.tryHandleReverseRequest(content)
				continue
			}
			return nil, err
		}
		return msg, nil
	}
}

// tryHandleReverseRequest checks if raw DAP content is a reverse request
// from the adapter and sends an appropriate response. This handles
// non-standard requests like vsdbg's "handshake" that go-dap can't parse.
func (c *dapClient) tryHandleReverseRequest(content []byte) {
	var raw struct {
		Seq       int             `json:"seq"`
		Type      string          `json:"type"`
		Command   string          `json:"command"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
	}
	if err := json.Unmarshal(content, &raw); err != nil || raw.Type != "request" {
		return // not a request — skip
	}

	body := map[string]interface{}{}

	// vsdbg sends a "handshake" reverse request with a base64 challenge.
	// We must sign it using VS Code's vsda.node module and return the
	// signature, otherwise vsdbg rejects the connection.
	if raw.Command == "handshake" && len(raw.Arguments) > 0 {
		var args struct {
			Value string `json:"value"`
		}
		if json.Unmarshal(raw.Arguments, &args) == nil && args.Value != "" {
			if sig, _, err := signVsdaChallenge(args.Value); err == nil {
				body["signature"] = sig
			}
			// If signing fails, still send response — vsdbg may
			// accept empty signature in some configurations.
		}
	}

	resp := map[string]interface{}{
		"seq":         c.nextSeq(),
		"type":        "response",
		"request_seq": raw.Seq,
		"command":     raw.Command,
		"success":     true,
		"body":        body,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		return
	}

	// Write raw DAP message (Content-Length header + JSON body)
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err = io.WriteString(c.writer, header); err != nil {
		return // Don't send partial message — would corrupt protocol stream
	}
	_, _ = c.writer.Write(data)
}

// getSeq extracts the Seq field from a DAP message.
func getSeq(msg dap.Message) int {
	return msg.GetSeq()
}

// getResponseRequestSeq extracts the request_seq from a DAP response.
// Returns -1 if the message is not a response type.
func getResponseRequestSeq(msg dap.Message) int {
	// All DAP response types embed dap.Response which has RequestSeq.
	// Use JSON round-trip to extract it generically since go-dap uses
	// concrete types rather than a common Response interface.
	data, err := json.Marshal(msg)
	if err != nil {
		return -1
	}
	var raw struct {
		Type       string `json:"type"`
		RequestSeq int    `json:"request_seq"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return -1
	}
	if raw.Type == "response" {
		return raw.RequestSeq
	}
	return -1
}

// autoSetRequestFields populates the required ProtocolMessage.Type and
// Request.Command fields that go-dap does NOT auto-fill on Marshal.
// Without these, adapters receive {"type":"","command":""} and reject the request.
func autoSetRequestFields(msg dap.Message) {
	switch r := msg.(type) {
	case *dap.InitializeRequest:
		r.Type, r.Command = "request", "initialize"
	case *dap.LaunchRequest:
		r.Type, r.Command = "request", "launch"
	case *dap.AttachRequest:
		r.Type, r.Command = "request", "attach"
	case *dap.ConfigurationDoneRequest:
		r.Type, r.Command = "request", "configurationDone"
	case *dap.SetBreakpointsRequest:
		r.Type, r.Command = "request", "setBreakpoints"
	case *dap.SetExceptionBreakpointsRequest:
		r.Type, r.Command = "request", "setExceptionBreakpoints"
	case *dap.ContinueRequest:
		r.Type, r.Command = "request", "continue"
	case *dap.NextRequest:
		r.Type, r.Command = "request", "next"
	case *dap.StepInRequest:
		r.Type, r.Command = "request", "stepIn"
	case *dap.StepOutRequest:
		r.Type, r.Command = "request", "stepOut"
	case *dap.PauseRequest:
		r.Type, r.Command = "request", "pause"
	case *dap.ThreadsRequest:
		r.Type, r.Command = "request", "threads"
	case *dap.StackTraceRequest:
		r.Type, r.Command = "request", "stackTrace"
	case *dap.ScopesRequest:
		r.Type, r.Command = "request", "scopes"
	case *dap.VariablesRequest:
		r.Type, r.Command = "request", "variables"
	case *dap.EvaluateRequest:
		r.Type, r.Command = "request", "evaluate"
	case *dap.DisconnectRequest:
		r.Type, r.Command = "request", "disconnect"
	// Extended operations (operations_ext.go)
	case *dap.BreakpointLocationsRequest:
		r.Type, r.Command = "request", "breakpointLocations"
	case *dap.SetFunctionBreakpointsRequest:
		r.Type, r.Command = "request", "setFunctionBreakpoints"
	case *dap.SetDataBreakpointsRequest:
		r.Type, r.Command = "request", "setDataBreakpoints"
	case *dap.DataBreakpointInfoRequest:
		r.Type, r.Command = "request", "dataBreakpointInfo"
	case *dap.SetInstructionBreakpointsRequest:
		r.Type, r.Command = "request", "setInstructionBreakpoints"
	case *dap.StepBackRequest:
		r.Type, r.Command = "request", "stepBack"
	case *dap.ReverseContinueRequest:
		r.Type, r.Command = "request", "reverseContinue"
	case *dap.RestartFrameRequest:
		r.Type, r.Command = "request", "restartFrame"
	case *dap.GotoRequest:
		r.Type, r.Command = "request", "goto"
	case *dap.GotoTargetsRequest:
		r.Type, r.Command = "request", "gotoTargets"
	case *dap.StepInTargetsRequest:
		r.Type, r.Command = "request", "stepInTargets"
	case *dap.SetVariableRequest:
		r.Type, r.Command = "request", "setVariable"
	case *dap.SetExpressionRequest:
		r.Type, r.Command = "request", "setExpression"
	case *dap.CompletionsRequest:
		r.Type, r.Command = "request", "completions"
	case *dap.ExceptionInfoRequest:
		r.Type, r.Command = "request", "exceptionInfo"
	case *dap.SourceRequest:
		r.Type, r.Command = "request", "source"
	case *dap.ModulesRequest:
		r.Type, r.Command = "request", "modules"
	case *dap.LoadedSourcesRequest:
		r.Type, r.Command = "request", "loadedSources"
	case *dap.DisassembleRequest:
		r.Type, r.Command = "request", "disassemble"
	case *dap.ReadMemoryRequest:
		r.Type, r.Command = "request", "readMemory"
	case *dap.WriteMemoryRequest:
		r.Type, r.Command = "request", "writeMemory"
	case *dap.TerminateRequest:
		r.Type, r.Command = "request", "terminate"
	case *dap.RestartRequest:
		r.Type, r.Command = "request", "restart"
	case *dap.CancelRequest:
		r.Type, r.Command = "request", "cancel"
	case *dap.TerminateThreadsRequest:
		r.Type, r.Command = "request", "terminateThreads"
	}
}

// handleStandardReverseRequest detects DAP reverse requests (adapter → client)
// that go-dap successfully parses and sends an appropriate response.
//
// Standard reverse requests:
//   - runInTerminal: adapter asks client to launch a process in a terminal.
//     We can't do this (no terminal), so we respond with an error.
//     The adapter should fall back to launching the process itself.
//   - startDebugging: adapter asks client to start a child debug session.
//     Not supported — respond with error.
//
// Returns true if the message was handled as a reverse request.
func (c *dapClient) handleStandardReverseRequest(msg dap.Message) bool {
	switch req := msg.(type) {
	case *dap.RunInTerminalRequest:
		resp := &dap.RunInTerminalResponse{}
		resp.Seq = c.nextSeq()
		resp.Type = "response"
		resp.Command = "runInTerminal"
		resp.RequestSeq = req.Seq
		resp.Success = false
		resp.Message = "runInTerminal not supported by this client"
		c.writeMu.Lock()
		_ = dap.WriteProtocolMessage(c.writer, resp)
		c.writeMu.Unlock()
		return true
	default:
		return false
	}
}

// isResponseSuccess checks if a DAP response indicates success.
func isResponseSuccess(msg dap.Message) (bool, string) {
	data, err := json.Marshal(msg)
	if err != nil {
		return false, "failed to marshal response"
	}
	var raw struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return false, "failed to parse response"
	}
	return raw.Success, raw.Message
}
