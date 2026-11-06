package common

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"unicode/utf8"
)

// BoundedCapture consumes an unlimited byte stream while retaining a bounded,
// representative head and tail. It always reports the original byte count so
// callers can make truncation visible instead of silently discarding output.
type BoundedCapture struct {
	mu    sync.Mutex
	limit int
	mode  string
	total int64
	head  []byte
	tail  []byte
}

func NewBoundedCapture(limit int) *BoundedCapture {
	return NewBoundedCaptureMode(limit, "head_tail")
}

func NewBoundedCaptureMode(limit int, mode string) *BoundedCapture {
	if limit < 0 {
		limit = 0
	}
	if mode != "head" && mode != "tail" {
		mode = "head_tail"
	}
	return &BoundedCapture{limit: limit, mode: mode}
}

func (c *BoundedCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	originalLen := len(p)
	c.total += int64(originalLen)
	if c.limit == 0 {
		return originalLen, nil
	}
	headLimit, tailLimit := (c.limit+1)/2, c.limit/2
	if c.mode == "head" {
		headLimit, tailLimit = c.limit, 0
	} else if c.mode == "tail" {
		headLimit, tailLimit = 0, c.limit
	}
	if len(c.head) < headLimit {
		n := headLimit - len(c.head)
		if n > len(p) {
			n = len(p)
		}
		c.head = append(c.head, p[:n]...)
		p = p[n:]
	}
	if tailLimit > 0 && len(p) > 0 {
		c.tail = append(c.tail, p...)
		if len(c.tail) > tailLimit {
			c.tail = append([]byte(nil), c.tail[len(c.tail)-tailLimit:]...)
		}
	}
	return originalLen, nil
}

// Result returns valid UTF-8 output plus truncation metadata. Invalid or split
// byte sequences are replaced rather than leaking malformed text to MCP JSON.
func (c *BoundedCapture) Result() (text string, totalBytes int64, truncated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return joinHeadTail(c.head, c.tail, c.total, c.limit)
}

func joinHeadTail(head, tail []byte, totalBytes int64, limit int) (string, int64, bool) {
	replacement := []byte(string(utf8.RuneError))
	if totalBytes <= int64(limit) {
		combined := append(append([]byte(nil), head...), tail...)
		return string(bytes.ToValidUTF8(combined, replacement)), totalBytes, false
	}
	marker := []byte(fmt.Sprintf("\n...[truncated; original_bytes=%d; retained_bytes=%d]...\n", totalBytes, limit))
	combined := make([]byte, 0, len(head)+len(marker)+len(tail))
	combined = append(combined, bytes.ToValidUTF8(head, replacement)...)
	combined = append(combined, marker...)
	combined = append(combined, bytes.ToValidUTF8(tail, replacement)...)
	return string(bytes.ToValidUTF8(combined, replacement)), totalBytes, true
}

// FileCapture presents a log file that a detached process writes directly as
// a bounded head+tail view. Background jobs log to files instead of pipes so
// the child does not die of a broken pipe when agent-tool exits or restarts.
type FileCapture struct {
	Path  string
	limit int
}

func NewFileCapture(path string, limit int) *FileCapture {
	if limit < 0 {
		limit = 0
	}
	return &FileCapture{Path: path, limit: limit}
}

func (c *FileCapture) Result() (string, int64, bool) {
	f, err := os.Open(c.Path)
	if err != nil {
		return "", 0, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, false
	}
	size := fi.Size()
	if size <= int64(c.limit) {
		data, _ := io.ReadAll(io.LimitReader(f, int64(c.limit)))
		return joinHeadTail(data, nil, int64(len(data)), c.limit)
	}
	head := make([]byte, (c.limit+1)/2)
	n, _ := f.ReadAt(head, 0)
	tail := make([]byte, c.limit/2)
	m, _ := f.ReadAt(tail, size-int64(len(tail)))
	return joinHeadTail(head[:n], tail[:m], size, c.limit)
}
