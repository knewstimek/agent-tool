package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"agent-tool/common"
	"agent-tool/install"
	edit "agent-tool/tools/edit"
	"agent-tool/tools/glob"
	"agent-tool/tools/grep"
	"agent-tool/tools/read"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	args := os.Args[1:]

	// install 서브커맨드
	if len(args) > 0 && args[0] == "install" {
		target := ""
		if len(args) > 1 {
			target = args[1]
		}
		if err := install.Run(target); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// --fallback-encoding 옵션 파싱
	for i, arg := range args {
		if arg == "--fallback-encoding" && i+1 < len(args) {
			common.FallbackEncoding = args[i+1]
		}
	}

	// MCP 서버 실행
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "agent-tool",
			Version: "v0.1.0",
		},
		nil,
	)

	edit.Register(server)
	read.Register(server)
	grep.Register(server)
	glob.Register(server)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
