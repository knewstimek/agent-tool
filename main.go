package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"agent-tool/common"
	"agent-tool/install"
	"agent-tool/tools/backup"
	"agent-tool/tools/checksum"
	"agent-tool/tools/compress"
	"agent-tool/tools/config"
	"agent-tool/tools/convertenc"
	"agent-tool/tools/diff"
	edit "agent-tool/tools/edit"
	"agent-tool/tools/fileinfo"
	"agent-tool/tools/findtools"
	"agent-tool/tools/glob"
	"agent-tool/tools/grep"
	"agent-tool/tools/help"
	"agent-tool/tools/listdir"
	"agent-tool/tools/patch"
	"agent-tool/tools/read"
	"agent-tool/tools/write"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	args := os.Args[1:]

	// install / uninstall 서브커맨드
	if len(args) > 0 && (args[0] == "install" || args[0] == "uninstall") {
		target := ""
		if len(args) > 1 {
			target = args[1]
		}
		var err error
		if args[0] == "install" {
			err = install.Run(target)
		} else {
			err = install.Uninstall(target)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// fallback-encoding 설정 (우선순위: CLI > 환경변수 > 기본값)
	// 1. 환경변수에서 읽기
	if envEnc := os.Getenv("AGENT_TOOL_FALLBACK_ENCODING"); envEnc != "" {
		if normalized := config.NormalizeAndValidate(envEnc); normalized != "" {
			common.SetFallbackEncoding(normalized)
		} else {
			common.SetFallbackEncoding(strings.ToUpper(strings.TrimSpace(envEnc)))
		}
	}
	// 2. CLI 옵션 (환경변수보다 우선)
	for i, arg := range args {
		if arg == "--fallback-encoding" && i+1 < len(args) {
			enc := args[i+1]
			normalized := config.NormalizeAndValidate(enc)
			if normalized == "" {
				fmt.Fprintf(os.Stderr, "warning: unknown encoding %q, using as-is. Supported: UTF-8, EUC-KR, Shift_JIS, ISO-8859-1, etc.\n", enc)
				common.SetFallbackEncoding(strings.ToUpper(strings.TrimSpace(enc)))
			} else {
				common.SetFallbackEncoding(normalized)
			}
		}
	}

	// MCP 서버 실행
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "agent-tool",
			Version: "v0.3.0",
		},
		nil,
	)

	edit.Register(server)
	read.Register(server)
	write.Register(server)
	grep.Register(server)
	glob.Register(server)
	listdir.Register(server)
	compress.RegisterCompress(server)
	compress.RegisterDecompress(server)
	backup.Register(server)
	config.Register(server)
	convertenc.Register(server)
	checksum.Register(server)
	fileinfo.Register(server)
	diff.Register(server)
	patch.Register(server)
	findtools.Register(server)
	help.Register(server)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
