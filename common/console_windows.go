//go:build windows

package common

import (
	"fmt"
	"syscall"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/transform"
)

var (
	kernel32DLL = syscall.NewLazyDLL("kernel32.dll")
	procGetACP  = kernel32DLL.NewProc("GetACP")
)

// getSystemCodePage returns the Windows system code page.
func getSystemCodePage() uint32 {
	ret, _, _ := procGetACP.Call()
	return uint32(ret)
}

// codePageToEncoding maps a Windows code page number to a Go encoding.
func codePageToEncoding(cp uint32) encoding.Encoding {
	switch cp {
	case 949:
		return korean.EUCKR // CP949 (Korean)
	case 932:
		return japanese.ShiftJIS // CP932 (Japanese)
	case 936:
		return simplifiedchinese.GBK // CP936 (Simplified Chinese)
	case 950:
		return traditionalchinese.Big5 // CP950 (Traditional Chinese)
	case 874:
		return charmap.Windows874 // Thai
	case 1250:
		return charmap.Windows1250 // Central European
	case 1251:
		return charmap.Windows1251 // Cyrillic
	case 1252:
		return charmap.Windows1252 // Western European
	case 1253:
		return charmap.Windows1253 // Greek
	case 1254:
		return charmap.Windows1254 // Turkish
	case 1255:
		return charmap.Windows1255 // Hebrew
	case 1256:
		return charmap.Windows1256 // Arabic
	case 1257:
		return charmap.Windows1257 // Baltic
	case 1258:
		return charmap.Windows1258 // Vietnamese
	case 65001:
		return nil // UTF-8 — no conversion needed
	default:
		return nil
	}
}

// DecodeConsoleOutput converts Windows console output (system code page) to UTF-8.
// Dynamically detects the system code page via GetACP() and decodes with the correct encoding.
func DecodeConsoleOutput(data []byte) string {
	// No high bytes means pure ASCII — no conversion needed
	hasHighByte := false
	for _, b := range data {
		if b >= 0x80 {
			hasHighByte = true
			break
		}
	}
	if !hasHighByte {
		return string(data)
	}

	cp := getSystemCodePage()
	enc := codePageToEncoding(cp)
	if enc == nil {
		return string(data) // UTF-8 or unknown code page
	}

	decoded, _, err := transform.Bytes(enc.NewDecoder(), data)
	if err == nil {
		return string(decoded)
	}
	return string(data)
}

// SystemCodePageInfo returns current system code page information (for debugging/logging).
func SystemCodePageInfo() string {
	cp := getSystemCodePage()
	enc := codePageToEncoding(cp)
	name := "unknown"
	if enc != nil {
		name = fmt.Sprintf("%v", enc)
	} else if cp == 65001 {
		name = "UTF-8"
	}
	return fmt.Sprintf("CP%d (%s)", cp, name)
}
