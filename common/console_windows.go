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

// getSystemCodePage는 Windows 시스템 코드페이지를 반환한다.
func getSystemCodePage() uint32 {
	ret, _, _ := procGetACP.Call()
	return uint32(ret)
}

// codePageToEncoding은 Windows 코드페이지 번호를 Go 인코딩으로 매핑한다.
func codePageToEncoding(cp uint32) encoding.Encoding {
	switch cp {
	case 949:
		return korean.EUCKR // CP949 (한국어)
	case 932:
		return japanese.ShiftJIS // CP932 (일본어)
	case 936:
		return simplifiedchinese.GBK // CP936 (중국어 간체)
	case 950:
		return traditionalchinese.Big5 // CP950 (중국어 번체)
	case 874:
		return charmap.Windows874 // 태국어
	case 1250:
		return charmap.Windows1250 // 중유럽
	case 1251:
		return charmap.Windows1251 // 키릴 문자
	case 1252:
		return charmap.Windows1252 // 서유럽
	case 1253:
		return charmap.Windows1253 // 그리스어
	case 1254:
		return charmap.Windows1254 // 터키어
	case 1255:
		return charmap.Windows1255 // 히브리어
	case 1256:
		return charmap.Windows1256 // 아랍어
	case 1257:
		return charmap.Windows1257 // 발트어
	case 1258:
		return charmap.Windows1258 // 베트남어
	case 65001:
		return nil // UTF-8 — 변환 불필요
	default:
		return nil
	}
}

// DecodeConsoleOutput은 Windows 콘솔 출력(시스템 코드페이지)을 UTF-8로 변환한다.
// GetACP()로 시스템 코드페이지를 동적으로 감지하여 올바른 인코딩으로 디코딩한다.
func DecodeConsoleOutput(data []byte) string {
	// high byte가 없으면 순수 ASCII — 변환 불필요
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
		return string(data) // UTF-8이거나 알 수 없는 코드페이지
	}

	decoded, _, err := transform.Bytes(enc.NewDecoder(), data)
	if err == nil {
		return string(decoded)
	}
	return string(data)
}

// SystemCodePageInfo는 현재 시스템 코드페이지 정보를 반환한다 (디버깅/로그용).
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
