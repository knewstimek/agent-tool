package common

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/ianaindex"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// DefaultMaxFileSize는 기본 최대 파일 크기이다 (50MB).
const DefaultMaxFileSize int64 = 50 * 1024 * 1024

// chardetSampleSize는 인코딩 감지에 사용할 최대 바이트 수이다.
// chardet은 전체 파일이 필요하지 않으며, 앞부분 샘플만으로 충분히 판정 가능하다.
const chardetSampleSize = 64 * 1024 // 64KB

// EncodingInfo는 파일의 인코딩 정보를 담는다.
type EncodingInfo struct {
	Charset    string // IANA 이름: "UTF-8", "EUC-KR", "Shift_JIS" 등
	HasBOM     bool   // UTF-8 BOM 존재 여부
	Confidence int    // chardet 감지 신뢰도 (0-100). 힌트/BOM/폴백 사용 시 100.
	UsedSource string // 인코딩 결정 출처: "bom", "hint", "chardet", "fallback"
}

var (
	// fallbackEncoding은 chardet 감지 실패 시 사용할 폴백 인코딩이다.
	fallbackEncoding   = "UTF-8"
	fallbackMu         sync.RWMutex
	// encodingWarnings는 인코딩 감지 경고 메시지 출력 여부이다.
	encodingWarnings   = true
	encodingWarningsMu sync.RWMutex
	// maxFileSize는 ReadFileWithEncoding이 허용하는 최대 파일 크기이다.
	// set_config의 max_file_size로 런타임에 변경 가능하다.
	maxFileSize   = DefaultMaxFileSize
	maxFileSizeMu sync.RWMutex
	// allowSymlinks는 압축 해제 시 symlink 생성 허용 여부이다.
	// 기본값 false (보안상 스킵). set_config의 allow_symlinks로 변경 가능.
	allowSymlinks   = false
	allowSymlinksMu sync.RWMutex
)

// GetFallbackEncoding은 현재 폴백 인코딩을 스레드 안전하게 반환한다.
func GetFallbackEncoding() string {
	fallbackMu.RLock()
	defer fallbackMu.RUnlock()
	return fallbackEncoding
}

// SetFallbackEncoding은 폴백 인코딩을 스레드 안전하게 변경한다.
func SetFallbackEncoding(enc string) {
	fallbackMu.Lock()
	defer fallbackMu.Unlock()
	fallbackEncoding = enc
}

// GetEncodingWarnings는 인코딩 경고 활성화 여부를 반환한다.
func GetEncodingWarnings() bool {
	encodingWarningsMu.RLock()
	defer encodingWarningsMu.RUnlock()
	return encodingWarnings
}

// SetEncodingWarnings는 인코딩 경고 활성화 여부를 설정한다.
func SetEncodingWarnings(enabled bool) {
	encodingWarningsMu.Lock()
	defer encodingWarningsMu.Unlock()
	encodingWarnings = enabled
}

// GetMaxFileSize는 현재 최대 파일 크기 제한을 반환한다.
func GetMaxFileSize() int64 {
	maxFileSizeMu.RLock()
	defer maxFileSizeMu.RUnlock()
	return maxFileSize
}

// SetMaxFileSize는 최대 파일 크기 제한을 변경한다. 최소 1MB.
func SetMaxFileSize(size int64) {
	if size < 1*1024*1024 {
		size = 1 * 1024 * 1024
	}
	maxFileSizeMu.Lock()
	defer maxFileSizeMu.Unlock()
	maxFileSize = size
}

// GetAllowSymlinks는 symlink 허용 여부를 반환한다.
func GetAllowSymlinks() bool {
	allowSymlinksMu.RLock()
	defer allowSymlinksMu.RUnlock()
	return allowSymlinks
}

// SetAllowSymlinks는 symlink 허용 여부를 설정한다.
func SetAllowSymlinks(allow bool) {
	allowSymlinksMu.Lock()
	defer allowSymlinksMu.Unlock()
	allowSymlinks = allow
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ReadFileWithEncoding은 파일을 읽고 UTF-8 텍스트와 인코딩 정보를 반환한다.
// hintCharset이 비어있지 않으면 (.editorconfig 등에서 온 힌트) 최우선으로 사용한다.
func ReadFileWithEncoding(path string, hintCharset string) (string, EncodingInfo, error) {
	// symlink 검사: allow_symlinks가 false이면 symlink 차단
	if !GetAllowSymlinks() {
		if lfi, err := os.Lstat(path); err == nil && lfi.Mode()&os.ModeSymlink != 0 {
			return "", EncodingInfo{}, fmt.Errorf("symlink not allowed: %s (enable via set_config allow_symlinks=true)", path)
		}
	}

	// OOM 방지: 파일 크기 사전 체크
	limit := GetMaxFileSize()
	fi, err := os.Stat(path)
	if err != nil {
		return "", EncodingInfo{}, fmt.Errorf("파일 접근 실패: %w", err)
	}
	if fi.Size() > limit {
		return "", EncodingInfo{}, fmt.Errorf("파일이 너무 큼 (%d bytes, 최대 %d bytes). set_config의 max_file_size로 상한 변경 가능", fi.Size(), limit)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", EncodingInfo{}, fmt.Errorf("파일 읽기 실패: %w", err)
	}

	info := EncodingInfo{Charset: "UTF-8", Confidence: 100, UsedSource: "bom"}

	// UTF-8 BOM 확인 (BOM은 항상 최우선)
	if bytes.HasPrefix(raw, utf8BOM) {
		info.HasBOM = true
		raw = raw[len(utf8BOM):]
		return string(raw), info, nil
	}

	// 빈 파일
	if len(raw) == 0 {
		info.UsedSource = "fallback"
		return "", info, nil
	}

	// 인코딩 결정 우선순위:
	// 1. .editorconfig charset 힌트 (hintCharset)
	// 2. chardet 자동 감지 (Confidence >= 50)
	// 3. FallbackEncoding (기본 UTF-8, CLI로 변경 가능)

	charset := ""

	// 1. 힌트 charset
	if hintCharset != "" {
		charset = normalizeCharsetName(hintCharset)
		info.Confidence = 100
		info.UsedSource = "hint"
	}

	// 2. chardet 감지 (앞부분 샘플만 사용 — 전체 파일 불필요)
	if charset == "" {
		sample := raw
		if len(sample) > chardetSampleSize {
			sample = sample[:chardetSampleSize]
		}
		detector := chardet.NewTextDetector()
		result, detectErr := detector.DetectBest(sample)
		if detectErr == nil && result.Confidence >= 50 {
			charset = normalizeCharsetName(result.Charset)
			info.Confidence = result.Confidence
			info.UsedSource = "chardet"
		}
	}

	// 3. 폴백
	if charset == "" {
		charset = normalizeCharsetName(GetFallbackEncoding())
		info.Confidence = 0
		info.UsedSource = "fallback"
	}

	info.Charset = charset

	// UTF-8이면 그대로 반환
	if info.Charset == "UTF-8" {
		return string(raw), info, nil
	}

	// 다른 인코딩이면 UTF-8로 디코딩
	enc, err := ianaindex.IANA.Encoding(info.Charset)
	if err != nil || enc == nil {
		info.Charset = "UTF-8"
		return string(raw), info, nil
	}

	decoded, err := decodeBytes(raw, enc)
	if err != nil {
		info.Charset = "UTF-8"
		return string(raw), info, nil
	}

	return decoded, info, nil
}

// WriteFileWithEncoding은 UTF-8 텍스트를 원래 인코딩으로 변환하여 저장한다.
func WriteFileWithEncoding(path string, content string, info EncodingInfo) error {
	// 원본 파일의 퍼미션 유지
	perm := os.FileMode(0644)
	if fi, err := os.Stat(path); err == nil {
		perm = fi.Mode().Perm()
	}

	var data []byte

	if info.HasBOM {
		data = append(utf8BOM, []byte(content)...)
	} else if info.Charset == "UTF-8" || info.Charset == "" {
		data = []byte(content)
	} else {
		enc, err := ianaindex.IANA.Encoding(info.Charset)
		if err != nil || enc == nil {
			data = []byte(content)
		} else {
			encoded, err := encodeString(content, enc)
			if err != nil {
				return fmt.Errorf("인코딩 변환 실패 (%s): %w", info.Charset, err)
			}
			data = encoded
		}
	}

	return os.WriteFile(path, data, perm)
}

// DetectLineEnding은 텍스트의 줄바꿈 문자를 감지한다.
func DetectLineEnding(content string) string {
	if bytes.Contains([]byte(content), []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

// normalizeCharsetName은 .editorconfig의 charset 값을 IANA 이름으로 정규화한다.
func normalizeCharsetName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "utf-8", "utf8":
		return "UTF-8"
	case "utf-8-bom":
		return "UTF-8" // BOM은 별도 처리
	case "euc-kr", "euckr":
		return "EUC-KR"
	case "shift_jis", "shift-jis", "shiftjis", "sjis":
		return "Shift_JIS"
	case "latin1", "iso-8859-1":
		return "ISO-8859-1"
	case "utf-16be":
		return "UTF-16BE"
	case "utf-16le":
		return "UTF-16LE"
	default:
		return strings.ToUpper(name)
	}
}

// EncodingWarning은 인코딩 감지 신뢰도가 낮을 때 경고 메시지를 반환한다.
// 경고가 없으면 빈 문자열을 반환한다.
func EncodingWarning(info EncodingInfo) string {
	if !GetEncodingWarnings() {
		return ""
	}
	if info.UsedSource == "fallback" && info.Confidence == 0 && info.Charset == "UTF-8" {
		return "\n⚠ Encoding detection failed (low confidence). " +
			"If text looks garbled, set --fallback-encoding (e.g. EUC-KR) " +
			"or add 'charset = euc-kr' to .editorconfig."
	}
	if info.UsedSource == "chardet" && info.Confidence < 70 {
		return fmt.Sprintf("\n⚠ Encoding detected as %s (confidence: %d%%). "+
			"If text looks wrong, add 'charset' to .editorconfig for reliable detection.",
			info.Charset, info.Confidence)
	}
	return ""
}

// decodeBytes는 enc 인코딩의 바이트를 UTF-8 문자열로 디코딩한다.
func decodeBytes(raw []byte, enc encoding.Encoding) (string, error) {
	reader := transform.NewReader(bytes.NewReader(raw), enc.NewDecoder())
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// encodeString은 UTF-8 문자열을 enc 인코딩 바이트로 변환한다.
func encodeString(s string, enc encoding.Encoding) ([]byte, error) {
	// UTF-8 계열은 변환 불필요. BOM 접두사는 WriteFileWithEncoding에서 별도 처리한다.
	if enc == unicode.UTF8 || enc == unicode.UTF8BOM {
		return []byte(s), nil
	}
	var buf bytes.Buffer
	writer := transform.NewWriter(&buf, enc.NewEncoder())
	_, err := writer.Write([]byte(s))
	if err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
