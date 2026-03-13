package compress

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// maxSingleFileSize는 압축 해제 시 단일 파일의 최대 크기이다 (1GB).
	maxSingleFileSize int64 = 1 << 30
	// maxTotalExtractSize는 압축 해제 시 전체 추출 크기 상한이다 (5GB).
	maxTotalExtractSize int64 = 5 << 30
)

type CompressInput struct {
	Sources []string `json:"sources" jsonschema:"description=List of absolute paths to files or directories to compress"`
	Output  string   `json:"output" jsonschema:"description=Absolute path for the output archive file (.zip or .tar.gz)"`
}

type CompressOutput struct {
	Result    string `json:"result"`
	FileCount int    `json:"file_count"`
}

type DecompressInput struct {
	Archive string `json:"archive" jsonschema:"description=Absolute path to the archive file (.zip or .tar.gz)"`
	Output  string `json:"output" jsonschema:"description=Absolute path to the output directory"`
}

type DecompressOutput struct {
	Result    string `json:"result"`
	FileCount int    `json:"file_count"`
}

func HandleCompress(ctx context.Context, req *mcp.CallToolRequest, input CompressInput) (*mcp.CallToolResult, CompressOutput, error) {
	if len(input.Sources) == 0 {
		return compressError("sources is required (at least one path)")
	}
	if input.Output == "" {
		return compressError("output is required")
	}
	if !filepath.IsAbs(input.Output) {
		return compressError("output must be an absolute path")
	}

	// 소스 경로 검증
	for _, src := range input.Sources {
		if !filepath.IsAbs(src) {
			return compressError(fmt.Sprintf("source path must be absolute: %s", src))
		}
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				return compressError(fmt.Sprintf("source not found: %s", src))
			}
			return compressError(fmt.Sprintf("cannot access source: %v", err))
		}
	}

	// 출력 디렉토리 생성
	if err := os.MkdirAll(filepath.Dir(input.Output), 0755); err != nil {
		return compressError(fmt.Sprintf("failed to create output directory: %v", err))
	}

	var count int
	var err error

	ext := strings.ToLower(input.Output)
	switch {
	case strings.HasSuffix(ext, ".tar.gz") || strings.HasSuffix(ext, ".tgz"):
		count, err = createTarGz(input.Output, input.Sources)
	case strings.HasSuffix(ext, ".zip"):
		count, err = createZip(input.Output, input.Sources)
	default:
		return compressError("unsupported format: use .zip or .tar.gz")
	}

	if err != nil {
		return compressError(fmt.Sprintf("compression failed: %v", err))
	}

	msg := fmt.Sprintf("OK: compressed %d files → %s", count, input.Output)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, CompressOutput{Result: msg, FileCount: count}, nil
}

func HandleDecompress(ctx context.Context, req *mcp.CallToolRequest, input DecompressInput) (*mcp.CallToolResult, DecompressOutput, error) {
	if input.Archive == "" {
		return decompressError("archive is required")
	}
	if input.Output == "" {
		return decompressError("output is required")
	}
	if !filepath.IsAbs(input.Archive) {
		return decompressError("archive must be an absolute path")
	}
	if !filepath.IsAbs(input.Output) {
		return decompressError("output must be an absolute path")
	}

	if _, err := os.Stat(input.Archive); err != nil {
		if os.IsNotExist(err) {
			return decompressError(fmt.Sprintf("archive not found: %s", input.Archive))
		}
		return decompressError(fmt.Sprintf("cannot access archive: %v", err))
	}

	if err := os.MkdirAll(input.Output, 0755); err != nil {
		return decompressError(fmt.Sprintf("failed to create output directory: %v", err))
	}

	var count, skippedSymlinks int
	var err error

	ext := strings.ToLower(input.Archive)
	switch {
	case strings.HasSuffix(ext, ".tar.gz") || strings.HasSuffix(ext, ".tgz"):
		count, skippedSymlinks, err = extractTarGz(input.Archive, input.Output)
	case strings.HasSuffix(ext, ".zip"):
		count, skippedSymlinks, err = extractZip(input.Archive, input.Output)
	default:
		return decompressError("unsupported format: use .zip or .tar.gz")
	}

	if err != nil {
		return decompressError(fmt.Sprintf("decompression failed: %v", err))
	}

	msg := fmt.Sprintf("OK: extracted %d files → %s", count, input.Output)
	if skippedSymlinks > 0 {
		msg += fmt.Sprintf(" (skipped %d symlinks)", skippedSymlinks)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, DecompressOutput{Result: msg, FileCount: count}, nil
}

// --- ZIP ---

func createZip(output string, sources []string) (int, error) {
	f, err := os.Create(output)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	count := 0
	for _, src := range sources {
		fi, err := os.Stat(src)
		if err != nil {
			return count, fmt.Errorf("cannot stat source: %w", err)
		}
		if fi.IsDir() {
			base := filepath.Dir(src)
			err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(base, path)
				return addFileToZip(w, path, filepath.ToSlash(rel), &count)
			})
			if err != nil {
				return count, err
			}
		} else {
			err := addFileToZip(w, src, filepath.Base(src), &count)
			if err != nil {
				return count, err
			}
		}
	}
	return count, nil
}

func addFileToZip(w *zip.Writer, filePath, archivePath string, count *int) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = archivePath
	header.Method = zip.Deflate

	writer, err := w.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, f)
	if err != nil {
		return err
	}

	*count++
	return nil
}

func extractZip(archive, outputDir string) (int, int, error) {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return 0, 0, err
	}
	defer r.Close()

	count := 0
	skippedSymlinks := 0
	var totalSize int64
	cleanOutputDir := filepath.Clean(outputDir) + string(os.PathSeparator)

	for _, f := range r.File {
		target := filepath.Join(outputDir, filepath.FromSlash(f.Name))

		// Zip Slip 방지: filepath.Join이 "../"를 해소한 뒤, 최종 경로가 outputDir 안에
		// 있는지 확인한다. outputDir 자체(디렉토리 엔트리)도 허용.
		// 예: "../../etc/passwd" → Join+Clean → "/etc/passwd" → outputDir 밖 → 스킵
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), cleanOutputDir) &&
			filepath.Clean(target) != filepath.Clean(outputDir) {
			continue
		}

		// ZIP symlink: Go의 archive/zip은 symlink target 읽기를 표준 지원하지 않으므로
		// allow_symlinks 설정과 무관하게 항상 스킵한다.
		// (tar와 달리 zip에서 symlink target은 파일 내용으로 저장되어 안전한 검증이 어려움)
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			skippedSymlinks++
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}

		// Zip Bomb 방지: 총 추출 크기 사전 체크
		totalSize += int64(f.UncompressedSize64)
		if totalSize > maxTotalExtractSize {
			return count, skippedSymlinks, fmt.Errorf("total extracted size exceeds limit (%d bytes)", maxTotalExtractSize)
		}

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return count, skippedSymlinks, err
		}

		if err := extractZipFile(f, target); err != nil {
			return count, skippedSymlinks, err
		}
		count++
	}
	return count, skippedSymlinks, nil
}

// extractZipFile은 단일 zip 엔트리를 target 경로에 추출한다.
// Zip Bomb 방지로 maxSingleFileSize를 초과하면 에러를 반환한다.
func extractZipFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer out.Close()

	// Zip Bomb 방지: 단일 파일 크기 제한. +1 바이트로 초과 감지.
	n, err := io.Copy(out, io.LimitReader(rc, maxSingleFileSize+1))
	if err != nil {
		return err
	}
	if n > maxSingleFileSize {
		return fmt.Errorf("file exceeds single file size limit (%d bytes): %s", maxSingleFileSize, target)
	}
	return nil
}

// --- TAR.GZ ---

func createTarGz(output string, sources []string) (int, error) {
	f, err := os.Create(output)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	count := 0
	for _, src := range sources {
		fi, err := os.Stat(src)
		if err != nil {
			return count, fmt.Errorf("cannot stat source: %w", err)
		}
		if fi.IsDir() {
			base := filepath.Dir(src)
			err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(base, path)
				return addFileToTar(tw, path, filepath.ToSlash(rel), info, &count)
			})
			if err != nil {
				return count, err
			}
		} else {
			err := addFileToTar(tw, src, filepath.Base(src), fi, &count)
			if err != nil {
				return count, err
			}
		}
	}
	return count, nil
}

func addFileToTar(tw *tar.Writer, filePath, archivePath string, info os.FileInfo, count *int) error {
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = archivePath

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(tw, f)
	if err != nil {
		return err
	}

	*count++
	return nil
}

// extractTarGz는 tar.gz 아카이브를 추출한다. (파일 수, 스킵된 symlink 수, 에러) 반환.
func extractTarGz(archive, outputDir string) (int, int, error) {
	f, err := os.Open(archive)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return 0, 0, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	count := 0
	skippedSymlinks := 0
	var totalSize int64
	cleanOutputDir := filepath.Clean(outputDir) + string(os.PathSeparator)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, skippedSymlinks, err
		}

		target := filepath.Join(outputDir, filepath.FromSlash(header.Name))

		// Zip Slip 방지: filepath.Join이 "../"를 해소한 뒤, 최종 경로가 outputDir 안에
		// 있는지 확인한다. outputDir 자체(디렉토리 엔트리)도 허용.
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), cleanOutputDir) &&
			filepath.Clean(target) != filepath.Clean(outputDir) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0755)
		case tar.TypeReg:
			// Zip Bomb 방지: 총 추출 크기를 사전 체크하여 디스크 고갈 공격을 막는다.
			totalSize += header.Size
			if totalSize > maxTotalExtractSize {
				return count, skippedSymlinks, fmt.Errorf("total extracted size exceeds limit (%d bytes)", maxTotalExtractSize)
			}

			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return count, skippedSymlinks, err
			}
			out, err := os.Create(target)
			if err != nil {
				return count, skippedSymlinks, err
			}
			// Zip Bomb 방지: maxSize+1 바이트를 읽어서 초과 여부를 감지한다.
			// 정확히 maxSize면 정상, maxSize+1이면 초과 → 에러.
			n, copyErr := io.Copy(out, io.LimitReader(tr, maxSingleFileSize+1))
			out.Close()
			if copyErr != nil {
				return count, skippedSymlinks, copyErr
			}
			if n > maxSingleFileSize {
				return count, skippedSymlinks, fmt.Errorf("file exceeds single file size limit (%d bytes): %s", maxSingleFileSize, target)
			}
			count++
		case tar.TypeSymlink, tar.TypeLink:
			// 기본값(allow_symlinks=false): 보안상 symlink/hardlink를 생성하지 않고 스킵.
			// set_config allow_symlinks=true로 활성화 가능하나, 활성화해도
			// 대상 경로가 outputDir 밖이면 Path Traversal 방지를 위해 스킵한다.
			if !common.GetAllowSymlinks() {
				skippedSymlinks++
				break
			}
			// symlink target을 절대 경로로 해소하여 outputDir 내부인지 검증.
			// 상대 경로(예: "../sibling/file")는 symlink 파일 위치 기준으로 해소.
			linkTarget := header.Linkname
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(filepath.Dir(target), linkTarget)
			}
			linkTarget = filepath.Clean(linkTarget)
			if !strings.HasPrefix(linkTarget+string(os.PathSeparator), cleanOutputDir) &&
				linkTarget != filepath.Clean(outputDir) {
				skippedSymlinks++ // 예: "../../etc/passwd" → outputDir 밖 → 스킵
				break
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return count, skippedSymlinks, err
			}
			os.Remove(target) // 기존 파일 충돌 방지
			if header.Typeflag == tar.TypeSymlink {
				// symlink: 원본 상대/절대 경로를 그대로 사용 (해소된 경로는 검증 전용).
				// 이미 위에서 해소된 경로가 outputDir 안인지 확인했으므로 안전하다.
				if err := os.Symlink(header.Linkname, target); err != nil {
					skippedSymlinks++ // Windows 등에서 권한 부족 시 graceful 스킵
					break
				}
			} else {
				// hardlink: 해소된 절대 경로로 생성 (outputDir 내부 보장됨).
				if err := os.Link(linkTarget, target); err != nil {
					skippedSymlinks++
					break
				}
			}
			count++
		}
	}
	return count, skippedSymlinks, nil
}

// --- Register ---

func RegisterCompress(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "compress",
		Description: `Compresses files and directories into an archive.
Supports .zip and .tar.gz formats.
Output format is determined by the file extension.`,
	}, HandleCompress)
}

func RegisterDecompress(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "decompress",
		Description: `Extracts an archive to a directory.
Supports .zip and .tar.gz formats.
Includes Zip Slip and Zip Bomb protection. Symlinks are skipped for security.`,
	}, HandleDecompress)
}

func compressError(msg string) (*mcp.CallToolResult, CompressOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, CompressOutput{Result: msg}, nil
}

func decompressError(msg string) (*mcp.CallToolResult, DecompressOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DecompressOutput{Result: msg}, nil
}
