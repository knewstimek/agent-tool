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

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

	var count int
	var err error

	ext := strings.ToLower(input.Archive)
	switch {
	case strings.HasSuffix(ext, ".tar.gz") || strings.HasSuffix(ext, ".tgz"):
		count, err = extractTarGz(input.Archive, input.Output)
	case strings.HasSuffix(ext, ".zip"):
		count, err = extractZip(input.Archive, input.Output)
	default:
		return decompressError("unsupported format: use .zip or .tar.gz")
	}

	if err != nil {
		return decompressError(fmt.Sprintf("decompression failed: %v", err))
	}

	msg := fmt.Sprintf("OK: extracted %d files → %s", count, input.Output)
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
		fi, _ := os.Stat(src)
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

func extractZip(archive, outputDir string) (int, error) {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return 0, err
	}
	defer r.Close()

	count := 0
	for _, f := range r.File {
		target := filepath.Join(outputDir, filepath.FromSlash(f.Name))

		// Zip Slip 방지
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(outputDir)+string(os.PathSeparator)) {
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return count, err
		}

		if err := extractZipFile(f, target); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

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

	_, err = io.Copy(out, rc)
	return err
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
		fi, _ := os.Stat(src)
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

func extractTarGz(archive, outputDir string) (int, error) {
	f, err := os.Open(archive)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return 0, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	count := 0

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}

		target := filepath.Join(outputDir, filepath.FromSlash(header.Name))

		// Zip Slip 방지 (tar에도 적용)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(outputDir)+string(os.PathSeparator)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0755)
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return count, err
			}
			out, err := os.Create(target)
			if err != nil {
				return count, err
			}
			_, err = io.Copy(out, tr)
			out.Close()
			if err != nil {
				return count, err
			}
			count++
		}
	}
	return count, nil
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
Includes Zip Slip protection for security.`,
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
