package edit

import (
	"context"
	"crypto/sha256"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"agent-tool/common"
	"agent-tool/tools/codegraph"
)

// Explicit opt-in only. No source, backup, report or index file is ever written.
func TestReadOnlyIndentCorpus(t *testing.T) {
	root := os.Getenv("AGENT_TOOL_INDENT_CORPUS")
	if root == "" {
		t.Skip("set AGENT_TOOL_INDENT_CORPUS for a read-only corpus audit")
	}
	type entry struct {
		path string
		size int64
		hash [32]byte
	}
	var files []entry
	backups := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".bak") {
			backups[path] = true
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".cpp", ".cc", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".py":
		default:
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, entry{path, info.Size(), sha256.Sum256(raw)})
		return nil
	})
	if err != nil {
		t.Fatal("cannot inventory corpus")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	if len(files) == 0 {
		t.Fatal("no corpus sources")
	}
	selected := map[int]bool{}
	largest := make([]int, len(files))
	for i := range largest {
		largest[i] = i
	}
	sort.Slice(largest, func(i, j int) bool { return files[largest[i]].size > files[largest[j]].size })
	for _, i := range largest[:min(24, len(largest))] {
		selected[i] = true
	}
	for i := 0; len(selected) < min(64, len(files)); i++ {
		selected[i*len(files)/min(64, len(files))] = true
		if i >= min(64, len(files))-1 {
			break
		}
	}
	for i := 0; len(selected) < min(64, len(files)); i++ {
		selected[i] = true
	}
	indices := make([]int, 0, len(selected))
	for i := range selected {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	decoded, explicit, decodeErrors, trees, clean, treeErrors, dryRuns, recoveryErrors := 0, 0, 0, 0, 0, 0, 0, 0
	for _, index := range indices {
		file := files[index]
		hint := ""
		text, _, err := common.ReadFileWithEncodingHash(file.path, hint)
		if err != nil {
			hint = "CP949"
			text, _, err = common.ReadFileWithEncodingHash(file.path, "CP949")
			if err == nil {
				explicit++
			}
		}
		if err != nil {
			decodeErrors++
			continue
		}
		decoded++
		norm := common.NormalizeLineEndings(text, "\n")
		lang := "cpp"
		if strings.EqualFold(filepath.Ext(file.path), ".py") {
			lang = "python"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		tree, err := codegraph.ParseSyntaxTree(ctx, lang, norm)
		cancel()
		if err != nil {
			treeErrors++
			continue
		}
		trees++
		if !tree.Nodes[0].HasError {
			clean++
		}
		for _, node := range tree.Nodes {
			if node.Type != "expression_statement" || node.HasError {
				continue
			}
			start, prefix := linePrefix(norm, node.StartByte)
			if prefix == "" || start+len(prefix) != node.StartByte {
				continue
			}
			end := strings.IndexByte(norm[start:], '\n')
			if end < 0 {
				end = len(norm)
			} else {
				end += start
			}
			body := norm[node.StartByte:end]
			if body == "" || len(body) > 200 || strings.Count(norm, body) != 1 {
				continue
			}
			oldPrefix := "\t"
			if strings.Contains(prefix, "\t") {
				oldPrefix = "    "
			}
			if prefix == oldPrefix {
				continue
			}
			marker := " /* syntax audit */"
			if lang == "python" {
				marker = " # syntax audit"
			}
			oldText, newText := oldPrefix+body, oldPrefix+body+marker
			want := norm[:start] + prefix + body + marker + norm[end:]
			got := ReplaceFile(context.Background(), file.path, text, oldText, newText, false, DetectIndent(file.path, text), false)
			if !got.Applied || common.NormalizeLineEndings(got.Content, "\n") != want {
				recoveryErrors++
				break
			}
			result, _, callErr := Handle(context.Background(), nil, EditInput{FilePath: file.path, Encoding: hint, OldString: oldText, NewString: newText, DryRun: true})
			if callErr != nil || result.IsError {
				recoveryErrors++
				break
			}
			dryRuns++
			break
		}
	}
	unchanged := 0
	for _, file := range files {
		raw, err := os.ReadFile(file.path)
		if err == nil && sha256.Sum256(raw) == file.hash {
			unchanged++
		}
	}
	newBackups := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".bak") && !backups[path] {
			newBackups++
		}
		return nil
	})
	if err != nil {
		t.Fatal("cannot verify backup inventory")
	}
	t.Logf("sources=%d sampled=%d decoded=%d explicit_cp949=%d decode_errors=%d trees=%d clean_trees=%d tree_errors=%d dry_runs=%d recovery_errors=%d unchanged=%d new_bak=%d", len(files), len(indices), decoded, explicit, decodeErrors, trees, clean, treeErrors, dryRuns, recoveryErrors, unchanged, newBackups)
	if unchanged != len(files) || newBackups != 0 || recoveryErrors != 0 {
		t.Fatal("read-only corpus audit failed")
	}
}
