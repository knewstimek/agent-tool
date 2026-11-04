package edit

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"agent-tool/tools/codegraph"
)

// ReplaceFile keeps exact/forced edits unchanged. Tree-sitter is lazy: only
// whitespace recovery in C++/Python asks for a detached syntax snapshot.
func ReplaceFile(ctx context.Context, path, content, oldText, newText string, all bool, style IndentStyle, force bool) ReplaceResult {
	lang := ""
	switch strings.ToLower(filepath.Ext(path)) {
	case ".cpp", ".cc", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx":
		lang = "cpp"
	case ".py", ".pyw", ".pyi":
		lang = "python"
	}
	var analysis *indentAnalysis
	if lang != "" && !force {
		analysis = &indentAnalysis{ctx: ctx, lang: lang}
	}
	return replaceAnalyzed(content, oldText, newText, all, style, force, analysis)
}

type indentAnalysis struct {
	ctx          context.Context
	lang, source string
	parsed       bool
	tree         *codegraph.SyntaxTree
}

func (a *indentAnalysis) parse(source string) *codegraph.SyntaxTree {
	if a == nil || a.ctx.Err() != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Second)
	defer cancel()
	tree, err := codegraph.ParseSyntaxTree(ctx, a.lang, source)
	if err != nil {
		return nil
	}
	return tree
}

func linePrefix(source string, offset int) (int, string) {
	start := strings.LastIndexByte(source[:offset], '\n') + 1
	end := start
	for end < len(source) && (source[end] == ' ' || source[end] == '\t') {
		end++
	}
	return start, source[start:end]
}

func (a *indentAnalysis) width(source string, anchor, fallback int) int {
	if a == nil {
		return localIndentWidth(source, anchor, fallback)
	}
	if !a.parsed {
		a.source = source
		a.tree = a.parse(source)
		a.parsed = true
	}
	if a.tree == nil {
		return localIndentWidth(source, anchor, fallback)
	}
	_, prefix := linePrefix(source, anchor)
	at := a.tree.NodeAt(anchor + len(prefix))
	for at >= 0 {
		n := a.tree.Nodes[at]
		if n.Type == "block" || n.Type == "compound_statement" || n.Type == "field_declaration_list" {
			if n.HasError {
				break
			}
			basePos := n.StartByte
			if n.Parent >= 0 {
				parent := a.tree.Nodes[n.Parent]
				// A brace can follow a heavily aligned constructor/header line.
				// The owning statement's indentation is the structural base.
				if parent.Type != "compound_statement" && parent.Type != "field_declaration_list" {
					basePos = parent.StartByte
				}
			}
			_, base := linePrefix(source, basePos)
			if strings.Contains(base, "\t") {
				break
			}
			var votes [9]int
			total, best := 0, 0
			for child := n.FirstChild; child >= 0; child = a.tree.Nodes[child].NextSibling {
				c := a.tree.Nodes[child]
				if !c.Named || c.Type == "comment" || strings.HasPrefix(c.Type, "preproc_") {
					continue
				}
				start, p := linePrefix(source, c.StartByte)
				// Only statement starts at the first code column supply votes.
				if start+len(p) != c.StartByte || strings.Contains(p, "\t") {
					continue
				}
				width := len(p) - len(base)
				if width > 0 && width <= 8 {
					votes[width]++
					total++
					if votes[width] > votes[best] {
						best = width
					}
				}
			}
			if best > 0 && votes[best]*2 > total {
				return best
			}
			// Do not borrow evidence from an unrelated sibling block.
			break
		}
		at = n.Parent
	}
	return localIndentWidth(source, anchor, fallback)
}

func literalNode(kind string) bool {
	switch kind {
	case "string_literal", "raw_string_literal", "string", "concatenated_string", "comment":
		return true
	}
	return false
}

func continuationNode(kind string) bool {
	switch kind {
	case "argument_list", "arguments", "parameter_list", "parameters", "parenthesized_expression",
		"initializer_list", "list", "list_comprehension", "dictionary", "dictionary_comprehension",
		"set", "set_comprehension", "tuple", "subscript_argument_list":
		return true
	}
	return false
}

func (a *indentAnalysis) rebase(newText, oldPrefix, actualPrefix string, sourceWidth, targetWidth int, useTabs bool) string {
	fallback := rebaseIndent(newText, oldPrefix, actualPrefix, sourceWidth, targetWidth, useTabs)
	return a.preserveSyntax(newText, fallback, sourceWidth, targetWidth, useTabs)
}

func (a *indentAnalysis) preserveSyntax(newText, fallback string, sourceWidth, targetWidth int, useTabs bool) string {
	if a == nil || !strings.Contains(newText, "\n") || len(newText) > 64*1024 || strings.Count(newText, "\n") > 512 {
		return fallback
	}
	wrapper := "void __indent_fragment() {\n"
	if a.lang == "python" {
		wrapper = "if True:\n"
	}
	source := wrapper + newText + "\n"
	if a.lang == "cpp" {
		source += "}\n"
	}
	tree := a.parse(source)
	if tree == nil || tree.Nodes[0].HasError {
		return fallback
	}
	input, output := strings.Split(newText, "\n"), strings.Split(fallback, "\n")
	offset := len(wrapper)
	lineStarts := make([]int, len(input))
	for i, line := range input {
		lineStarts[i] = offset
		offset += len(line) + 1
	}
	for i, line := range input {
		if line == "" {
			continue
		}
		_, prefix := linePrefix(source, lineStarts[i])
		at := tree.NodeAt(lineStarts[i] + len(prefix))
		for at >= 0 {
			n := tree.Nodes[at]
			if literalNode(n.Type) && n.StartByte < lineStarts[i] {
				// Indentation within multiline literals is source content.
				output[i] = line
				break
			}
			if n.Type == "block" || n.Type == "compound_statement" {
				break
			}
			if continuationNode(n.Type) && n.StartByte < lineStarts[i] {
				openStart, openPrefix := linePrefix(source, n.StartByte)
				openLine := -1
				for j := i - 1; j >= 0; j-- {
					if lineStarts[j] == openStart {
						openLine = j
						break
					}
				}
				if openLine >= 0 {
					// Align to a token already on the opener's line. Hanging
					// indentation without such a token keeps level rescaling.
					hasInlineChild := false
					for c := n.FirstChild; c >= 0; c = tree.Nodes[c].NextSibling {
						child := tree.Nodes[c]
						if child.Named && child.Type != "comment" && child.StartByte > n.StartByte && child.StartByte < lineStarts[openLine]+len(input[openLine]) {
							hasInlineChild = true
							break
						}
					}
					if hasInlineChild {
						_, outPrefix := linePrefix(output[openLine], 0)
						columns := indentColumns(prefix, sourceWidth) + indentColumns(outPrefix, targetWidth) - indentColumns(openPrefix, sourceWidth)
						if columns >= 0 {
							p := strings.Repeat(" ", columns)
							if useTabs {
								p = strings.Repeat("\t", columns/targetWidth) + strings.Repeat(" ", columns%targetWidth)
							}
							output[i] = p + strings.TrimLeft(line, " \t")
						}
					}
				}
				break
			}
			at = n.Parent
		}
	}
	return strings.Join(output, "\n")
}
