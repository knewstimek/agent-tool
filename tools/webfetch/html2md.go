package webfetch

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

var multiNewline = regexp.MustCompile(`\n{3,}`)

// skipTags are tags whose content should be completely removed.
var skipTags = map[string]bool{
	"script":   true,
	"style":    true,
	"noscript": true,
	"svg":      true,
	"iframe":   true,
}

// convertHTMLToMarkdown converts HTML content to readable Markdown.
func convertHTMLToMarkdown(htmlContent string) string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return htmlContent // return raw on parse failure
	}

	var sb strings.Builder
	walkNode(&sb, doc)

	result := sb.String()
	// Clean up excessive newlines (single pass)
	result = multiNewline.ReplaceAllString(result, "\n\n")
	return strings.TrimSpace(result)
}

// walkNode recursively processes an HTML node tree.
func walkNode(sb *strings.Builder, n *html.Node) {
	if n == nil {
		return
	}

	switch n.Type {
	case html.TextNode:
		text := strings.TrimSpace(n.Data)
		if text != "" {
			sb.WriteString(text)
		} else if n.Data != "" && (strings.Contains(n.Data, " ") || strings.Contains(n.Data, "\n")) {
			// Preserve a single space for whitespace-only text nodes
			sb.WriteString(" ")
		}

	case html.ElementNode:
		tag := strings.ToLower(n.DataAtom.String())
		if tag == "" {
			tag = strings.ToLower(n.Data)
		}

		// Skip content of certain tags entirely
		if skipTags[tag] {
			return
		}

		switch tag {
		case "h1":
			sb.WriteString("\n\n# ")
			walkChildren(sb, n)
			sb.WriteString("\n\n")
		case "h2":
			sb.WriteString("\n\n## ")
			walkChildren(sb, n)
			sb.WriteString("\n\n")
		case "h3":
			sb.WriteString("\n\n### ")
			walkChildren(sb, n)
			sb.WriteString("\n\n")
		case "h4":
			sb.WriteString("\n\n#### ")
			walkChildren(sb, n)
			sb.WriteString("\n\n")
		case "h5":
			sb.WriteString("\n\n##### ")
			walkChildren(sb, n)
			sb.WriteString("\n\n")
		case "h6":
			sb.WriteString("\n\n###### ")
			walkChildren(sb, n)
			sb.WriteString("\n\n")
		case "p":
			sb.WriteString("\n\n")
			walkChildren(sb, n)
			sb.WriteString("\n\n")
		case "br":
			sb.WriteString("\n")
		case "hr":
			sb.WriteString("\n\n---\n\n")
		case "a":
			href := getAttr(n, "href")
			sb.WriteString("[")
			walkChildren(sb, n)
			sb.WriteString("](")
			sb.WriteString(href)
			sb.WriteString(")")
		case "img":
			alt := getAttr(n, "alt")
			src := getAttr(n, "src")
			sb.WriteString("![")
			sb.WriteString(alt)
			sb.WriteString("](")
			sb.WriteString(src)
			sb.WriteString(")")
		case "strong", "b":
			sb.WriteString("**")
			walkChildren(sb, n)
			sb.WriteString("**")
		case "em", "i":
			sb.WriteString("*")
			walkChildren(sb, n)
			sb.WriteString("*")
		case "code":
			// Check if inside <pre>
			if n.Parent != nil && strings.ToLower(n.Parent.Data) == "pre" {
				lang := getAttr(n, "class")
				lang = extractLang(lang)
				sb.WriteString("\n\n```")
				sb.WriteString(lang)
				sb.WriteString("\n")
				walkChildrenRaw(sb, n)
				sb.WriteString("\n```\n\n")
			} else {
				sb.WriteString("`")
				walkChildren(sb, n)
				sb.WriteString("`")
			}
		case "pre":
			// Check if contains <code> child
			hasCode := false
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && strings.ToLower(c.Data) == "code" {
					hasCode = true
					break
				}
			}
			if hasCode {
				walkChildren(sb, n)
			} else {
				sb.WriteString("\n\n```\n")
				walkChildrenRaw(sb, n)
				sb.WriteString("\n```\n\n")
			}
		case "ul":
			sb.WriteString("\n")
			walkListItems(sb, n, false, 0)
			sb.WriteString("\n")
		case "ol":
			sb.WriteString("\n")
			walkListItems(sb, n, true, 0)
			sb.WriteString("\n")
		case "li":
			// Handled by walkListItems
			walkChildren(sb, n)
		case "blockquote":
			sb.WriteString("\n\n")
			var quoteSB strings.Builder
			walkChildren(&quoteSB, n)
			for _, line := range strings.Split(quoteSB.String(), "\n") {
				sb.WriteString("> ")
				sb.WriteString(strings.TrimSpace(line))
				sb.WriteString("\n")
			}
			sb.WriteString("\n")
		case "table":
			sb.WriteString("\n\n")
			walkTable(sb, n)
			sb.WriteString("\n\n")
		case "div", "section", "article", "main", "span":
			walkChildren(sb, n)
		case "nav", "footer", "header", "aside":
			// Skip navigation/footer elements for cleaner output
			return
		default:
			walkChildren(sb, n)
		}

	case html.DocumentNode:
		walkChildren(sb, n)
	default:
		walkChildren(sb, n)
	}
}

// walkChildren processes all child nodes.
func walkChildren(sb *strings.Builder, n *html.Node) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkNode(sb, c)
	}
}

// walkChildrenRaw processes child nodes preserving whitespace.
func walkChildrenRaw(sb *strings.Builder, n *html.Node) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			sb.WriteString(c.Data)
		} else {
			walkChildrenRaw(sb, c)
		}
	}
}

// walkListItems handles ordered and unordered list items.
func walkListItems(sb *strings.Builder, n *html.Node, ordered bool, depth int) {
	idx := 1
	indent := strings.Repeat("  ", depth)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode || strings.ToLower(c.Data) != "li" {
			continue
		}
		if ordered {
			sb.WriteString(fmt.Sprintf("%s%d. ", indent, idx))
			idx++
		} else {
			sb.WriteString(indent + "- ")
		}
		// Process li content, handling nested lists
		for gc := c.FirstChild; gc != nil; gc = gc.NextSibling {
			tag := strings.ToLower(gc.Data)
			if gc.Type == html.ElementNode && (tag == "ul" || tag == "ol") {
				sb.WriteString("\n")
				walkListItems(sb, gc, tag == "ol", depth+1)
			} else {
				walkNode(sb, gc)
			}
		}
		sb.WriteString("\n")
	}
}

// walkTable converts an HTML table to Markdown.
func walkTable(sb *strings.Builder, n *html.Node) {
	var rows [][]string
	collectTableRows(n, &rows)
	if len(rows) == 0 {
		return
	}

	// Calculate column widths
	maxCols := 0
	for _, row := range rows {
		if len(row) > maxCols {
			maxCols = len(row)
		}
	}

	// Write header row
	sb.WriteString("| ")
	for i := 0; i < maxCols; i++ {
		if i < len(rows[0]) {
			sb.WriteString(rows[0][i])
		}
		sb.WriteString(" | ")
	}
	sb.WriteString("\n")

	// Write separator
	sb.WriteString("| ")
	for i := 0; i < maxCols; i++ {
		sb.WriteString("--- | ")
	}
	sb.WriteString("\n")

	// Write data rows
	for _, row := range rows[1:] {
		sb.WriteString("| ")
		for i := 0; i < maxCols; i++ {
			if i < len(row) {
				sb.WriteString(row[i])
			}
			sb.WriteString(" | ")
		}
		sb.WriteString("\n")
	}
}

// collectTableRows extracts rows from table elements.
func collectTableRows(n *html.Node, rows *[][]string) {
	if n.Type == html.ElementNode {
		tag := strings.ToLower(n.Data)
		if tag == "tr" {
			var cells []string
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				ct := strings.ToLower(c.Data)
				if c.Type == html.ElementNode && (ct == "td" || ct == "th") {
					var cellSB strings.Builder
					walkChildren(&cellSB, c)
					cells = append(cells, strings.TrimSpace(cellSB.String()))
				}
			}
			*rows = append(*rows, cells)
			return
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectTableRows(c, rows)
	}
}

// getAttr returns the value of an HTML attribute.
func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// extractLang extracts language from a class like "language-go" or "lang-python".
func extractLang(class string) string {
	for _, c := range strings.Fields(class) {
		if strings.HasPrefix(c, "language-") {
			return strings.TrimPrefix(c, "language-")
		}
		if strings.HasPrefix(c, "lang-") {
			return strings.TrimPrefix(c, "lang-")
		}
	}
	return ""
}
