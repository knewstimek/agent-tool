package edit

import "testing"

func TestDetectIndentFromContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    IndentStyle
	}{
		{
			name:    "tab indented",
			content: "\tfoo\n\t\tbar\n\t\t\tbaz",
			want:    IndentStyle{UseTabs: true, IndentSize: 4},
		},
		{
			name:    "4-space indented",
			content: "foo\n    bar\n        baz",
			want:    IndentStyle{UseTabs: false, IndentSize: 4},
		},
		{
			name:    "2-space indented",
			content: "foo\n  bar\n    baz\n      qux",
			want:    IndentStyle{UseTabs: false, IndentSize: 2},
		},
		{
			name:    "no indentation",
			content: "foo\nbar\nbaz",
			want:    IndentStyle{UseTabs: false, IndentSize: 4},
		},
		{
			name:    "mixed favoring tabs",
			content: "\ta\n\tb\n\tc\n    d",
			want:    IndentStyle{UseTabs: true, IndentSize: 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectIndentFromContent(tt.content)
			if got.UseTabs != tt.want.UseTabs {
				t.Errorf("UseTabs = %v, want %v", got.UseTabs, tt.want.UseTabs)
			}
			if got.IndentSize != tt.want.IndentSize {
				t.Errorf("IndentSize = %v, want %v", got.IndentSize, tt.want.IndentSize)
			}
		})
	}
}

func TestSpacesToTabs(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		indentSize int
		want       string
	}{
		{
			name:       "4 spaces to 1 tab",
			input:      "    code",
			indentSize: 4,
			want:       "\tcode",
		},
		{
			name:       "8 spaces to 2 tabs",
			input:      "        code",
			indentSize: 4,
			want:       "\t\tcode",
		},
		{
			name:       "6 spaces: 1 tab + 2 spaces",
			input:      "      code",
			indentSize: 4,
			want:       "\t  code",
		},
		{
			name:       "no leading spaces",
			input:      "code",
			indentSize: 4,
			want:       "code",
		},
		{
			name:       "multiline",
			input:      "    a\n        b\n    c",
			indentSize: 4,
			want:       "\ta\n\t\tb\n\tc",
		},
		{
			name:       "2-space indent",
			input:      "  a\n    b",
			indentSize: 2,
			want:       "\ta\n\t\tb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SpacesToTabs(tt.input, tt.indentSize)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTabsToSpaces(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		indentSize int
		want       string
	}{
		{
			name:       "1 tab to 4 spaces",
			input:      "\tcode",
			indentSize: 4,
			want:       "    code",
		},
		{
			name:       "2 tabs to 8 spaces",
			input:      "\t\tcode",
			indentSize: 4,
			want:       "        code",
		},
		{
			name:       "no tabs",
			input:      "code",
			indentSize: 4,
			want:       "code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TabsToSpaces(tt.input, tt.indentSize)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHasLeadingSpaces(t *testing.T) {
	if !HasLeadingSpaces("    code") {
		t.Error("should detect leading spaces")
	}
	if HasLeadingSpaces("\tcode") {
		t.Error("should not detect tabs as spaces")
	}
	if HasLeadingSpaces("code") {
		t.Error("should not detect no indentation")
	}
}
