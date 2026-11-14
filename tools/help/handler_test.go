package help

import (
	"context"
	"strings"
	"testing"
)

func helpText(t *testing.T, topic string) string {
	t.Helper()
	_, out, err := Handle(context.Background(), nil, HelpInput{Topic: topic})
	if err != nil {
		t.Fatalf("Handle(%q): %v", topic, err)
	}
	return out.Content
}

func TestIndexedTopicReturnsIndexNotBodies(t *testing.T) {
	index := helpText(t, "analyze")
	for _, want := range []string{"- decompile: ", "- annotation_batch / annotation_suggest: ", "analyze/<section>"} {
		if !strings.Contains(index, want) {
			t.Errorf("analyze index lacks %q", want)
		}
	}
	// A parameter documented only inside the decompile section body.
	if strings.Contains(index, "assume_branches") {
		t.Error("analyze index leaks section bodies")
	}
	if full := helpAnalyze(); len(index)*3 > len(full) {
		t.Errorf("analyze index is %d chars of a %d char document; expected under a third", len(index), len(full))
	}
}

func TestSectionRequest(t *testing.T) {
	got := helpText(t, "Analyze/Decompile")
	if !strings.HasPrefix(got, "## decompile\n") || !strings.Contains(got, "assume_branches") {
		t.Errorf("analyze/decompile did not return the decompile section:\n%.200s", got)
	}
	if strings.Contains(got, "## xref") || strings.Contains(got, "Typical order") {
		t.Error("analyze/decompile returned more than the requested section")
	}

	// Two names of one joint heading plus another section: the joint section
	// prints once, in request order.
	got = helpText(t, "analyze/annotation_list, annotation_set ,type_info")
	if n := strings.Count(got, "## annotation_set / annotation_list / annotation_delete"); n != 1 {
		t.Errorf("joint section printed %d times, want 1", n)
	}
	if a, b := strings.Index(got, "## annotation_set"), strings.Index(got, "## type_info"); a < 0 || b < a {
		t.Errorf("sections out of request order (annotation at %d, type_info at %d)", a, b)
	}

	// Alias topic names and non-indexed topics resolve sections the same way.
	if got := helpText(t, "pe/hexdump"); !strings.HasPrefix(got, "## hexdump\n") {
		t.Errorf("alias topic section lookup failed:\n%.120s", got)
	}
	if got := helpText(t, "tools/ssh"); !strings.HasPrefix(got, "## ssh\n") || strings.Contains(got, "## ssh_key") {
		t.Errorf("tools/ssh returned the wrong section:\n%.120s", got)
	}
}

func TestUnknownSectionNamesAlternatives(t *testing.T) {
	got := helpText(t, "analyze/decompile,nosuch")
	if !strings.HasPrefix(got, "## decompile\n") {
		t.Error("known section dropped when another name was unknown")
	}
	if !strings.Contains(got, `No section named nosuch in topic "analyze". Available: `) || !strings.Contains(got, "type_info") {
		t.Errorf("unknown section message is not actionable:\n%s", got[max(0, len(got)-400):])
	}
	if got := helpText(t, "nosuch/x"); !strings.Contains(got, "Unknown topic: nosuch") || !strings.Contains(got, "codegraph") {
		t.Errorf("unknown topic message: %s", got)
	}
}

func TestBareAndEmptySectionRequests(t *testing.T) {
	if helpText(t, "") != helpOverview() {
		t.Error("empty topic is not the overview")
	}
	if helpText(t, "debug") != helpDebug() {
		t.Error("non-indexed topic is not returned whole")
	}
	if helpText(t, "analyze/ , ") != helpText(t, "analyze") {
		t.Error("an empty section list should fall back to the topic's default view")
	}
}

// Size budgets, in characters (about 3.6 per token). A help answer is read in
// full by an agent that needed one fact; when a budget fails, split the text
// into sections or delete implementation detail instead of raising it.
func TestHelpSizeBudgets(t *testing.T) {
	const (
		wholeTopicMax = 16000 // topics returned whole
		indexMax      = 8000  // default view of an indexed topic
		sectionMax    = 8000
		summaryMax    = 160
	)
	for _, tp := range topics {
		name := tp.names[0]
		if !tp.indexed {
			if n := len(tp.doc()); n > wholeTopicMax {
				t.Errorf("topic %s is %d chars (max %d): mark it indexed and give it ## sections", name, n, wholeTopicMax)
			}
			continue
		}
		if n := len(render(tp, "")); n > indexMax {
			t.Errorf("index of %s is %d chars (max %d)", name, n, indexMax)
		}
		_, sections := splitSections(tp.doc())
		if len(sections) == 0 {
			t.Errorf("indexed topic %s has no ## sections", name)
		}
		seen := map[string]bool{}
		for _, s := range sections {
			if n := len(s.body); n > sectionMax {
				t.Errorf("%s/%s is %d chars (max %d)", name, s.heading, n, sectionMax)
			}
			summary, _, _ := strings.Cut(s.body, "\n")
			// The index prints this line alone, so it has to be a finished
			// sentence, not the first half of a wrapped paragraph.
			if summary != strings.TrimSpace(summary) || len(summary) > summaryMax || !strings.HasSuffix(summary, ".") {
				t.Errorf("%s/%s must open with a one-line summary sentence of at most %d chars, got %q", name, s.heading, summaryMax, summary)
			}
			for _, n := range s.names() {
				if seen[n] {
					t.Errorf("%s has two sections named %q", name, n)
				}
				seen[n] = true
			}
		}
	}
}
