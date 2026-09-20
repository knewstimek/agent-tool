package common

import "testing"

func TestPrivateAccessWarningIsCompact(t *testing.T) {
	const want = "⚠ ssh private address: 10.0.0.1. Proceed only if requested."
	if got := PrivateAccessWarning("10.0.0.1", "ssh"); got != want {
		t.Fatalf("warning = %q, want %q", got, want)
	}
}
