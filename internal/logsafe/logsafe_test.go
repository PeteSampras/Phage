package logsafe

import (
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"plain /etc/cron.d/x":          "plain /etc/cron.d/x",
		"a\nCRITICAL forged":           `a\nCRITICAL forged`,
		"\x1b[2Jwipe":                  `\x1b[2Jwipe`,
		"back\\slash":                  `back\\slash`,
		"\xff":                         `\xff`,
		"wrote /x (op: \"quoted\") ok": `wrote /x (op: \"quoted\") ok`,
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
		if strings.ContainsAny(Clean(in), "\n\r\x1b") {
			t.Errorf("Clean(%q) still has control characters", in)
		}
	}
}
