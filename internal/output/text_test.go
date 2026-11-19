package output

import (
	"bytes"
	"strings"
	"testing"
	"unicode"

	"github.com/raxwqx/orbit/internal/dns"
)

func TestSanitizeStripsTerminalControlCharacters(t *testing.T) {
	input := "before\x1b[31mred\x1b[0m\x00\n\r\tafter\u202e"
	got := Sanitize(input)
	if strings.ContainsAny(got, "\x1b\x00\n\r\t") {
		t.Fatalf("control characters survived sanitization: %q", got)
	}
	for _, r := range got {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("unexpected control rune %U in %q", r, got)
		}
	}
	if !strings.Contains(got, "before[31mred[0mafter") {
		t.Fatalf("unexpected sanitized text: %q", got)
	}
}

func TestSanitizeKeepsInternationalText(t *testing.T) {
	input := "café.example — 例え.テスト"
	if got := Sanitize(input); got != input {
		t.Fatalf("expected unchanged text, got %q", got)
	}
}

func TestSanitizeTruncatesLongValues(t *testing.T) {
	got := Sanitize(strings.Repeat("a", maxDisplayRunes+50))
	runes := []rune(got)
	if len(runes) != maxDisplayRunes+1 {
		t.Fatalf("expected %d runes including the ellipsis, got %d", maxDisplayRunes+1, len(runes))
	}
	if runes[len(runes)-1] != '…' {
		t.Fatalf("expected truncation marker, got %q", string(runes[len(runes)-1]))
	}
}

func TestPrintTerminalSanitizesUntrustedValues(t *testing.T) {
	result := Result{
		Target: "example.com",
		A:      []string{"192.0.2.1"},
		TXT:    []string{"v=spf1 include:\x1b[2Jevil.example ~all"},
		CAA:    []string{"0 issue \"\x1b[31mevil.example\""},
		PTR:    map[string][]string{"192.0.2.1": {"host\x1b[0m.example."}},
		Security: dns.SecurityResult{
			Summary: dns.SecuritySummary{
				SPF:    "present",
				DMARC:  "missing",
				DNSSEC: "unsigned",
			},
		},
		Warnings: []string{"lookup \x1b[2Jinjected"},
	}

	var buf bytes.Buffer
	PrintTerminal(&buf, result)
	out := buf.String()

	if strings.Contains(out, "\x1b") {
		t.Fatalf("terminal output contains an escape sequence: %q", out)
	}
	if !strings.Contains(out, "Certificate Authorities (CAA)") {
		t.Fatal("expected CAA section in terminal output")
	}
	if !strings.Contains(out, "CAA") || !strings.Contains(out, "evil.example") {
		t.Fatalf("expected CAA record in terminal output: %q", out)
	}
}
