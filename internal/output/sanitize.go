package output

import (
	"strings"
	"unicode"
)

// maxDisplayRunes bounds how much untrusted text is printed for one value.
const maxDisplayRunes = 512

// Sanitize makes DNS-derived text safe for terminal output. Resolver data,
// TXT records and DNS error messages are attacker-influenced: control
// characters could otherwise inject ANSI escapes or forge report lines.
func Sanitize(value string) string {
	var b strings.Builder
	count := 0
	truncated := false

	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			continue
		}
		if count >= maxDisplayRunes {
			truncated = true
			break
		}
		b.WriteRune(r)
		count++
	}

	if truncated {
		b.WriteString("…")
	}
	return b.String()
}
