package output

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/raxwqx/orbit/internal/dns"
)

func TestPrintCSVFlattensAndSanitizesValues(t *testing.T) {
	result := dns.LookupResult{
		Target: "example.com",
		A: []string{"192.0.2.1"},
		TXT: []string{"\x00=HYPERLINK(\"https://example.invalid\")", `v=spf1 include:"mail.example"`},
		Warnings: []string{"timeout, retry later"},
	}
	var output strings.Builder
	if err := PrintCSV(&output, result); err != nil {
		t.Fatalf("PrintCSV returned an error: %v", err)
	}
	rows, err := csv.NewReader(strings.NewReader(output.String())).ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("expected header and four value rows, got %d", len(rows))
	}
	if rows[2][2] != "'\x00=HYPERLINK(\"https://example.invalid\")" {
		t.Fatalf("formula-like value was not neutralized: %q", rows[2][2])
	}
	if rows[4][2] != "timeout, retry later" {
		t.Fatalf("CSV quoting did not preserve warning text: %q", rows[4][2])
	}
}
