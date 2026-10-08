package dns

import "testing"

func TestAppendUnique(t *testing.T) {
	items := []string{"one", "two"}
	items = appendUnique(items, "two")
	items = appendUnique(items, "three")

	if len(items) != 3 {
		t.Fatalf("expected 3 unique items, got %d", len(items))
	}

	if items[2] != "three" {
		t.Fatalf("unexpected third item: %q", items[2])
	}
}

func TestBuildSummary(t *testing.T) {
	result := SecurityResult{
		SPF:    SPFResult{Present: true},
		DMARC:  DMARCResult{Present: false},
		DNSSEC: DNSSECResult{Status: "signed", Validated: true},
	}

	summary := buildSummary(result)
	if summary.SPF != "present" {
		t.Fatalf("expected SPF present, got %q", summary.SPF)
	}
	if summary.DMARC != "missing" {
		t.Fatalf("expected DMARC missing, got %q", summary.DMARC)
	}
	if summary.DNSSEC != "validated" {
		t.Fatalf("expected DNSSEC validated, got %q", summary.DNSSEC)
	}
}

func TestDOHResponseHasAnswerType(t *testing.T) {
	result := dohResponse{Answer: []dohAnswer{{Type: 48}, {Type: 1}}}
	if !result.hasAnswerType(48) {
		t.Fatal("expected DNSKEY answer type to be detected")
	}
	if result.hasAnswerType(15) {
		t.Fatal("unexpected MX answer type")
	}
}
