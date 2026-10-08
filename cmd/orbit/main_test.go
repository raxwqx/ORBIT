package main

import "testing"

func TestParseArgsAllowsFlagsAfterTarget(t *testing.T) {
	opts, err := parseArgs([]string{"example.com", "--json", "--timeout", "10"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.target != "example.com" {
		t.Fatalf("unexpected target: %q", opts.target)
	}
	if !opts.jsonOutput {
		t.Fatal("expected json output to be enabled")
	}
	if opts.timeoutSecs != 10 {
		t.Fatalf("expected timeout 10, got %d", opts.timeoutSecs)
	}
}

func TestParseArgsTargetFlag(t *testing.T) {
	opts, err := parseArgs([]string{"--target", "example.com", "--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.target != "example.com" {
		t.Fatalf("unexpected target: %q", opts.target)
	}
	if !opts.jsonOutput {
		t.Fatal("expected json output to be enabled")
	}
}

func TestParseArgsRejectsDuplicateTarget(t *testing.T) {
	if _, err := parseArgs([]string{"example.com", "--target", "other.com"}); err == nil {
		t.Fatal("expected duplicate target error")
	}
}
