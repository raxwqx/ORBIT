package main

import (
	"errors"
	"strings"
	"testing"
)

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

func TestParseArgsNormalizesTarget(t *testing.T) {
	opts, err := parseArgs([]string{"Example.COM."})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.target != "example.com" {
		t.Fatalf("expected normalized target, got %q", opts.target)
	}
}

func TestParseArgsHelp(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		if _, err := parseArgs([]string{arg}); !errors.Is(err, errHelp) {
			t.Fatalf("expected help sentinel for %s, got %v", arg, err)
		}
	}
}

func TestParseArgsVersion(t *testing.T) {
	for _, arg := range []string{"-version", "--version"} {
		if _, err := parseArgs([]string{arg}); !errors.Is(err, errVersion) {
			t.Fatalf("expected version sentinel for %s, got %v", arg, err)
		}
	}
}

func TestParseArgsRejectsBadTargets(t *testing.T) {
	targets := []string{
		"",
		"example.com..",
		"exa mple.com",
		"example.com\x1b[31m",
		"example.com/other",
		"-example.com",
		"example..com",
	}
	for _, target := range targets {
		if _, err := parseArgs([]string{target}); err == nil {
			t.Errorf("expected an error for target %q", target)
		}
	}
}

func TestParseArgsRejectsBadTimeout(t *testing.T) {
	for _, value := range []string{"0", "-1", "301"} {
		if _, err := parseArgs([]string{"example.com", "--timeout", value}); err == nil {
			t.Errorf("expected an error for timeout %s", value)
		}
	}
}

func TestParseArgsAcceptsEqualsForm(t *testing.T) {
	opts, err := parseArgs([]string{"--target=example.com", "--timeout=12", "--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.target != "example.com" || opts.timeoutSecs != 12 || !opts.jsonOutput {
		t.Fatalf("unexpected options: %+v", opts)
	}
}

func TestParseArgsRejectsUnknownFlag(t *testing.T) {
	_, err := parseArgs([]string{"example.com", "--bogus"})
	if err == nil {
		t.Fatal("expected unknown flag error")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseArgsRejectsMissingTimeoutValue(t *testing.T) {
	if _, err := parseArgs([]string{"example.com", "--timeout"}); err == nil {
		t.Fatal("expected missing value error")
	}
}
