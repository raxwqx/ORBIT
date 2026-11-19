package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestResolver(t *testing.T, handler http.HandlerFunc) *Resolver {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &Resolver{
		Resolver: nil,
		Timeout:  2 * time.Second,
		HTTP:     server.Client(),
		DoH:      server.URL + "/dns-query",
	}
}

func writeDoH(t *testing.T, w http.ResponseWriter, payload string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/dns-json")
	if _, err := w.Write([]byte(payload)); err != nil {
		t.Fatalf("write response: %v", err)
	}
}

func TestValidateTarget(t *testing.T) {
	valid := []string{
		"example.com",
		"example.com.",
		"WWW.Example.COM",
		"_dmarc.example.com",
		"xn--bcher-kva.example",
		"localhost",
		"1.1.1.1",
	}
	for _, target := range valid {
		if err := ValidateTarget(target); err != nil {
			t.Errorf("ValidateTarget(%q) returned unexpected error: %v", target, err)
		}
	}

	invalid := []string{
		"",
		".",
		"example.com..",
		"exa mple.com",
		"example.com/path",
		"example.com\x1b[31m",
		"example.com\nother.com",
		"-example.com",
		"example-.com",
		"example..com",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 128) + "com",
	}
	for _, target := range invalid {
		if err := ValidateTarget(target); err == nil {
			t.Errorf("ValidateTarget(%q) expected an error", target)
		}
	}
}

func TestDoHQueryStatuses(t *testing.T) {
	resolver := newTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "A":
			writeDoH(t, w, `{"Status":3}`)
		case "TXT":
			writeDoH(t, w, `{"Status":2}`)
		default:
			writeDoH(t, w, `{"Status":0,"AD":true,"Answer":[{"name":"example.com","type":48,"data":"key"}]}`)
		}
	})

	ctx := context.Background()
	if _, err := resolver.dohQuery(ctx, "example.com", "DNSKEY"); err != nil {
		t.Fatalf("unexpected DNSKEY error: %v", err)
	}

	if _, err := resolver.dohQuery(ctx, "example.com", "A"); !errors.Is(err, errNXDomain) {
		t.Fatalf("expected NXDOMAIN sentinel, got %v", err)
	}

	if _, err := resolver.dohQuery(ctx, "example.com", "TXT"); err == nil || !strings.Contains(err.Error(), "status 2") {
		t.Fatalf("expected SERVFAIL status error, got %v", err)
	}
}

func TestInspectCAA(t *testing.T) {
	resolver := newTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "CAA" {
			t.Errorf("unexpected record type: %s", r.URL.Query().Get("type"))
		}
		writeDoH(t, w, `{"Status":0,"Answer":[
			{"name":"example.com","type":257,"data":"0 issue \"letsencrypt.org\""},
			{"name":"example.com","type":46,"data":"CAA 13 2 300 ..."},
			{"name":"example.com","type":257,"data":"0 iodef \"mailto:security@example.com\""}
		]}`)
	})

	var result LookupResult
	records := resolver.inspectCAA("example.com", &result)
	if len(records) != 2 {
		t.Fatalf("expected 2 CAA records, got %v", records)
	}
	if !strings.Contains(records[0], "iodef") {
		t.Fatalf("expected sorted CAA records, got %v", records)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", result.Warnings)
	}
}

func TestInspectCAANXDomainIsNotAWarning(t *testing.T) {
	resolver := newTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		writeDoH(t, w, `{"Status":3}`)
	})

	var result LookupResult
	if records := resolver.inspectCAA("missing.example", &result); len(records) != 0 {
		t.Fatalf("expected no CAA records, got %v", records)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", result.Warnings)
	}
}

func TestInspectDNSSECUsesZoneApex(t *testing.T) {
	var queries []string
	resolver := newTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		recordType := r.URL.Query().Get("type")
		queries = append(queries, recordType+" "+name)

		switch {
		case recordType == "DNSKEY" && name == "www.example.com":
			// Subdomains normally return NODATA but the authority section
			// points at the signing zone.
			writeDoH(t, w, `{"Status":0,"Authority":[
				{"name":"example.com","type":6,"data":"ns1.example.com. hostmaster.example.com. 1 2 3 4 5"}
			]}`)
		case recordType == "DNSKEY" && name == "example.com":
			writeDoH(t, w, `{"Status":0,"Answer":[
				{"name":"example.com","type":48,"data":"256 3 13 key"}
			]}`)
		case recordType == "A" || recordType == "AAAA":
			writeDoH(t, w, `{"Status":0,"AD":true,"Answer":[
				{"name":"www.example.com","type":1,"data":"192.0.2.1"}
			]}`)
		default:
			t.Errorf("unexpected query: %s %s", recordType, name)
			writeDoH(t, w, `{"Status":0}`)
		}
	})

	var result LookupResult
	dnssec := inspectDNSSEC(resolver, "www.example.com", &result)
	if dnssec.Status != "signed" {
		t.Fatalf("expected signed status, got %q", dnssec.Status)
	}
	if !dnssec.Validated {
		t.Fatal("expected DNSSEC data to be validated")
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", result.Warnings)
	}
	if !containsQuery(queries, "DNSKEY example.com") {
		t.Fatalf("expected the zone apex to be queried, got %v", queries)
	}
}

func TestInspectDNSSECUnsignedZone(t *testing.T) {
	resolver := newTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "DNSKEY" {
			writeDoH(t, w, `{"Status":0}`)
			return
		}
		writeDoH(t, w, `{"Status":0,"AD":false}`)
	})

	var result LookupResult
	dnssec := inspectDNSSEC(resolver, "www.example.com", &result)
	if dnssec.Status != "unsigned" {
		t.Fatalf("expected unsigned status, got %q", dnssec.Status)
	}
	if dnssec.Validated {
		t.Fatal("expected unsigned data not to be validated")
	}
}

func TestInspectDNSSECSERVFAILIsUnknown(t *testing.T) {
	resolver := newTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		writeDoH(t, w, `{"Status":2}`)
	})

	var result LookupResult
	dnssec := inspectDNSSEC(resolver, "example.com", &result)
	if dnssec.Status != "unknown" {
		t.Fatalf("expected unknown status, got %q", dnssec.Status)
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "status 2") {
		t.Fatalf("expected a DNSSEC warning, got %v", result.Warnings)
	}
}

func TestInspectDNSSECSkipsPublicSuffix(t *testing.T) {
	var queried []string
	resolver := newTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "DNSKEY" {
			queried = append(queried, r.URL.Query().Get("name"))
			writeDoH(t, w, `{"Status":0}`)
			return
		}
		writeDoH(t, w, `{"Status":0}`)
	})

	var result LookupResult
	dnssec := inspectDNSSEC(resolver, "a.b.example.co.uk", &result)
	if dnssec.Status != "unsigned" {
		t.Fatalf("expected unsigned status, got %q", dnssec.Status)
	}
	if containsQuery(queried, "co.uk") {
		t.Fatalf("must not treat the public suffix as the signing zone: %v", queried)
	}
}

func TestDoHURLIsEscaped(t *testing.T) {
	resolver := &Resolver{DoH: "https://example.test/dns-query"}
	raw := resolver.dohURL("_dmarc.example.com", "TXT")
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("invalid DoH URL: %v", err)
	}
	if parsed.Query().Get("name") != "_dmarc.example.com" || parsed.Query().Get("type") != "TXT" || parsed.Query().Get("do") != "1" {
		t.Fatalf("unexpected DoH query: %s", raw)
	}
}

func TestJSONAnswersDecode(t *testing.T) {
	payload := `{"Status":0,"AD":true,"Answer":[{"name":"example.com","type":257,"data":"0 issue \"ca\""}]}`
	var response dohResponse
	if err := json.Unmarshal([]byte(payload), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(response.Answer) != 1 || response.Answer[0].Data == "" {
		t.Fatalf("unexpected answer: %+v", response.Answer)
	}
}

func containsQuery(queries []string, want string) bool {
	for _, query := range queries {
		if query == want {
			return true
		}
	}
	return false
}

func TestLookupPTRsEmpty(t *testing.T) {
	resolver := &Resolver{}
	ptrs, warnings := resolver.lookupPTRs(nil)
	if ptrs != nil || warnings != nil {
		t.Fatalf("expected empty result, got %v %v", ptrs, warnings)
	}
}

func TestFindDNSKEYNXDomain(t *testing.T) {
	resolver := newTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		writeDoH(t, w, `{"Status":3}`)
	})
	found, successes, errs := resolver.findDNSKEY(context.Background(), "missing.example")
	if found || successes != 1 || len(errs) != 0 {
		t.Fatalf("unexpected result: found=%v successes=%d errs=%v", found, successes, errs)
	}
}

func TestDoHHTTPStatusError(t *testing.T) {
	resolver := newTestResolver(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	_, err := resolver.dohQuery(context.Background(), "example.com", "A")
	if err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("expected HTTP status error, got %v", err)
	}
}

func TestDohURLDefaultEndpoint(t *testing.T) {
	resolver := &Resolver{}
	if got := resolver.dohURL("example.com", "A"); !strings.HasPrefix(got, defaultDoHEndpoint) {
		t.Fatalf("expected default endpoint, got %q", got)
	}
}

func TestBuildSummaryUnknownDNSSEC(t *testing.T) {
	summary := buildSummary(SecurityResult{DNSSEC: DNSSECResult{Status: "unknown"}})
	if summary.DNSSEC != "unknown" {
		t.Fatalf("expected unknown DNSSEC summary, got %q", summary.DNSSEC)
	}
}

func ExampleValidateTarget() {
	fmt.Println(ValidateTarget("example.com"))
	// Output: <nil>
}
