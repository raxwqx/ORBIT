package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Resolver struct {
	Resolver *net.Resolver
	Timeout  time.Duration
	HTTP     *http.Client
}

type SecurityResult struct {
	SPF     SPFResult       `json:"spf"`
	DMARC   DMARCResult     `json:"dmarc"`
	DNSSEC  DNSSECResult    `json:"dnssec"`
	Summary SecuritySummary `json:"summary"`
}

type SPFResult struct {
	Present bool     `json:"present"`
	Records []string `json:"records,omitempty"`
}

type DMARCResult struct {
	Present bool     `json:"present"`
	Records []string `json:"records,omitempty"`
}

type DNSSECResult struct {
	Status     string `json:"status"`
	Validated  bool   `json:"validated"`
	CheckedVia string `json:"checked_via"`
}

type SecuritySummary struct {
	SPF    string `json:"spf"`
	DMARC  string `json:"dmarc"`
	DNSSEC string `json:"dnssec"`
}

type LookupResult struct {
	Target    string              `json:"target"`
	ElapsedMS int64               `json:"elapsed_ms"`
	A         []string            `json:"A"`
	AAAA      []string            `json:"AAAA"`
	MX        []string            `json:"MX"`
	NS        []string            `json:"NS"`
	TXT       []string            `json:"TXT"`
	CNAME     []string            `json:"CNAME"`
	PTR       map[string][]string `json:"PTR,omitempty"`
	Security  SecurityResult      `json:"security"`
	Warnings  []string            `json:"warnings,omitempty"`
}

func New(timeout time.Duration) *Resolver {
	return &Resolver{
		Resolver: net.DefaultResolver,
		Timeout:  timeout,
		HTTP:     &http.Client{Timeout: timeout},
	}
}

func (r *Resolver) context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), r.Timeout)
}

func (r *Resolver) Lookup(target string) LookupResult {
	start := time.Now()
	result := LookupResult{Target: target}

	type lookupOutput struct {
		name string
		data any
		err  error
	}

	jobs := []struct {
		name string
		fn   func(context.Context) (any, error)
	}{
		{"ip", func(ctx context.Context) (any, error) { return r.Resolver.LookupIPAddr(ctx, target) }},
		{"cname", func(ctx context.Context) (any, error) { return r.Resolver.LookupCNAME(ctx, target) }},
		{"mx", func(ctx context.Context) (any, error) { return r.Resolver.LookupMX(ctx, target) }},
		{"ns", func(ctx context.Context) (any, error) { return r.Resolver.LookupNS(ctx, target) }},
		{"txt", func(ctx context.Context) (any, error) { return r.Resolver.LookupTXT(ctx, target) }},
	}

	results := make(chan lookupOutput, len(jobs))
	for _, job := range jobs {
		go func(name string, fn func(context.Context) (any, error)) {
			ctx, cancel := r.context()
			defer cancel()
			data, err := fn(ctx)
			results <- lookupOutput{name: name, data: data, err: err}
		}(job.name, job.fn)
	}

	for range jobs {
		out := <-results
		if out.err != nil {
			result.Warnings = append(result.Warnings, out.name+" lookup: "+out.err.Error())
			continue
		}

		switch out.name {
		case "ip":
			for _, ip := range out.data.([]net.IPAddr) {
				if v4 := ip.IP.To4(); v4 != nil {
					result.A = appendUnique(result.A, v4.String())
				} else {
					result.AAAA = appendUnique(result.AAAA, ip.IP.String())
				}
			}
		case "cname":
			if cname := strings.TrimSuffix(out.data.(string), "."); cname != "" && cname != target {
				result.CNAME = appendUnique(result.CNAME, cname)
			}
		case "mx":
			for _, record := range out.data.([]*net.MX) {
				result.MX = appendUnique(result.MX, strings.TrimSuffix(record.Host, ".")+" (priority "+itoa(record.Pref)+")")
			}
			sort.Strings(result.MX)
		case "ns":
			for _, record := range out.data.([]*net.NS) {
				result.NS = appendUnique(result.NS, strings.TrimSuffix(record.Host, "."))
			}
			sort.Strings(result.NS)
		case "txt":
			for _, record := range out.data.([]string) {
				result.TXT = appendUnique(result.TXT, record)
			}
			sort.Strings(result.TXT)
		}
	}

	ips := append(append([]string{}, result.A...), result.AAAA...)
	ptrResults := make(chan ptrOutput, len(ips))
	for _, ip := range ips {
		go func(ip string) {
			ctx, cancel := r.context()
			defer cancel()
			names, err := r.Resolver.LookupAddr(ctx, ip)
			ptrResults <- ptrOutput{ip: ip, names: names, err: err}
		}(ip)
	}

	result.PTR = map[string][]string{}
	for range ips {
		out := <-ptrResults
		if out.err != nil {
			result.Warnings = append(result.Warnings, "PTR lookup for "+out.ip+": "+out.err.Error())
			continue
		}
		for _, name := range out.names {
			result.PTR[out.ip] = appendUnique(result.PTR[out.ip], strings.TrimSuffix(name, "."))
		}
		sort.Strings(result.PTR[out.ip])
	}
	if len(result.PTR) == 0 {
		result.PTR = nil
	}

	result.Security.SPF = inspectSPF(target, result.TXT)
	result.Security.DMARC = inspectDMARC(r, target, &result)
	result.Security.DNSSEC = inspectDNSSEC(r, target, &result)
	result.Security.Summary = buildSummary(result.Security)

	if !result.Security.SPF.Present {
		result.Warnings = append(result.Warnings, "SPF record not found")
	}
	if !result.Security.DMARC.Present {
		result.Warnings = append(result.Warnings, "DMARC record not found")
	}
	if result.Security.DNSSEC.Status == "unknown" {
		result.Warnings = append(result.Warnings, "DNSSEC status could not be determined")
	}

	sort.Strings(result.Warnings)
	result.ElapsedMS = time.Since(start).Milliseconds()
	return result
}

type ptrOutput struct {
	ip    string
	names []string
	err   error
}

func inspectSPF(target string, txt []string) SPFResult {
	var result SPFResult
	for _, record := range txt {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=spf1") {
			result.Present = true
			result.Records = appendUnique(result.Records, record)
		}
	}
	sort.Strings(result.Records)
	return result
}

func inspectDMARC(r *Resolver, target string, result *LookupResult) DMARCResult {
	ctx, cancel := r.context()
	defer cancel()
	records, err := r.Resolver.LookupTXT(ctx, "_dmarc."+target)
	if err != nil {
		result.Warnings = append(result.Warnings, "DMARC lookup: "+err.Error())
		return DMARCResult{}
	}

	var out DMARCResult
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=dmarc1") {
			out.Present = true
			out.Records = appendUnique(out.Records, record)
		}
	}
	sort.Strings(out.Records)
	return out
}

func inspectDNSSEC(r *Resolver, target string, result *LookupResult) DNSSECResult {
	const endpoint = "https://cloudflare-dns.com/dns-query"

	dnskey, err := dohQuery(r, endpoint, target, "DNSKEY")
	if err != nil {
		result.Warnings = append(result.Warnings, "DNSSEC DNSKEY check: "+err.Error())
		return DNSSECResult{Status: "unknown", CheckedVia: "Cloudflare DoH"}
	}

	status := "unsigned"
	if dnskey.hasAnswerType(48) {
		status = "signed"
	}

	authenticated := false
	if status == "signed" {
		a, aErr := dohQuery(r, endpoint, target, "A")
		if aErr != nil {
			result.Warnings = append(result.Warnings, "DNSSEC validation check: "+aErr.Error())
		} else {
			authenticated = a.AD
		}
	}

	return DNSSECResult{
		Status:     status,
		Validated:  authenticated,
		CheckedVia: "Cloudflare DoH",
	}
}

type dohAnswer struct {
	Type int `json:"type"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	AD     bool        `json:"AD"`
	Answer []dohAnswer `json:"Answer"`
}

func (r *Resolver) dohURL(endpoint, name, recordType string) string {
	values := url.Values{}
	values.Set("name", name)
	values.Set("type", recordType)
	values.Set("do", "1")
	return endpoint + "?" + values.Encode()
}

func dohQuery(r *Resolver, endpoint, name, recordType string) (dohResponse, error) {
	ctx, cancel := r.context()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.dohURL(endpoint, name, recordType), nil)
	if err != nil {
		return dohResponse{}, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return dohResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return dohResponse{}, fmt.Errorf("DoH returned HTTP %d", resp.StatusCode)
	}

	var out dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return dohResponse{}, err
	}
	if out.Status == 3 {
		return out, fmt.Errorf("DNS name does not exist")
	}
	return out, nil
}

func (r dohResponse) hasAnswerType(recordType int) bool {
	for _, answer := range r.Answer {
		if answer.Type == recordType {
			return true
		}
	}
	return false
}

func buildSummary(security SecurityResult) SecuritySummary {
	spf := "missing"
	if security.SPF.Present {
		spf = "present"
	}

	dmarc := "missing"
	if security.DMARC.Present {
		dmarc = "present"
	}

	dnssec := security.DNSSEC.Status
	if security.DNSSEC.Validated {
		dnssec = "validated"
	}

	return SecuritySummary{SPF: spf, DMARC: dmarc, DNSSEC: dnssec}
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
