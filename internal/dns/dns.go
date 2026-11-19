package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	defaultDoHEndpoint = "https://cloudflare-dns.com/dns-query"
	maxPTRLookups      = 64
	ptrWorkers         = 8
	maxDoHBodyBytes    = 1 << 20

	typeDNSKEY = 48
	typeSOA    = 6
	typeCAA    = 257
)

var errNXDomain = errors.New("DNS name does not exist")

type Resolver struct {
	Resolver *net.Resolver
	Timeout  time.Duration
	HTTP     *http.Client
	DoH      string
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
	CAA       []string            `json:"CAA"`
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
		DoH:      defaultDoHEndpoint,
	}
}

func (r *Resolver) context() (context.Context, context.CancelFunc) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (r *Resolver) Lookup(target string) LookupResult {
	start := time.Now()
	result := LookupResult{
		Target: target,
		A:      []string{},
		AAAA:   []string{},
		MX:     []string{},
		NS:     []string{},
		TXT:    []string{},
		CAA:    []string{},
		CNAME:  []string{},
	}

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
			if cname := strings.TrimSuffix(out.data.(string), "."); cname != "" && !strings.EqualFold(cname, target) {
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
	if len(ips) > maxPTRLookups {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"PTR lookups limited to the first %d of %d addresses", maxPTRLookups, len(ips)))
		ips = ips[:maxPTRLookups]
	}

	ptrs, ptrWarnings := r.lookupPTRs(ips)
	result.PTR = ptrs
	result.Warnings = append(result.Warnings, ptrWarnings...)

	result.CAA = r.inspectCAA(target, &result)
	result.Security.SPF = inspectSPF(result.TXT)
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

type ptrResult struct {
	ip    string
	names []string
	err   error
}

// lookupPTRs resolves reverse DNS names with a bounded worker pool so a domain
// with many addresses cannot spawn an unbounded number of goroutines.
func (r *Resolver) lookupPTRs(ips []string) (map[string][]string, []string) {
	if len(ips) == 0 {
		return nil, nil
	}

	workers := ptrWorkers
	if len(ips) < workers {
		workers = len(ips)
	}

	jobs := make(chan string)
	results := make(chan ptrResult, len(ips))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				ctx, cancel := r.context()
				names, err := r.Resolver.LookupAddr(ctx, ip)
				cancel()
				results <- ptrResult{ip: ip, names: names, err: err}
			}
		}()
	}

	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
	}()

	wg.Wait()
	close(results)

	ptrs := map[string][]string{}
	var warnings []string
	for out := range results {
		if out.err != nil {
			warnings = append(warnings, "PTR lookup for "+out.ip+": "+out.err.Error())
			continue
		}
		for _, name := range out.names {
			ptrs[out.ip] = appendUnique(ptrs[out.ip], strings.TrimSuffix(name, "."))
		}
		sort.Strings(ptrs[out.ip])
	}
	if len(ptrs) == 0 {
		return nil, warnings
	}
	return ptrs, warnings
}

// ValidateTarget checks that a target is a plausible hostname before it is used
// for DNS lookups or printed to a terminal.
func ValidateTarget(target string) error {
	if target == "" {
		return errors.New("target domain is required")
	}
	if strings.HasSuffix(target, "..") {
		return errors.New("target domain must not contain repeated trailing dots")
	}
	name := strings.ToLower(strings.TrimSuffix(target, "."))
	if name == "" {
		return errors.New("target domain is required")
	}
	if len(name) > 253 {
		return errors.New("target domain must be 253 characters or fewer")
	}

	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return errors.New("target domain contains an empty label")
		}
		if len(label) > 63 {
			return errors.New("target domain contains a label longer than 63 characters")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("target domain label %q must not start or end with a hyphen", label)
		}
		for _, ch := range label {
			switch {
			case ch >= 'a' && ch <= 'z':
			case ch >= '0' && ch <= '9':
			case ch == '-' || ch == '_':
			case unicode.IsControl(ch), unicode.IsSpace(ch):
				return fmt.Errorf("target domain contains whitespace or control characters")
			default:
				return fmt.Errorf("target domain contains invalid character %q; use an ASCII or punycode name", ch)
			}
		}
	}
	return nil
}

func inspectSPF(txt []string) SPFResult {
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

// inspectCAA fetches Certificate Authority Authorization records through the
// same DoH resolver used for DNSSEC checks. CAA lives outside net.Resolver's
// standard lookup helpers, so DoH is the dependency-free way to read it.
func (r *Resolver) inspectCAA(target string, result *LookupResult) []string {
	ctx, cancel := r.context()
	defer cancel()

	resp, err := r.dohQuery(ctx, target, "CAA")
	if err != nil {
		if !errors.Is(err, errNXDomain) {
			result.Warnings = append(result.Warnings, "CAA lookup: "+err.Error())
		}
		return []string{}
	}

	records := []string{}
	for _, answer := range resp.Answer {
		if answer.Type != typeCAA {
			continue
		}
		if data := strings.TrimSpace(answer.Data); data != "" {
			records = appendUnique(records, data)
		}
	}
	sort.Strings(records)
	return records
}

func inspectDNSSEC(r *Resolver, target string, result *LookupResult) DNSSECResult {
	const checkedVia = "Cloudflare DoH"

	ctx, cancel := r.context()
	defer cancel()

	found, successes, dnsErrs := r.findDNSKEY(ctx, target)
	for _, errText := range dnsErrs {
		result.Warnings = append(result.Warnings, "DNSSEC DNSKEY check: "+errText)
	}

	status := "unknown"
	switch {
	case found:
		status = "signed"
	case successes > 0 && len(dnsErrs) == 0:
		status = "unsigned"
	}

	validated := false
	if status == "signed" {
		validated = r.dnssecValidated(ctx, target, result)
	}

	return DNSSECResult{
		Status:     status,
		Validated:  validated,
		CheckedVia: checkedVia,
	}
}

// findDNSKEY looks for a DNSKEY RRset at the target and at its signing zone.
// DNSKEY records live at the zone apex, so a subdomain query alone would
// incorrectly report signed zones as unsigned.
func (r *Resolver) findDNSKEY(ctx context.Context, target string) (bool, int, []string) {
	tried := map[string]bool{}
	successes := 0
	var dnsErrs []string
	var last dohResponse

	target = strings.ToLower(strings.TrimSuffix(target, "."))
	tried[target] = true

	resp, err := r.dohQuery(ctx, target, "DNSKEY")
	switch {
	case err == nil:
		successes++
		last = resp
		if resp.hasAnswerType(typeDNSKEY) {
			return true, successes, dnsErrs
		}
	case errors.Is(err, errNXDomain):
		// A nonexistent target has no signing zone to inspect.
		return false, successes + 1, dnsErrs
	default:
		dnsErrs = append(dnsErrs, target+": "+err.Error())
	}

	try := func(name string) bool {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if name == "" || tried[name] {
			return false
		}
		tried[name] = true

		resp, err := r.dohQuery(ctx, name, "DNSKEY")
		if err != nil {
			if errors.Is(err, errNXDomain) {
				successes++
				return false
			}
			dnsErrs = append(dnsErrs, name+": "+err.Error())
			return false
		}
		successes++
		return resp.hasAnswerType(typeDNSKEY)
	}

	// The SOA in the authority section usually names the actual zone apex.
	for _, answer := range last.Authority {
		if answer.Type != typeSOA || !isSubdomainOf(target, answer.Name) {
			continue
		}
		if try(answer.Name) {
			return true, successes, dnsErrs
		}
	}

	// Fall back to walking parent labels, skipping the TLD and, for ccTLDs,
	// the public-suffix-like second level (for example co.uk).
	labels := strings.Split(target, ".")
	for i := 1; i < len(labels); i++ {
		suffix := labels[i:]
		if len(suffix) == 1 {
			break
		}
		if len(suffix) == 2 && len(labels[len(labels)-1]) == 2 {
			break
		}
		if try(strings.Join(suffix, ".")) {
			return true, successes, dnsErrs
		}
	}

	return false, successes, dnsErrs
}

func (r *Resolver) dnssecValidated(ctx context.Context, target string, result *LookupResult) bool {
	validated := false
	answered := false
	var dnsErrs []string

	for _, recordType := range []string{"A", "AAAA"} {
		resp, err := r.dohQuery(ctx, target, recordType)
		if err != nil {
			if errors.Is(err, errNXDomain) {
				answered = true
				continue
			}
			dnsErrs = append(dnsErrs, recordType+": "+err.Error())
			continue
		}
		answered = true
		if resp.AD {
			validated = true
		}
	}

	if !answered && len(dnsErrs) > 0 {
		result.Warnings = append(result.Warnings, "DNSSEC validation check: "+strings.Join(dnsErrs, "; "))
	}
	return validated
}

func isSubdomainOf(name, zone string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if name == "" || zone == "" {
		return false
	}
	return name == zone || strings.HasSuffix(name, "."+zone)
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status    int         `json:"Status"`
	AD        bool        `json:"AD"`
	Answer    []dohAnswer `json:"Answer"`
	Authority []dohAnswer `json:"Authority"`
}

func (r *Resolver) dohURL(name, recordType string) string {
	endpoint := r.DoH
	if endpoint == "" {
		endpoint = defaultDoHEndpoint
	}
	values := url.Values{}
	values.Set("name", name)
	values.Set("type", recordType)
	values.Set("do", "1")
	return endpoint + "?" + values.Encode()
}

func (r *Resolver) dohQuery(ctx context.Context, name, recordType string) (dohResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.dohURL(name, recordType), nil)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDoHBodyBytes)).Decode(&out); err != nil {
		return dohResponse{}, err
	}

	switch out.Status {
	case 0:
		return out, nil
	case 3:
		return out, errNXDomain
	default:
		return out, fmt.Errorf("DoH returned DNS status %d", out.Status)
	}
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
