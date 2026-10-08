package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/raxwqx/orbit/internal/dns"
)

type Result = dns.LookupResult

func PrintJSON(w io.Writer, result any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func PrintTerminal(w io.Writer, result Result) {
	fmt.Fprintln(w, "🛰️ ORBIT")
	fmt.Fprintf(w, "Target: %s\n", result.Target)
	fmt.Fprintf(w, "Elapsed: %d ms\n\n", result.ElapsedMS)

	printSection(w, "IPv4 (A)", result.A)
	printSection(w, "IPv6 (AAAA)", result.AAAA)
	printSection(w, "Mail (MX)", result.MX)
	printSection(w, "Nameservers (NS)", result.NS)
	printSection(w, "Aliases (CNAME)", result.CNAME)
	printSection(w, "TXT", result.TXT)

	if len(result.PTR) > 0 {
		fmt.Fprintln(w, "Reverse DNS (PTR)")
		keys := make([]string, 0, len(result.PTR))
		for key := range result.PTR {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(w, "  %s ->\n", key)
			for _, value := range result.PTR[key] {
				fmt.Fprintf(w, "    • %s\n", value)
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Security")
	fmt.Fprintf(w, "  • SPF:   %s\n", result.Security.Summary.SPF)
	fmt.Fprintf(w, "  • DMARC: %s\n", result.Security.Summary.DMARC)
	fmt.Fprintf(w, "  • DNSSEC: %s", result.Security.Summary.DNSSEC)
	if result.Security.DNSSEC.Validated {
		fmt.Fprint(w, " (Cloudflare DoH validated)")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	if len(result.Security.SPF.Records) > 0 {
		fmt.Fprintln(w, "SPF Records")
		for _, record := range result.Security.SPF.Records {
			fmt.Fprintf(w, "  • %s\n", record)
		}
		fmt.Fprintln(w)
	}

	if len(result.Security.DMARC.Records) > 0 {
		fmt.Fprintln(w, "DMARC Records")
		for _, record := range result.Security.DMARC.Records {
			fmt.Fprintf(w, "  • %s\n", record)
		}
		fmt.Fprintln(w)
	}

	if len(result.Warnings) > 0 {
		fmt.Fprintln(w, "Warnings")
		for _, warning := range result.Warnings {
			fmt.Fprintf(w, "  ! %s\n", warning)
		}
	}
}

func printSection(w io.Writer, title string, values []string) {
	fmt.Fprintln(w, title)
	if len(values) == 0 {
		fmt.Fprintln(w, "  -")
	} else {
		for _, value := range values {
			fmt.Fprintf(w, "  • %s\n", value)
		}
	}
	fmt.Fprintln(w)
}
