# 🛰️ ORBIT

**Lightweight DNS & network intelligence tool written in Go.**

[Türkçe dokümantasyon](README.md)

ORBIT performs focused, passive-friendly DNS reconnaissance against a domain and produces a compact terminal report covering IPv4/IPv6 resolution, mail servers, nameservers, TXT records, CNAME aliases, CAA policies, reverse DNS, lookup timing, DNS security posture, and resolver warnings.

The project is intentionally small and uses only Go's standard library. Its optional DNSSEC validation and CAA lookups use Cloudflare's DNS-over-HTTPS endpoint and require no third-party Go dependency.

<p>
  <img alt="Go 1.23+" src="https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white" />
  <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-14B8A6.svg" />
  <img alt="No runtime dependencies" src="https://img.shields.io/badge/Runtime%20dependencies-None-64748B.svg" />
  <a href="https://github.com/raxwqx/ORBIT/actions/workflows/tests.yml"><img alt="Tests" src="https://github.com/raxwqx/ORBIT/actions/workflows/tests.yml/badge.svg?branch=main" /></a>
</p>

## Features

- A / AAAA records
- MX records
- NS records
- TXT records
- CNAME records
- **CAA (Certificate Authority Authorization) records** — new
- Reverse DNS (PTR) for resolved IPs
- DNS lookup timing
- SPF detection and record extraction
- DMARC detection and record extraction
- DNSSEC signed / unsigned / validated status
- Correct DNSSEC zone detection for subdomains
- Human-readable terminal output
- JSON output
- Configurable DNS and HTTP timeout
- Standard-library only
- Concurrent, bounded DNS lookups
- Terminal control-character sanitization

## Requirements

- Go 1.23 or newer
- HTTPS access to `cloudflare-dns.com` for DNSSEC and CAA checks
- Access to the system resolver (usually the local network) for other records

## Installation

Build from source:

```bash
git clone https://github.com/raxwqx/ORBIT.git
cd ORBIT
go build -o orbit ./cmd/orbit
```

Run directly with Go:

```bash
go run ./cmd/orbit example.com
```

## Usage

```bash
./orbit example.com
```

JSON output:

```bash
./orbit example.com --json
```

Custom timeout (seconds):

```bash
./orbit example.com --timeout 10
```

Specify the target with a flag:

```bash
./orbit --target example.com --json
```

Help and version:

```bash
./orbit --help
./orbit --version
```

Flags may appear before or after the positional target. Supplying both `--target` and a positional target is an error.

### Timeout

`--timeout` defaults to `5` seconds and accepts an integer from `1` to `300`. The value applies to both system resolver queries and Cloudflare DoH requests.

### Target validation

ORBIT validates the target before querying:

- The domain may be at most 253 characters and each label at most 63 characters.
- Empty labels, leading/trailing hyphens, whitespace, and control characters are rejected.
- Only ASCII letters, digits, hyphens, and underscores are accepted. Use punycode (`xn--...`) for internationalized names.
- One trailing dot is accepted and removed; repeated trailing dots are rejected.
- Input is lowercased because DNS names are case-insensitive.

## Example output

```text
🛰️ ORBIT
Target: example.com
Elapsed: 412 ms

IPv4 (A)
  • 192.0.2.10
  • 192.0.2.11

IPv6 (AAAA)
  • 2001:db8::10

Mail (MX)
  • mail.example.com (priority 10)
  • mail2.example.com (priority 20)

Nameservers (NS)
  • ns1.example.com
  • ns2.example.com

Aliases (CNAME)
  -

TXT
  • v=spf1 include:_spf.example.net ~all

Certificate Authorities (CAA)
  • 0 iodef "mailto:security@example.com"
  • 0 issue "letsencrypt.org"
  • 0 issuewild "letsencrypt.org"

Reverse DNS (PTR)
  192.0.2.10 ->
    • host.example.com

Security
  • SPF:   present
  • DMARC: present
  • DNSSEC: validated (Cloudflare DoH validated)

SPF Records
  • v=spf1 include:_spf.example.net ~all

DMARC Records
  • v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com
```

## Security checks

ORBIT identifies SPF and DMARC records by querying DNS TXT records.

DNSSEC status is checked through Cloudflare DNS-over-HTTPS. DNSKEY records live at the zone apex, so ORBIT inspects the zone named by the authoritative SOA record and walks parent labels instead of trusting the target name alone. This prevents subdomains such as `www.example.com` from being misreported as unsigned when `example.com` is signed. A zone is reported as `signed` when DNSKEY records are returned, and `validated` when Cloudflare reports authenticated DNS data for the validation query.

CAA records are read through the same DoH resolver to show the certificate authority policy. A missing CAA record does not produce a warning because CAA is an optional policy.

DNS responses are treated as untrusted input. All domain names, TXT/CAA records, PTR names, and resolver error messages in terminal output are stripped of control characters, and long values are truncated. A malicious DNS response therefore cannot inject ANSI escape sequences or forged report lines.

## Limits

- Reverse DNS lookups cover at most 64 addresses. If more are present, only the first 64 are processed and a warning is shown.
- PTR lookups use at most 8 concurrent workers, so a domain with many A/AAAA records does not spawn an unbounded number of goroutines.
- Each phase is bounded by `--timeout`. On a very slow resolver, total runtime can approach the sum of the phases.
- DNSSEC validation reflects Cloudflare's view of the data; ORBIT is not a local validating resolver.
- CAA and DNSSEC checks require internet access. Without it, those sections return missing/`unknown` with a warning.

## JSON structure

JSON output contains the same DNS intelligence as the terminal report, plus machine-readable security results:

```json
{
  "target": "example.com",
  "elapsed_ms": 412,
  "A": ["192.0.2.1"],
  "AAAA": ["2001:db8::1"],
  "MX": ["mail.example.com (priority 10)"],
  "NS": ["ns1.example.com", "ns2.example.com"],
  "TXT": ["v=spf1 -all"],
  "CAA": ["0 issue \"letsencrypt.org\""],
  "CNAME": [],
  "PTR": {
    "192.0.2.1": ["host.example.com"]
  },
  "security": {
    "spf": {
      "present": true,
      "records": ["v=spf1 -all"]
    },
    "dmarc": {
      "present": false
    },
    "dnssec": {
      "status": "signed",
      "validated": true,
      "checked_via": "Cloudflare DoH"
    },
    "summary": {
      "spf": "present",
      "dmarc": "missing",
      "dnssec": "validated"
    }
  },
  "warnings": []
}
```

Notes:

- `CAA` is a top-level array; it is empty when no CAA records exist.
- `PTR` only appears when at least one reverse DNS name was found.
- `warnings` is omitted entirely when empty.
- `MX` and `NS` values are formatted strings for readability.

## Tests

```bash
go test ./...
go vet ./...
```

CI runs the tests, `go vet`, and a build on Linux, macOS, and Windows with Go 1.23–1.25.

## Scope

ORBIT is designed for authorized security research, asset inventory, troubleshooting, and DNS-focused reconnaissance. It does not perform port scanning, exploitation, credential attacks, or intrusive service probing.

Only query domains you are authorized to inspect.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT
