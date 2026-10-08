# 🛰️ ORBIT

**Lightweight DNS & network intelligence tool written in Go.**

ORBIT performs focused, passive-friendly DNS reconnaissance against a domain and produces a compact terminal report covering IPv4/IPv6 resolution, mail servers, nameservers, TXT records, CNAME aliases, reverse DNS, lookup timing, DNS security posture, and resolver warnings.

The project is intentionally small and uses only Go's standard library. Its optional DNSSEC validation check uses Cloudflare's DNS-over-HTTPS endpoint and does not require a third-party Go dependency.

## Features

- A / AAAA records
- MX records
- NS records
- TXT records
- CNAME records
- Reverse DNS (PTR) for resolved IPs
- DNS lookup timing
- SPF detection and record extraction
- DMARC detection and record extraction
- DNSSEC signed / unsigned / validated status
- Human-readable terminal output
- JSON output
- Configurable DNS and HTTP timeout
- Standard-library only
- Concurrent DNS lookups

## Installation

```bash
git clone https://github.com/raxwqx/orbit.git
cd orbit
go build -o orbit ./cmd/orbit
```

## Usage

```bash
./orbit example.com
```

JSON output:

```bash
./orbit example.com --json
```

Custom timeout:

```bash
./orbit example.com --timeout 10
```

Run directly with Go:

```bash
go run ./cmd/orbit example.com
```

Run tests:

```bash
go test ./...
```

## Example

```text
🛰️ ORBIT
Target: example.com
Elapsed: 80 ms

IPv4 (A)
  • 104.20.23.154
  • 172.66.147.243

IPv6 (AAAA)
  • 2606:4700:10::ac42:93f3

Mail (MX)
  • 0 . (priority 0)

Nameservers (NS)
  • elliott.ns.cloudflare.com
  • hera.ns.cloudflare.com

Security
  • SPF:   present
  • DMARC: missing
  • DNSSEC: unsigned
```

## Security checks

ORBIT identifies SPF and DMARC records by querying DNS TXT records.

DNSSEC status is checked through Cloudflare DNS over HTTPS. A zone is reported as `signed` when DNSKEY records are returned, and `validated` when Cloudflare reports authenticated DNS data for the validation query.

## JSON structure

JSON output contains the same DNS intelligence as the terminal report, plus machine-readable security results:

```json
{
  "target": "example.com",
  "elapsed_ms": 80,
  "A": [],
  "AAAA": [],
  "MX": [],
  "NS": [],
  "TXT": [],
  "CNAME": [],
  "PTR": {},
  "security": {
    "spf": {
      "present": false,
      "records": []
    },
    "dmarc": {
      "present": false,
      "records": []
    },
    "dnssec": {
      "status": "unknown",
      "validated": false,
      "checked_via": "Cloudflare DoH"
    },
    "summary": {
      "spf": "missing",
      "dmarc": "missing",
      "dnssec": "unknown"
    }
  },
  "warnings": []
}
```

## Scope

ORBIT is designed for authorized security research, asset inventory, troubleshooting, and DNS-focused reconnaissance. It does not perform port scanning, exploitation, credential attacks, or intrusive service probing.

## License

MIT
