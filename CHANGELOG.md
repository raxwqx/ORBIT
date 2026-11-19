# Changelog

## 0.2.0 - 2026-11-19

### Added

- CAA (Certificate Authority Authorization) record discovery through Cloudflare DNS-over-HTTPS, shown as a dedicated terminal section and a top-level `CAA` array in JSON.
- Turkish `README.md` and English `README_EN.md`, both documenting CAA support, DNSSEC behavior, limits, and the new validation rules.
- Go test and build CI for Linux, macOS, and Windows across Go 1.23–1.25.
- Unit tests for target validation, DoH status handling, CAA parsing, DNSSEC zone-apex detection, public-suffix skipping, terminal sanitization, and CLI help/version behavior.

### Fixed

- DNSSEC checks now inspect the signing zone instead of only the queried name. Subdomains such as `www.ietf.org` are correctly reported as `signed` when their parent zone publishes DNSKEY records.
- DNSSEC no longer reports `unsigned` when a DoH query fails with SERVFAIL, REFUSED, or another non-zero DNS status; the status is `unknown` and a warning is recorded.
- DNSSEC validation queries both A and AAAA, so IPv6-only names are not silently treated as unvalidated.
- CAA and DNSSEC DoH responses are capped at 1 MiB, and all DNSSEC probes share one timeout budget.
- PTR lookups now use a bounded worker pool (8 workers) and are capped at 64 addresses instead of spawning one unbounded goroutine per IP.
- Target input is validated before any lookup: empty labels, repeated trailing dots, whitespace, control characters, invalid ASCII, overlong labels, and leading/trailing hyphens are rejected with a clear error.
- Target names are lowercased, and CNAME self-comparison is case-insensitive.
- One trailing dot is trimmed exactly once; repeated trailing dots are rejected.
- `--timeout` is capped at 300 seconds, and non-positive values remain rejected.
- DNS-derived terminal output is sanitized: TXT/CAA records, PTR names, resolver errors, and the target cannot inject ANSI escapes, control characters, or forged lines. Long values are truncated.
- CLI help and version requests no longer terminate inside `parseArgs`, so they are testable and print to stdout.
- Flag parse errors are printed once instead of duplicating the flag package's error and usage output.
- `--timeout` now reports a clear missing-value error when used without a value.
- JSON record arrays (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CAA`, `CNAME`) are emitted as empty arrays instead of `null` for machine consumers.

### Changed

- `--help` and `--version` write to stdout; validation and lookup errors continue to write to stderr with exit code `2`.
- README examples and the JSON schema were refreshed for CAA output, DNSSEC apex behavior, and the sanitization/limit guarantees.
