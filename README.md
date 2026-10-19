# hsts-verify

A small Bash tool for verifying **"Missing HSTS"** findings during VAPT and collecting audit-ready evidence. Run it once **before** a fix to confirm the finding, and once **after** to confirm remediation. Each run produces a timestamped evidence bundle with raw headers, scanner output, a summary CSV and a SHA-256 manifest.

The tool performs only light, read-only checks (a few GET requests per host plus header-only scans). Run it only against hosts you are authorised to test.

---

## What it checks

| # | Check | Purpose |
|---|-------|---------|
| 1 | HTTPS response headers on `/`, a non-existent path, and any asset URLs you supply | Confirms whether `Strict-Transport-Security` is sent on normal, error (403/404) and real asset responses, and whether `max-age` meets the minimum |
| 2 | HTTP → HTTPS redirect | Confirms plain HTTP redirects to HTTPS (expected alongside HSTS) |
| 3 | `nmap --script http-security-headers` | Independent second confirmation |
| 4 | `testssl --headers` | Report-friendly HSTS and header check, with an HTML report per host |

Each tested HTTPS response is classed as:

- **PRESENT** — header set with `max-age` at or above the minimum (default 1 year)
- **PRESENT (max-age < N)** — header set but `max-age` is too low
- **MISSING** — no HSTS header
- **NO RESPONSE** — request failed or timed out

---

## Requirements

- Bash 4+ and `curl` (required)
- `nmap` (optional, preinstalled on Kali)
- `testssl.sh` (optional; install with `sudo apt install testssl.sh`, may be named `testssl` on some systems)

Missing optional tools are skipped with a warning.

---

## Installation

```bash
chmod +x hsts-verify.sh
```

If you get `Permission denied` (for example, on a mounted drive with `noexec`), run it with `bash hsts-verify.sh ...` instead.

---

## Usage

```
./hsts-verify.sh <before|after> [options] [host ...]
```

| Option | Description |
|--------|-------------|
| `-f FILE` | File with hosts, one per line |
| `-a FILE` | File with extra asset URLs to test, one per line |
| `-u URL` | Single extra asset URL (repeatable) |
| `-m SECS` | Minimum acceptable `max-age` (default `31536000`, 1 year) |
| `-N` | Skip nmap |
| `-T` | Skip testssl |
| `-h` | Show help |

The first argument must be `before` or `after`. Hosts can be passed as arguments, with `-f`, or both.

### Input files

Lines starting with `#` and blank lines are ignored.

`hosts.txt`
```
# Hosts from VAPT queue
cdn.example.com
api.example.com
https://assets.example.com/some/path   # URLs are reduced to the hostname
```

`assets.txt`
```
# One real asset per host (copy from browser DevTools > Network)
https://cdn.example.com/static/app.js
https://api.example.com/_health
```

Hosts are lower-cased, stripped of scheme and path, de-duplicated, and validated. Invalid entries are skipped with a warning.

### Examples

```bash
# Hosts on the command line
./hsts-verify.sh before cdn.example.com api.example.com

# Hosts and assets from files (recommended)
./hsts-verify.sh before -f hosts.txt -a assets.txt

# Add a single asset and skip testssl
./hsts-verify.sh after -f hosts.txt -u https://cdn.example.com/app.js -T

# Accept a 6-month max-age as the minimum
./hsts-verify.sh after -f hosts.txt -m 15768000
```

---

## Recommended VAPT workflow

1. **Collect asset URLs.** Open the web app in a browser, press F12, go to the Network tab, filter by each host, and copy one real asset URL per host into `assets.txt`.
2. **Run `before`.** If the summary says *Finding CONFIRMED*, mark the finding as a true positive in your VAPT tool and attach the archive.
3. **Apply the fix** under an approved change ticket (for example, a CDN response-header rule).
4. **Run `after` with the same input files**, so the before and after evidence covers identical URLs.
5. If the summary says *REMEDIATED*, attach the archive, mark the finding as fixed, and re-run your automated scan before removing hosts from the queue.

Keep the before archive, after archive, change ticket and a screenshot of the configuration change together as the audit trail.

---

## Output

Each run creates a folder and a matching archive in the current directory:

```
hsts-before-20261019T080000Z/
├── evidence.log            # Readable log of every check and the verdict
├── summary.csv             # One row per tested URL (attach to tickets)
├── MANIFEST.sha256         # Checksums of every file in the bundle
├── raw/                    # Raw response headers for each request
├── nmap/
│   └── http-security-headers.txt
└── testssl/
    ├── <host>.html         # Per-host HTML report
    └── <host>.log
hsts-before-20261019T080000Z.tar.gz
```

`summary.csv` columns: `phase, timestamp_utc, url, http_status, hsts_header, max_age, result`

To verify a bundle has not been modified:

```bash
cd hsts-before-20261019T080000Z && sha256sum -c MANIFEST.sha256
```

---

## Interpreting results

- **Before:** any `MISSING` result confirms the finding. If nothing is missing, the finding may be a false positive or already fixed. Check whether the scanner tested a different path or protocol.
- **After:** the tool reports *REMEDIATED* only when every tested response is `PRESENT` with an adequate `max-age` and none failed to respond.
- The HTTP redirect responses will **not** carry HSTS. This is expected, because browsers ignore HSTS sent over plain HTTP.

---

## Troubleshooting

| Problem | Likely cause and fix |
|---------|----------------------|
| `Permission denied` | Run with `bash hsts-verify.sh ...` |
| `NO RESPONSE` on a host | DNS issue, firewall, or WAF blocking or challenging your IP. Check connectivity with `curl -v https://host/` |
| Header present on some paths but not others | The fix is applied at the wrong layer or scoped too narrowly (for example, set at origin but stripped by the CDN, or an Nginx `add_header` missing `always`) |
| testssl skipped | Not installed, or installed as `testssl` rather than `testssl.sh` (both are detected) |
| testssl takes a long time | Expected for hosts with many IPs. The tool uses `--ip one` to test one IP per host |

---

## Limitations

- Tests port 443 only.
- Does not check HSTS preload list status (see hstspreload.org).
- Does not assess `includeSubDomains` coverage across all subdomains.
- Verifies headers only. It is not a substitute for a full manual penetration test.
