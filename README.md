# devsecops_scanner

A Python script I put together to automate two things:

1. Checking whether a web server has its security headers configured properly
2. Pulling CVE data from NIST's NVD to see what known vulnerabilities exist for a given package or keyword

It runs both checks from the CLI and dumps everything into a JSON file you can feed into other tooling (or just read yourself).

---

## What it checks

**HTTP security headers** — the script looks for 8 headers that matter in practice:

- `Strict-Transport-Security` — HTTPS enforcement, stops SSL stripping
- `Content-Security-Policy` — XSS mitigation via source whitelisting  
- `X-Frame-Options` — clickjacking protection
- `X-Content-Type-Options` — kills MIME sniffing
- `Referrer-Policy` — limits URL leakage through the Referer header
- `Permissions-Policy` — restricts camera/mic/geolocation API access
- `X-XSS-Protection` — legacy, but still worth having
- `Cache-Control` — keeps sensitive responses out of the browser cache

It grades the result A–F based on how many are present.

**CVE lookup** — queries the [NIST NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) by keyword. You can filter by severity (CRITICAL, HIGH, etc.) and it parses the nested CVSS scoring out of the response — tries v3.1 first, falls back to v3.0, then v2 if that's all that's there.

---

## Setup

```bash
pip install requests
```



---

## Usage

```bash
# just scan headers
python devsecops_scanner.py --url https://example.com

# just look up CVEs
python devsecops_scanner.py --cve "log4j" --severity CRITICAL

# both at once, save to a specific file
python devsecops_scanner.py --url https://nginx.org --cve "nginx" --output report.json

# control how many CVE results come back
python devsecops_scanner.py --cve "openssl" --max-cves 25
```

If you don't pass `--output`, the script auto-names the report with a timestamp like `report_20241115_143200.json`.

---

## Sample targets to try


| Target | What to expect |
|---|---|
| `https://google.com` | CSP and HSTS present, a few others missing — decent score |
| `https://github.com` | Strong headers across the board, should grade A or B |
| `https://example.com` | Minimal headers, expect a D or F — good "bad example" |
| `http://neverssl.com` | No HTTPS, no security headers at all — F grade |
| `https://expired.badssl.com` | SSL error — tests the error handling path |
| `https://self-signed.badssl.com` | SSL cert error — same |

For CVE searches:
```bash
python devsecops_scanner.py --cve "log4j" --severity CRITICAL          # the Log4Shell vuln should show up
python devsecops_scanner.py --cve "openssl heartbleed" --severity HIGH  # Heartbleed
python devsecops_scanner.py --cve "apache struts" --max-cves 5         # Equifax-related vulns
python devsecops_scanner.py --cve "nginx" --severity MEDIUM            # broad search, lots of results
```

---

## Running the tests

```bash
pip install pytest
pytest test_scanner.py -v
```

Tests mock out all HTTP calls so you don't need internet access. There are a few live network tests at the bottom of the test file that are skipped by default — remove the `@pytest.mark.skip` decorator if you want to run those against real endpoints.

---

## JSON report structure

```json
{
  "scanner": "devsecops_scanner v1.0",
  "run_at": "2024-11-15T14:32:00Z",
  "header_scan": {
    "url": "https://example.com",
    "score": 25,
    "grade": "F",
    "server": "ECS (dcb/7EA3)",
    "findings": [
      {
        "header": "Content-Security-Policy",
        "status": "fail",
        "value": "not set",
        "info": "Whitelists where scripts/styles can load from. Big XSS mitigation.",
        "hint": "default-src 'self'"
      }
    ]
  },
  "cve_lookup": {
    "keyword": "nginx",
    "total": 247,
    "cves": [
      {
        "id": "CVE-2024-XXXXX",
        "severity": "HIGH",
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "published": "2024-09-20",
        "description": "..."
      }
    ]
  }
}
```
