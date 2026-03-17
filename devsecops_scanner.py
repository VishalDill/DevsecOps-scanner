# devsecops_scanner.py
# Scans a URL for missing security headers and pulls CVE data from NIST NVD.
# Spits out a JSON report when done.
#
# pip install requests
#
# python devsecops_scanner.py --url https://example.com
# python devsecops_scanner.py --cve "apache log4j" --severity CRITICAL
# python devsecops_scanner.py --url https://example.com --cve "nginx" --output report.json

import argparse
import json
import sys
from datetime import datetime, timezone

import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 15

# Headers we care about, what they do, and what a reasonable value looks like
HEADERS_TO_CHECK = {
    "Strict-Transport-Security": {
        "info": "Tells the browser to only use HTTPS — stops SSL stripping.",
        "hint": "max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "info": "Whitelists where scripts/styles can load from. Big XSS mitigation.",
        "hint": "default-src 'self'",
    },
    "X-Frame-Options": {
        "info": "Blocks your page from being iframed — kills most clickjacking attempts.",
        "hint": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "info": "Stops browsers from guessing the content type (MIME sniffing).",
        "hint": "nosniff",
    },
    "Referrer-Policy": {
        "info": "Controls how much URL info leaks in the Referer header.",
        "hint": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "info": "Locks down browser APIs like camera, mic, geolocation.",
        "hint": "geolocation=(), microphone=(), camera=()",
    },
    "X-XSS-Protection": {
        "info": "Old-school XSS header. Mostly obsolete but still worth having.",
        "hint": "1; mode=block",
    },
    "Cache-Control": {
        "info": "Keeps sensitive responses out of the browser cache.",
        "hint": "no-store (on anything sensitive)",
    },
}

# ANSI color codes
COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[32m",
    "NONE":     "\033[37m",
    "RESET":    "\033[0m",
}


def paint(text, level):
    c = COLORS.get(level.upper(), "")
    return f"{c}{text}{COLORS['RESET']}"


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Header Scanner

def check_headers(target_url):
    print(f"\n[*] Header scan: {target_url}")

    out = {
        "url":         target_url,
        "scanned_at":  utc_now(),
        "status_code": None,
        "server":      None,
        "findings":    [],
        "score":       None,
        "grade":       None,
    }

    try:
        resp = requests.get(
            target_url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "sec-audit/1.0"},
        )
    except requests.exceptions.SSLError as e:
        out["error"] = f"SSL error: {e}"
        print(paint(f"SSL handshake failed: {e}", "CRITICAL"))
        return out
    except requests.exceptions.ConnectionError as e:
        out["error"] = f"Connection failed: {e}"
        print(paint(f"Couldn't connect: {e}", "HIGH"))
        return out
    except requests.exceptions.Timeout:
        out["error"] = f"Timed out after {TIMEOUT}s"
        print(paint("Request timed out", "MEDIUM"))
        return out

    out["status_code"] = resp.status_code
    out["server"]      = resp.headers.get("Server", "hidden")
    out["raw_headers"] = dict(resp.headers)

    print(f"HTTP {resp.status_code}  |  Server: {out['server']}")
    print(f"Resolved to: {resp.url}\n")

    hits = 0
    for hdr, meta in HEADERS_TO_CHECK.items():
        found = hdr in resp.headers
        val   = resp.headers.get(hdr, "not set")

        out["findings"].append({
            "header": hdr,
            "status": "pass" if found else "fail",
            "value":  val,
            "info":   meta["info"],
            "hint":   meta["hint"],
        })

        if found:
            hits += 1
            print(f"{paint('PASS', 'LOW')}  {hdr}  ->  {val}")
        else:
            print(f"{paint('FAIL', 'HIGH')}  {hdr}")
            print(f"missing -- should be: {meta['hint']}")

    pct   = round((hits / len(HEADERS_TO_CHECK)) * 100)
    grade = (
        "A" if pct >= 90 else
        "B" if pct >= 75 else
        "C" if pct >= 60 else
        "D" if pct >= 40 else
        "F"
    )

    out["score"] = pct
    out["grade"] = grade

    sev_map = {"A": "LOW", "B": "LOW", "C": "MEDIUM", "D": "HIGH", "F": "CRITICAL"}
    print(f"\n  Score: {paint(f'{pct}/100 -- Grade {grade}', sev_map[grade])}  ({hits}/{len(HEADERS_TO_CHECK)} headers present)\n")

    return out


# ---- CVE Lookup -------------------------------------------------------------

def fetch_cves(keyword, sev_filter=None, limit=10):
    print(f"\n[*] CVE lookup: '{keyword}'" + (f"  [filter: {sev_filter}]" if sev_filter else ""))

    query = {
        "keywordSearch": keyword,
        "resultsPerPage": limit,
        "startIndex": 0,
    }
    if sev_filter:
        query["cvssV3Severity"] = sev_filter.upper()

    out = {
        "keyword": keyword,
        "filter": sev_filter,
        "queried_at": utc_now(),
        "total": 0,
        "cves": [],
    }

    try:
        resp = requests.get(
            NVD_URL,
            params=query,
            timeout=TIMEOUT,
            headers={"User-Agent": "sec-audit/1.0"},
        )
        resp.raise_for_status()
    except requests.exceptions.HTTPError as e:
        out["error"] = f"HTTP error {resp.status_code}: {e}"
        print(paint(f"NVD returned an error: {e}", "HIGH"))
        return out
    except requests.exceptions.RequestException as e:
        out["error"] = str(e)
        print(paint(f"Request failed: {e}", "HIGH"))
        return out

    # NVD returns a deeply nested JSON blob dig through it to grab what we need
    try:
        blob = resp.json()
    except json.JSONDecodeError as e:
        out["error"] = f"Couldn't parse response JSON: {e}"
        print(paint(f"Bad JSON from NVD: {e}", "HIGH"))
        return out

    out["total"] = blob.get("totalResults", 0)
    vulns = blob.get("vulnerabilities", [])

    print(f"{out['total']} total matches -- showing first {len(vulns)}\n")

    for entry in vulns:
        cve_node = entry.get("cve", {})
        cve_id = cve_node.get("id", "unknown")

        # Grab the English description
        descs = cve_node.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "no description")

        # Try CVSSv3.1 first, fall back to v3.0, then v2 as a last resort
        metrics = cve_node.get("metrics", {})
        v3_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        severity = "unknown"
        score = None
        vec = None

        if v3_list:
            cvss = v3_list[0].get("cvssData", {})
            severity = cvss.get("baseSeverity", "unknown")
            score = cvss.get("baseScore")
            vec = cvss.get("vectorString")

        if severity == "unknown":
            v2_list = metrics.get("cvssMetricV2", [])
            if v2_list:
                cvss = v2_list[0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = v2_list[0].get("baseSeverity", "unknown")
                vec = cvss.get("vectorString")

        pub_date = cve_node.get("published", "n/a")[:10]
        refs = [r["url"] for r in cve_node.get("references", [])[:3]]

        record = {
            "id":          cve_id,
            "severity":    severity,
            "score":       score,
            "vector":      vec,
            "published":   pub_date,
            "description": desc[:300] + ("..." if len(desc) > 300 else ""),
            "refs":        refs,
        }
        out["cves"].append(record)

        score_tag = f"(CVSS {score})" if score else ""
        print(f"  {paint(f'[{severity.upper()}]', severity.upper())} {score_tag}  {cve_id}  |  {pub_date}")
        print(f"  {desc[:120]}{'...' if len(desc) > 120 else ''}")
        if refs:
            print(f"  -> {refs[0]}")
        print()

    return out


# Report Writer

def save_report(data, path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] Report saved: {paint(path, 'LOW')}")
    except OSError as e:
        print(paint(f"Couldn't write report: {e}", "HIGH"))


# CLI

def get_args():
    ap = argparse.ArgumentParser(
        prog="devsecops_scanner",
        description="HTTP header auditor + NVD CVE lookup. Outputs a JSON report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python devsecops_scanner.py --url https://example.com
  python devsecops_scanner.py --cve "log4j" --severity CRITICAL
  python devsecops_scanner.py --url https://nginx.org --cve nginx --output out.json
        """,
    )
    ap.add_argument("--url",      metavar="URL",  help="target URL to scan for security headers")
    ap.add_argument("--cve",      metavar="TERM", help="keyword to search in NIST NVD")
    ap.add_argument("--severity", metavar="LVL",  choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    default=None, help="filter CVEs by severity")
    ap.add_argument("--max-cves", metavar="N",    type=int, default=10,
                    help="max CVE results to fetch (default: 10)")
    ap.add_argument("--output",   metavar="FILE", default=None,
                    help="where to save the report (auto-named if not set)")
    return ap.parse_args()


def main():
    args = get_args()

    if not args.url and not args.cve:
        print(paint("need at least --url or --cve", "HIGH"))
        sys.exit(1)

    report = {
        "scanner":     "devsecops_scanner v1.0",
        "run_at":      utc_now(),
        "header_scan": None,
        "cve_lookup":  None,
    }

    if args.url:
        report["header_scan"] = check_headers(args.url)

    if args.cve:
        report["cve_lookup"] = fetch_cves(args.cve, args.severity, args.max_cves)

    fname = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save_report(report, fname)
    print(f"\nDone. Full report at: {fname}\n")


if __name__ == "__main__":
    main()