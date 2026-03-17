# test_scanner.py
# Run with: pytest test_scanner.py -v
#
# These tests mock out the actual HTTP calls so you don't need live internet access.
# A few tests at the bottom DO hit real endpoints if you want to run them manually.

import json
import pytest
from unittest.mock import patch, MagicMock

from devsecops_scanner import (
    check_headers,
    fetch_cves,
    paint,
    utc_now,
    HEADERS_TO_CHECK,
)


# Helpers

def make_response(status=200, headers=None, json_body=None, url="https://example.com"):
    """Build a fake requests.Response object."""
    mock = MagicMock()
    mock.status_code = status
    mock.url         = url
    mock.headers     = headers or {}
    mock.json.return_value = json_body or {}
    return mock


def all_secure_headers():
    """Return a dict with every header we check set to a valid value."""
    return {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy":   "default-src 'self'",
        "X-Frame-Options":           "DENY",
        "X-Content-Type-Options":    "nosniff",
        "Referrer-Policy":           "strict-origin-when-cross-origin",
        "Permissions-Policy":        "geolocation=()",
        "X-XSS-Protection":          "1; mode=block",
        "Cache-Control":             "no-store",
        "Server":                    "nginx",
    }


def test_paint_wraps_critical():
    result = paint("oops", "CRITICAL")
    assert "\033[91m" in result   # bright red
    assert "oops" in result
    assert "\033[0m" in result    # reset at end


def test_paint_unknown_level_no_crash():
    # should not raise, just return the text
    result = paint("hello", "WHATEVER")
    assert "hello" in result


# utc_now()

def test_utc_now_format():
    ts = utc_now()
    # should look like 2024-11-15T14:32:00Z
    assert len(ts) == 20
    assert ts.endswith("Z")
    assert ts[4] == "-" and ts[7] == "-"


# check_headers()

class TestCheckHeaders:

    @patch("devsecops_scanner.requests.get")
    def test_all_headers_present_grades_a(self, mock_get):
        mock_get.return_value = make_response(headers=all_secure_headers())
        result = check_headers("https://example.com")

        assert result["grade"] == "A"
        assert result["score"] == 100
        assert result["status_code"] == 200
        assert len(result["findings"]) == len(HEADERS_TO_CHECK)

    @patch("devsecops_scanner.requests.get")
    def test_no_headers_grades_f(self, mock_get):
        # Only set Server, none of the security headers
        mock_get.return_value = make_response(headers={"Server": "apache"})
        result = check_headers("https://example.com")

        assert result["grade"] == "F"
        assert result["score"] == 0
        # every finding should be a fail
        statuses = [f["status"] for f in result["findings"]]
        assert all(s == "fail" for s in statuses)

    @patch("devsecops_scanner.requests.get")
    def test_half_headers_somewhere_between_c_and_d(self, mock_get):
        # Set exactly 4 out of 8 headers
        hdrs = dict(list(all_secure_headers().items())[:4])
        mock_get.return_value = make_response(headers=hdrs)
        result = check_headers("https://example.com")

        assert result["score"] == 50
        assert result["grade"] == "D"

    @patch("devsecops_scanner.requests.get")
    def test_server_header_captured(self, mock_get):
        mock_get.return_value = make_response(headers={"Server": "cloudflare"})
        result = check_headers("https://example.com")
        assert result["server"] == "cloudflare"

    @patch("devsecops_scanner.requests.get")
    def test_server_hidden_when_absent(self, mock_get):
        mock_get.return_value = make_response(headers={})
        result = check_headers("https://example.com")
        assert result["server"] == "hidden"

    @patch("devsecops_scanner.requests.get")
    def test_ssl_error_returns_error_key(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.SSLError("bad cert")
        result = check_headers("https://self-signed.badssl.com")

        assert "error" in result
        assert "SSL" in result["error"]
        assert result["status_code"] is None

    @patch("devsecops_scanner.requests.get")
    def test_connection_error_returns_error_key(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError("refused")
        result = check_headers("https://doesnotexist.invalid")

        assert "error" in result

    @patch("devsecops_scanner.requests.get")
    def test_timeout_returns_error_key(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.Timeout()
        result = check_headers("https://example.com")

        assert "error" in result
        assert "Timed out" in result["error"]

    @patch("devsecops_scanner.requests.get")
    def test_raw_headers_stored(self, mock_get):
        hdrs = all_secure_headers()
        mock_get.return_value = make_response(headers=hdrs)
        result = check_headers("https://example.com")

        assert "raw_headers" in result
        assert isinstance(result["raw_headers"], dict)

    @patch("devsecops_scanner.requests.get")
    def test_findings_contain_required_keys(self, mock_get):
        mock_get.return_value = make_response(headers=all_secure_headers())
        result = check_headers("https://example.com")

        for finding in result["findings"]:
            assert "header" in finding
            assert "status" in finding
            assert "value"  in finding
            assert "hint"   in finding


# fetch_cves() 

# Minimal fake NVD response with one CVE
FAKE_NVD_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints."},
                    {"lang": "es", "value": "Spanish description here"},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore":    10.0,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "references": [
                    {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
                ],
            }
        }
    ],
}


class TestFetchCves:

    @patch("devsecops_scanner.requests.get")
    def test_parses_cve_id(self, mock_get):
        mock_get.return_value = make_response(json_body=FAKE_NVD_RESPONSE)
        result = fetch_cves("log4j")

        assert len(result["cves"]) == 1
        assert result["cves"][0]["id"] == "CVE-2021-44228"

    @patch("devsecops_scanner.requests.get")
    def test_parses_severity_and_score(self, mock_get):
        mock_get.return_value = make_response(json_body=FAKE_NVD_RESPONSE)
        result = fetch_cves("log4j")

        cve = result["cves"][0]
        assert cve["severity"] == "CRITICAL"
        assert cve["score"]    == 10.0

    @patch("devsecops_scanner.requests.get")
    def test_english_description_selected(self, mock_get):
        mock_get.return_value = make_response(json_body=FAKE_NVD_RESPONSE)
        result = fetch_cves("log4j")

        desc = result["cves"][0]["description"]
        assert "Apache Log4j2" in desc
        assert "Spanish" not in desc   # should not have grabbed the 'es' entry

    @patch("devsecops_scanner.requests.get")
    def test_published_date_trimmed(self, mock_get):
        mock_get.return_value = make_response(json_body=FAKE_NVD_RESPONSE)
        result = fetch_cves("log4j")

        # Should be YYYY-MM-DD only
        assert result["cves"][0]["published"] == "2021-12-10"

    @patch("devsecops_scanner.requests.get")
    def test_refs_capped_at_three(self, mock_get):
        # Give it 5 references, expect only 3 back
        blob = json.loads(json.dumps(FAKE_NVD_RESPONSE))
        blob["vulnerabilities"][0]["cve"]["references"] = [
            {"url": f"https://example.com/ref{i}"} for i in range(5)
        ]
        mock_get.return_value = make_response(json_body=blob)
        result = fetch_cves("log4j")

        assert len(result["cves"][0]["refs"]) == 3

    @patch("devsecops_scanner.requests.get")
    def test_total_results_captured(self, mock_get):
        blob = dict(FAKE_NVD_RESPONSE)
        blob["totalResults"] = 247
        mock_get.return_value = make_response(json_body=blob)
        result = fetch_cves("nginx")

        assert result["total"] == 247

    @patch("devsecops_scanner.requests.get")
    def test_empty_results(self, mock_get):
        mock_get.return_value = make_response(json_body={"totalResults": 0, "vulnerabilities": []})
        result = fetch_cves("xyzzy_nothing_matches_this")

        assert result["total"] == 0
        assert result["cves"] == []

    @patch("devsecops_scanner.requests.get")
    def test_bad_json_returns_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = json.JSONDecodeError("boom", "", 0)
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = fetch_cves("anything")
        assert "error" in result

    @patch("devsecops_scanner.requests.get")
    def test_http_error_returns_error(self, mock_get):
        import requests as req
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status.side_effect = req.exceptions.HTTPError("403 Forbidden")
        mock_get.return_value = mock_resp

        result = fetch_cves("openssl")
        assert "error" in result

    @patch("devsecops_scanner.requests.get")
    def test_v2_fallback_when_no_v3(self, mock_get):
        """If there's no CVSSv3 data, we should fall back to v2."""
        blob = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2002-0001",
                        "published": "2002-01-15T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Old vuln with only CVSS v2 data."}],
                        "metrics": {
                            "cvssMetricV2": [
                                {
                                    "baseSeverity": "HIGH",
                                    "cvssData": {
                                        "baseScore":    7.8,
                                        "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
                                    },
                                }
                            ]
                        },
                        "references": [],
                    }
                }
            ],
        }
        mock_get.return_value = make_response(json_body=blob)
        result = fetch_cves("old vuln")

        cve = result["cves"][0]
        assert cve["severity"] == "HIGH"
        assert cve["score"]    == 7.8

    @patch("devsecops_scanner.requests.get")
    def test_severity_filter_passed_to_api(self, mock_get):
        mock_get.return_value = make_response(json_body={"totalResults": 0, "vulnerabilities": []})
        fetch_cves("openssl", sev_filter="HIGH")

        call_kwargs = mock_get.call_args
        # Check the params dict passed to requests.get
        params = call_kwargs[1].get("params") or call_kwargs[0][1]
        assert params.get("cvssV3Severity") == "HIGH"


# save_report()
class TestSaveReport:

    def test_writes_valid_json(self, tmp_path):
        from devsecops_scanner import save_report

        data = {"scanner": "test", "findings": [{"id": "CVE-2021-1234", "score": 9.8}]}
        out  = tmp_path / "test_report.json"
        save_report(data, str(out))

        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded["scanner"] == "test"
        assert loaded["findings"][0]["score"] == 9.8

    def test_bad_path_does_not_raise(self):
        from devsecops_scanner import save_report
        # Should print an error but not crash the program
        save_report({"x": 1}, "/no/such/dir/report.json")


# Integration-ish tests (mocked end-to-end)

class TestEndToEnd:

    @patch("devsecops_scanner.requests.get")
    def test_full_scan_output_shape(self, mock_get):
        mock_get.return_value = make_response(headers=all_secure_headers())
        result = check_headers("https://example.com")

        assert result["score"]  is not None
        assert result["grade"]  is not None
        assert result["findings"]
        assert result["raw_headers"]

    @patch("devsecops_scanner.requests.get")
    def test_full_cve_output_shape(self, mock_get):
        mock_get.return_value = make_response(json_body=FAKE_NVD_RESPONSE)
        result = fetch_cves("log4j", sev_filter="CRITICAL", limit=5)

        assert result["total"] == 1
        assert len(result["cves"]) == 1
        assert result["filter"] == "CRITICAL"


# Real network tests (skipped by default) 
# Remove the skip decorator if you want to hit real endpoints.

@pytest.mark.skip(reason="hits the real internet -- run manually")
def test_live_header_scan_example_com():
    result = check_headers("https://example.com")
    assert result["status_code"] == 200
    assert result["score"] is not None
    assert isinstance(result["findings"], list)


@pytest.mark.skip(reason="hits the real NVD API -- run manually")
def test_live_cve_lookup_log4j():
    result = fetch_cves("log4j", sev_filter="CRITICAL", limit=3)
    assert result["total"] > 0
    assert any("CVE-2021-44228" in c["id"] for c in result["cves"])


@pytest.mark.skip(reason="hits the real internet -- run manually")
def test_live_scan_known_bad_headers():
    # http://neverssl.com is deliberately minimal and won't have security headers
    result = check_headers("http://neverssl.com")
    assert result["grade"] in ("D", "F")
