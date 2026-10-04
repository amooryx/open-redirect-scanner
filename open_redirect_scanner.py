"""Check common query parameters for redirects to a reserved example domain."""

from __future__ import annotations

import http.client
import urllib.error
import urllib.parse
import urllib.request

import rclib

CANARY = "https://redcell-redirect.example/"
PARAMS = (
    "next",
    "url",
    "redirect",
    "return",
    "returnUrl",
    "dest",
    "destination",
    "continue",
    "r",
    "u",
)
REQUEST_TIMEOUT = 12
REDIRECT_STATUSES = frozenset((300, 301, 302, 303, 307, 308))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def normalize_target(target: str) -> str:
    """Require an HTTP(S) URL with a hostname; default bare hosts to HTTPS."""
    target = target.strip()
    if not target:
        raise ValueError("target must not be empty")
    if "://" not in target:
        target = "https://" + target

    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be an HTTP or HTTPS URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target URLs must not contain credentials")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("target URL contains an invalid port") from exc
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, parsed.fragment)
    )


def build_test_url(base: str, parameter: str) -> str:
    """Set one probe parameter while preserving the rest of the target query."""
    parsed = urllib.parse.urlsplit(base)
    query = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != parameter
    ]
    query.append((parameter, CANARY))
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment)
    )


def is_verified_redirect(base: str, location: str) -> bool:
    """Only verify a redirect whose resolved destination is the exact canary origin."""
    try:
        destination = urllib.parse.urlsplit(urllib.parse.urljoin(base, location))
        if destination.username is not None or destination.password is not None:
            return False
        return (
            destination.scheme.lower() == "https"
            and destination.hostname is not None
            and destination.hostname.lower() == "redcell-redirect.example"
            and destination.port in (None, 443)
        )
    except ValueError:
        return False


def is_candidate_redirect(location: str) -> bool:
    """Identify canary reflection in a redirect that does not meet verification."""
    return "redcell-redirect.example" in urllib.parse.unquote(location).lower()


def get_redirect_response(opener, test_url: str) -> tuple[int, str]:
    request = urllib.request.Request(test_url, headers={"User-Agent": "open-redirect-scanner"})
    try:
        response = opener.open(request, timeout=REQUEST_TIMEOUT)
    except urllib.error.HTTPError as exc:
        response = exc

    try:
        return response.code, response.headers.get("Location", "")
    finally:
        response.close()


def run(ctx):
    base = normalize_target(ctx.target)
    opener = urllib.request.build_opener(NoRedirect)
    verified = 0
    candidates = 0
    failures = 0

    for parameter in PARAMS:
        test_url = build_test_url(base, parameter)
        try:
            status, location = get_redirect_response(opener, test_url)
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            failures += 1
            ctx.warn(f"request for parameter '{parameter}' failed: {exc}")
            continue

        if status not in REDIRECT_STATUSES or not location:
            continue

        evidence = {"parameter": parameter, "status": status, "location": location}
        detail = f"parameter={parameter}; HTTP {status}"
        if is_verified_redirect(base, location):
            verified += 1
            ctx.finding("Verified open redirect", "medium", detail=detail, **evidence)
        elif is_candidate_redirect(location):
            candidates += 1
            ctx.finding("Candidate open redirect indicator", "low", detail=detail, **evidence)

    ctx.data["redirect_scan"] = {
        "requests": len(PARAMS),
        "failures": failures,
        "verified_redirects": verified,
        "candidate_indicators": candidates,
    }
    if not verified and not candidates:
        if failures:
            ctx.warn("no redirect indicator found in successful responses; scan was incomplete")
        else:
            ctx.info("no canary redirect indicator found on common parameters")
    return 1 if failures else 0


if __name__ == "__main__":
    rclib.main("open-redirect-scanner", "Open-redirect parameter tester", run)
