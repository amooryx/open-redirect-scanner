import unittest
import urllib.error
from unittest.mock import Mock, patch

import open_redirect_scanner as scanner


class FakeResponse:
    def __init__(self, code, location=""):
        self.code = code
        self.headers = {"Location": location}
        self.closed = False

    def close(self):
        self.closed = True


class FakeContext:
    target = "example.test/account?keep=this"

    def __init__(self):
        self.findings = []
        self.messages = []
        self.data = {}

    def finding(self, title, severity, detail="", **evidence):
        self.findings.append((title, severity, detail, evidence))

    def info(self, message):
        self.messages.append(("info", message))

    def warn(self, message):
        self.messages.append(("warn", message))


class ScannerTests(unittest.TestCase):
    def test_normalize_target_defaults_to_https_and_rejects_unsafe_urls(self):
        self.assertEqual(scanner.normalize_target(" example.test/path "), "https://example.test/path")
        self.assertEqual(scanner.normalize_target("http://example.test"), "http://example.test")
        for target in (
            "",
            "ftp://example.test",
            "https://user:password@example.test",
            "https://example.test:invalid",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                scanner.normalize_target(target)

    def test_build_test_url_preserves_other_query_values_and_fragment(self):
        url = scanner.build_test_url(
            "https://example.test/path?keep=a+b&next=old&keep=again#section",
            "next",
        )
        parsed = scanner.urllib.parse.urlsplit(url)
        self.assertEqual(parsed.fragment, "section")
        self.assertEqual(
            scanner.urllib.parse.parse_qs(parsed.query),
            {"keep": ["a b", "again"], "next": [scanner.CANARY]},
        )

    def test_verification_requires_exact_canary_origin(self):
        base = "https://example.test/"
        self.assertTrue(scanner.is_verified_redirect(base, scanner.CANARY + "path"))
        for location in (
            "https://redcell-redirect.example.attacker.test/",
            "https://attacker.test@redcell-redirect.example/",
            "http://redcell-redirect.example/",
            "https://redcell-redirect.example:444/",
        ):
            with self.subTest(location=location):
                self.assertFalse(scanner.is_verified_redirect(base, location))
        self.assertFalse(scanner.is_verified_redirect(base, "https://[malformed"))

    def test_encoded_canary_is_candidate_but_not_verified(self):
        location = "https://example.test/continue?url=https%3A%2F%2Fredcell-redirect.example%2F"
        self.assertTrue(scanner.is_candidate_redirect(location))
        self.assertFalse(scanner.is_verified_redirect("https://example.test/", location))

    def test_http_error_redirect_response_is_read_and_closed(self):
        response = urllib.error.HTTPError(
            "https://example.test/", 302, "Found", {"Location": scanner.CANARY}, None
        )
        opener = Mock()
        opener.open.side_effect = response

        self.assertEqual(
            scanner.get_redirect_response(opener, "https://example.test/"),
            (302, scanner.CANARY),
        )
        self.assertTrue(response.closed)

    @patch("open_redirect_scanner.urllib.request.build_opener")
    def test_run_separates_verified_and_candidate_redirects(self, build_opener):
        responses = [
            FakeResponse(302, scanner.CANARY + "destination"),
            FakeResponse(302, "https://redcell-redirect.example.attacker.test/"),
        ] + [FakeResponse(200) for _ in range(len(scanner.PARAMS) - 2)]
        opener = Mock()
        opener.open.side_effect = responses
        build_opener.return_value = opener
        ctx = FakeContext()

        self.assertEqual(scanner.run(ctx), 0)
        self.assertEqual(ctx.data["redirect_scan"]["verified_redirects"], 1)
        self.assertEqual(ctx.data["redirect_scan"]["candidate_indicators"], 1)
        self.assertEqual(ctx.findings[0][0], "Verified open redirect")
        self.assertEqual(ctx.findings[1][0], "Candidate open redirect indicator")
        self.assertTrue(all(response.closed for response in responses))
        self.assertEqual(opener.open.call_count, len(scanner.PARAMS))
        self.assertTrue(all(call.kwargs["timeout"] == scanner.REQUEST_TIMEOUT
                            for call in opener.open.call_args_list))

    @patch("open_redirect_scanner.urllib.request.build_opener")
    def test_request_failures_are_reported_and_make_scan_incomplete(self, build_opener):
        opener = Mock()
        opener.open.side_effect = urllib.error.URLError("offline")
        build_opener.return_value = opener
        ctx = FakeContext()

        self.assertEqual(scanner.run(ctx), 1)
        self.assertEqual(ctx.data["redirect_scan"]["failures"], len(scanner.PARAMS))
        self.assertEqual(len(ctx.messages), len(scanner.PARAMS) + 1)
        self.assertTrue(all(level == "warn" for level, _ in ctx.messages))


if __name__ == "__main__":
    unittest.main()
