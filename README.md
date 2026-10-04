<div align="center">
  <img src="./banner.svg" alt="open-redirect-scanner" width="800">
</div>

# open-redirect-scanner

An authorized-testing tool that checks common query parameters for open-redirect
behavior. Use it only against systems you own or have explicit permission to test.

```bash
python open_redirect_scanner.py --help
python open_redirect_scanner.py example.test
```

## Scan behavior

The scanner makes at most ten sequential HTTP requests per target, one for each
common redirect parameter. Each request has a 12-second timeout. Bare hostnames
use HTTPS; only HTTP and HTTPS targets are accepted, and URLs containing
credentials are rejected. TLS certificate verification remains enabled. Redirect
responses are inspected but never followed.

The probe destination uses the reserved `redcell-redirect.example` domain. A
**Verified open redirect** is reported only when a 3xx response's resolved
`Location` points to that exact HTTPS origin. A **Candidate open redirect
indicator** is reported when a 3xx `Location` reflects the canary hostname but
does not resolve to the exact canary origin; this includes percent-encoded
reflections, which are never treated as verified redirects. Review candidates
manually. Network failures are reported, and the process returns a nonzero status
if any request failed, indicating the scan may be incomplete.

Run the offline regression tests with:

```bash
python -m unittest discover -s tests -v
```

The shared runtime prompts for authorization; `--yes` skips that prompt and
should only be used when authorization has already been established.

## Author

**Omar Khalid**
