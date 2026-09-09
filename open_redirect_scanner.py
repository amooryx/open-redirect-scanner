import urllib.request, urllib.error, rclib
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a): return None
def run(ctx):
    base = ctx.target if "://" in ctx.target else "https://" + ctx.target
    canary = "https://redcell-redirect.example/"
    params = ["next","url","redirect","return","returnUrl","dest","destination","continue","r","u"]
    op = urllib.request.build_opener(NoRedirect)
    sep = "&" if "?" in base else "?"
    hit = False
    for p in params:
        test = f"{base}{sep}{p}={canary}"
        try:
            r = op.open(urllib.request.Request(test, headers={"User-Agent":"redcell"}), timeout=12)
            loc = r.headers.get("Location","")
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location","")
        except Exception:
            continue
        if loc.startswith(canary):
            hit = True
            ctx.finding(f"Open redirect via '{p}'", "medium", detail=test, location=loc)
    if not hit: ctx.info("no reflected redirect on common params")
    return 0
rclib.main("open-redirect-scanner", "Open-redirect parameter tester", run)
