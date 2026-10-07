"""Explainable observations from one response. Never a claim of comprehensive testing."""

import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookies import SimpleCookie, CookieError
from urllib.parse import urlsplit
from app.web.transport import Page

REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"


class Resources(HTMLParser):
    def __init__(self):
        super().__init__()
        self.insecure = []

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        field = (
            "src"
            if tag in ("script", "img", "iframe", "audio", "video")
            else "href"
            if tag == "link"
            else "action"
            if tag == "form"
            else None
        )
        value = fields.get(field or "", "") or ""
        if field and value.lower().startswith("http://") and len(self.insecure) < 20:
            self.insecure.append(f"HTML line {self.getpos()[0]} · <{tag}> {field} attribute")


def inspect(page: Page) -> dict:
    headers = {}
    for key, value in page.headers:
        if key.lower() != "set-cookie":
            headers[key.lower()] = headers.get(key.lower(), "") + (", " if key.lower() in headers else "") + value
    findings = []
    checks = []
    html = (
        "text/html" in headers.get("content-type", "").lower()
        or "application/xhtml+xml" in headers.get("content-type", "").lower()
    )
    successful = 200 <= page.status < 300

    def record(key, title, seen, severity, evidence, impact, fix, applicable=True, classification="configuration_gap"):
        checks.append(
            {"id": key, "name": title, "status": "pass" if seen else "review" if applicable else "not_assessed"}
        )
        if not seen and applicable:
            findings.append(
                {
                    "id": key,
                    "title": title,
                    "severity": severity,
                    "classification": classification,
                    "location": page.url,
                    "evidence": evidence,
                    "impact": impact,
                    "recommendation": fix,
                    "verification": "Observed in this HTTP response; applicability and real-world impact require review.",
                    "reference": REFERENCE,
                }
            )

    secure = urlsplit(page.url).scheme == "https"
    record(
        "transport",
        "HTTPS transport",
        secure,
        "medium",
        "The final inspected response used plain HTTP.",
        "Traffic on this connection has no TLS protection.",
        "Serve the page over HTTPS and redirect HTTP to HTTPS.",
    )
    hsts = headers.get("strict-transport-security", "")
    max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts, re.I)
    record(
        "hsts",
        "HSTS response policy",
        bool(max_age and len(max_age.group(1)) <= 12 and int(max_age.group(1)) > 0),
        "low",
        "No positive HSTS max-age was observed.",
        "Browsers may revisit the origin over HTTP unless other protection applies.",
        "After validating HTTPS across the deployment, configure Strict-Transport-Security with a positive max-age.",
        applicable=secure and successful,
    )
    csp = headers.get("content-security-policy", "")
    directives = {part.strip().split()[0].lower() for part in csp.split(";") if part.strip()}
    record(
        "csp",
        "Content Security Policy header",
        bool(csp),
        "low",
        "No enforcing CSP response header was observed.",
        "A defense-in-depth control is absent from these headers; this does not establish an XSS vulnerability. Meta policies are not evaluated.",
        "Develop and test an application-specific CSP; start with Report-Only before enforcing.",
        applicable=html and successful,
    )
    frame = (
        headers.get("x-frame-options", "").strip().lower() in ("deny", "sameorigin") or "frame-ancestors" in directives
    )
    record(
        "framing",
        "Framing restriction",
        frame,
        "low",
        "Neither CSP frame-ancestors nor a valid X-Frame-Options value was observed.",
        "Interactive pages may need protection against untrusted framing; exploitability is not verified.",
        "Use an appropriate CSP frame-ancestors policy, or X-Frame-Options DENY/SAMEORIGIN where suitable.",
        applicable=html and successful,
    )
    record(
        "nosniff",
        "Content type protection",
        headers.get("x-content-type-options", "").strip().lower() == "nosniff",
        "low",
        "X-Content-Type-Options: nosniff was not observed.",
        "Browsers may infer a content type in contexts where MIME sniffing is allowed.",
        "Set X-Content-Type-Options: nosniff and correct Content-Type values.",
        applicable=successful,
    )
    record(
        "referrer",
        "Referrer policy",
        bool(headers.get("referrer-policy")),
        "info",
        "No explicit Referrer-Policy header was observed.",
        "Browser defaults may already protect cross-origin referrers; review whether a stricter policy is needed.",
        "Choose Referrer-Policy according to the application, e.g. strict-origin-when-cross-origin.",
        applicable=html and successful,
    )
    disclosures = {
        k: headers[k][:200] for k in ("server", "x-powered-by", "x-aspnet-version") if k in headers and headers[k]
    }
    checks.append(
        {"id": "technology", "name": "Technology response headers", "status": "review" if disclosures else "pass"}
    )
    if disclosures:
        findings.append(
            {
                "id": "technology",
                "title": "Technology headers exposed",
                "severity": "info",
                "classification": "observed_disclosure",
                "location": page.url,
                "evidence": "; ".join(f"{k}: {v}" for k, v in disclosures.items()),
                "impact": "Public technology hints can assist fingerprinting. No vulnerable version or CVE is inferred.",
                "recommendation": "Remove unnecessary version/banner headers at the application or reverse proxy.",
                "verification": "Header values were observed; vulnerability status is not established.",
                "reference": REFERENCE,
            }
        )
    cookies = []
    for key, value in page.headers:
        if key.lower() != "set-cookie":
            continue
        jar = SimpleCookie()
        try:
            jar.load(value)
        except CookieError:
            continue
        for name, cookie in jar.items():
            info = {
                "name": name[:100],
                "secure": bool(cookie["secure"]),
                "http_only": bool(cookie["httponly"]),
                "same_site": cookie["samesite"].lower() or "unspecified",
            }
            cookies.append(info)
            missing = [
                flag
                for flag, ok in (
                    ("Secure", info["secure"]),
                    ("HttpOnly", info["http_only"]),
                    ("SameSite", info["same_site"] in ("lax", "strict", "none")),
                )
                if not ok
            ]
            if missing:
                findings.append(
                    {
                        "id": f"cookie-{len(cookies)}",
                        "title": "Review cookie protection attributes",
                        "severity": "low",
                        "classification": "configuration_review",
                        "location": page.url + " · Set-Cookie #" + str(len(cookies)),
                        "evidence": "Cookie "
                        + name[:100]
                        + ": absent attributes "
                        + ", ".join(missing)
                        + ". Values are not retained.",
                        "impact": "Required attributes depend on the cookie purpose; JavaScript-readable cookies may intentionally omit HttpOnly.",
                        "recommendation": "For sensitive session cookies use Secure, HttpOnly, and an appropriate SameSite policy. Review functionality before changing other cookies.",
                        "verification": "Attribute omission observed; cookie sensitivity and exploitability are unknown.",
                        "reference": REFERENCE,
                    }
                )
    checks.append(
        {
            "id": "cookies",
            "name": "Cookie attributes",
            "status": "review"
            if any(f["id"].startswith("cookie-") for f in findings)
            else "pass"
            if cookies
            else "not_assessed",
        }
    )
    body_readable = html and successful and headers.get("content-encoding", "identity").lower() in ("identity", "")
    body = page.body.decode("utf-8", errors="replace") if body_readable else ""
    parser = Resources()
    if body:
        parser.feed(body)
    if secure and parser.insecure:
        findings.append(
            {
                "id": "mixed-content",
                "title": "HTTP resource references on an HTTPS page",
                "severity": "low",
                "classification": "configuration_review",
                "location": page.url,
                "evidence": "; ".join(parser.insecure),
                "impact": "Browsers may block or upgrade mixed resources; references alone do not demonstrate a data leak.",
                "recommendation": "Use HTTPS URLs for resources and form actions.",
                "verification": "Static HTML references only; scripts were not executed and resources were not fetched.",
                "reference": REFERENCE,
            }
        )
    markers = [
        (
            "private-key-marker",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "Private-key marker in page response",
            "high",
        ),
        (
            "debug-output",
            r"Traceback \(most recent call last\)|Fatal error:|Exception in thread",
            "Debug-error marker in page response",
            "medium",
        ),
    ]
    for key, pattern, title, severity in markers:
        match = re.search(pattern, body) if body else None
        if match:
            findings.append(
                {
                    "id": key,
                    "title": title,
                    "severity": severity,
                    "classification": "potential_exposure",
                    "location": page.url + " · HTML line " + str(body.count("\n", 0, match.start()) + 1),
                    "evidence": "A matching marker was observed. Raw response content and possible secret values are not retained.",
                    "impact": "Could be sensitive output or an intentional example. Authenticity and context must be verified privately.",
                    "recommendation": "Review the response. If a real private key was exposed, remove it and revoke/rotate it through your normal incident process. Disable detailed public error output where applicable.",
                    "verification": "Pattern match, not a confirmed credential leak.",
                    "reference": REFERENCE,
                }
            )
    checks.append(
        {
            "id": "body",
            "name": "Static HTML exposure markers",
            "status": "review"
            if any(f["classification"] == "potential_exposure" for f in findings)
            else "pass"
            if body_readable and not page.truncated
            else "not_assessed",
        }
    )
    return {
        "model_version": "web-0.2.0",
        "url": page.url,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "http_status": page.status,
        "scope": "One unauthenticated public page; up to three same-host redirects. No crawling, payloads, login, or exploitation.",
        "findings": findings,
        "checks": checks,
        "cookies": cookies,
        "redirects": page.redirects,
        "notes": page.notes,
        "coverage": {"body_inspected": body_readable, "body_truncated": page.truncated, "max_body_bytes": 512 * 1024},
        "summary": {s: sum(f["severity"] == s for f in findings) for s in ("high", "medium", "low", "info")},
        "limitations": [
            "No SQL injection, XSS exploitation, authorization testing, private data access, or internal attack graph is inferred.",
            "No findings does not mean secure. Authentication, business logic, dependencies, APIs and other pages remain untested.",
            "Query parameters and fragments are removed. Raw HTML and cookie values are not stored.",
            "Cross-host redirects require a separate authorized assessment. Body-dependent checks can be incomplete.",
        ],
    }
