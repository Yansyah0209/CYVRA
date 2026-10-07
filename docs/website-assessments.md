# Website assessments

Website Check accepts an HTTP/HTTPS URL for a website you own or are authorized to assess. It retrieves one unauthenticated public response, evaluates observable configuration and exposure markers, and saves an immutable report. It does not require an AI API key. The supplied logo and dark dashboard are bundled with the application.

## What a report means

Each finding includes the inspected page URL, observed evidence, priority, classification, potential impact, recommended action and a verification caveat. Configuration gaps are not automatically vulnerabilities. Private-key and debug markers are potential exposures, not validated credential leaks: documentation may legitimately contain examples. Missing findings are not proof of security.

Checks include HTTPS transport, positive HSTS max-age, presence of an enforcing CSP header, framing restrictions, nosniff, explicit referrer policy, technology headers, attributes of cookies issued by the response, static HTTP resource references in HTTPS HTML, and selected private-key/debug markers in HTML. A header's presence does not validate its entire policy. CSP meta tags, client-side JavaScript, authenticated content, other pages, source code, SQL injection, authorization flaws, dependency vulnerabilities and exploitability are not assessed.

The UI distinguishes pass, review and not assessed. Saved reports can be reopened and exported as JSON. A website report does not manufacture an internal asset graph from a URL; the evidence-import workflow remains available separately.

## Request boundaries

- Only HTTP port 80 and HTTPS port 443; no credentials in URLs. Query strings and fragments are removed before requests and storage. Path components remain, so avoid URLs containing secrets in the path.
- All DNS addresses must be public. Private, loopback, link-local, multicast and IPv6 transition targets are rejected. Connections pin a validated numeric address while preserving the original hostname for Host, TLS SNI and certificate verification. Each redirect is resolved and checked again.
- At most three same-host redirects; HTTPS downgrades and cross-host redirects are recorded without following them. Redirect destinations need a separate authorized assessment.
- One GET per hop; no crawling, payloads, authentication, cookie replay, exploitation or background scans. GET can have side effects on poorly designed applications; choose an appropriate public page.
- 512 KiB response body, 64 KiB response headers, eight-second operation timeout and 25-second assessment budget. DNS workers and concurrent assessments are capped at two. The in-process start limit is ten per minute; it is not a distributed customer quota.
- Normal TLS certificate validation. An invalid certificate produces an assessment error instead of bypassing validation. Compressed responses are not decompressed; unsupported encodings and non-HTML bodies are marked outside body inspection.
- Raw HTML and cookie values are not saved. Cookie names/flags, selected banner headers, page URLs and observations are saved in the local database. Treat saved reports as project data.

These controls reduce SSRF exposure; outbound network isolation and an independent review are still required for any public service. See the [OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) and [HTTP header guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

## Running and deployment

The shipped setup is ready for a trusted local developer workspace with Docker Desktop. On Windows, double-click `start.cmd`; it creates `.env` only if absent, starts/builds containers and opens the browser when ready. Existing database volumes are retained. Update the checkout before launching when new changes are available.

It is not a hosted multi-tenant customer product. Public launch still requires user authentication, tenant/report isolation, a job queue with distributed quotas, enforced outbound network rules, security review, backup/retention policies, monitoring and an HTTPS deployment. The optional backend key does not authenticate customers at the frontend proxy.
