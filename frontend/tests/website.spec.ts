import { test, expect } from "@playwright/test";
const report = {
  id: "11111111-1111-1111-1111-111111111111",
  url: "https://example.com/",
  created_at: "2026-10-07T12:00:00Z",
  http_status: 200,
  scope: "One unauthenticated public page; no crawling or exploitation.",
  summary: { high: 0, medium: 0, low: 1, info: 0 },
  findings: [
    {
      id: "csp",
      title: "Content Security Policy header",
      severity: "low",
      classification: "configuration_gap",
      location: "https://example.com/",
      evidence: "No enforcing CSP response header was observed.",
      impact: "An absent defense-in-depth control does not prove XSS.",
      recommendation: "Develop and test an application-specific CSP.",
      verification: "Observed configuration; exploitability not verified.",
      reference:
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    },
  ],
  checks: [
    { id: "transport", name: "HTTPS transport", status: "pass" },
    { id: "csp", name: "Content Security Policy header", status: "review" },
    { id: "cookies", name: "Cookie attributes", status: "not_assessed" },
  ],
  cookies: [],
  redirects: [],
  notes: [],
  coverage: { body_inspected: true, body_truncated: false },
  limitations: ["Other pages and authenticated content remain untested."],
};
test("website report details, export, saved history and responsive dark layout", async ({
  page,
}) => {
  // Deterministic UI fixture, never requests a third-party website.
  let saved = false;
  await page.route("**/api/web/assessments**", async (route) => {
    const req = route.request();
    const detail = new URL(req.url()).pathname.endsWith(report.id);
    if (req.method() === "POST") {
      expect(req.postDataJSON()).toEqual({
        url: "https://example.com",
        authorized: true,
      });
      saved = true;
    }
    await route.fulfill({
      status: req.method() === "POST" ? 201 : 200,
      json: req.method() === "POST" || detail ? report : saved ? [report] : [],
    });
  });
  await page.goto("/");
  await expect(
    page.getByRole("img", { name: "CYVRA", exact: true }),
  ).toBeVisible();
  await expect
    .poll(async () =>
      page
        .getByRole("img", { name: "CYVRA", exact: true })
        .evaluate((e: HTMLImageElement) => e.complete && e.naturalWidth > 0),
    )
    .toBe(true);
  await page.screenshot({
    path: "test-results/website-desktop.png",
    fullPage: true,
  });
  await page.getByLabel("Website URL").fill("https://example.com");
  await expect(
    page.getByRole("button", { name: "Check website", exact: true }),
  ).toBeDisabled();
  await page.getByRole("checkbox").check();
  await page
    .getByRole("button", { name: "Check website", exact: true })
    .click();
  await expect(page.getByText("Saved report", { exact: false })).toBeVisible();
  await page
    .getByRole("button", { name: /Content Security Policy header/ })
    .click();
  await expect(
    page.getByText("No enforcing CSP response header was observed.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByText("Develop and test an application-specific CSP.", {
      exact: true,
    }),
  ).toBeVisible();
  const download = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export report", exact: true })
    .click();
  expect((await download).suggestedFilename()).toMatch(/\.json$/);
  await page.screenshot({
    path: "test-results/website-report.png",
    fullPage: true,
  });
  await page.reload();
  await page.locator(".saved-report").click();
  await expect(
    page.getByText("WEBSITE ASSESSMENT", { exact: true }),
  ).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    ),
  ).toBe(false);
  await page.screenshot({
    path: "test-results/website-mobile.png",
    fullPage: true,
  });
});

test("real API rejects private targets through frontend proxy", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByLabel("Website URL").fill("http://127.0.0.1");
  await page.getByRole("checkbox").check();
  await page
    .getByRole("button", { name: "Check website", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText(
    "local/private targets are blocked",
  );
});
