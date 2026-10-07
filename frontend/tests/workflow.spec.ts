import { test, expect } from "@playwright/test";
test("demo evidence, graph, counterfactuals and grounded explanation", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await page.getByRole("button", { name: "Launch demo", exact: true }).click();
  await expect(
    page.getByText("Prioritized findings", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Risk Graph", exact: true }).click();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  await page.getByRole("button", { name: "Findings", exact: true }).click();
  await page.getByRole("button", { name: "Explain F-01", exact: true }).click();
  await expect(
    page.getByText("Source evidence", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Simulate patch", exact: true })
    .click();
  await expect(
    page.getByText("Simulation results", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Remediation", exact: true }).click();
  await page
    .getByRole("button", { name: "Simulate combined plan", exact: true })
    .click();
  await expect(
    page.getByText("Simulation results", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: /CYVRA AI/ }).click();
  await page.getByRole("button", { name: "Ask CYVRA", exact: true }).click();
  await expect(
    page.getByText("STRUCTURED CITATIONS", { exact: true }),
  ).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Overview", exact: true }).click();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    ),
  ).toBe(false);
  const original = await page.getByLabel("Select environment").inputValue();
  const newResponse = await page.request.post("/api/projects", {
    data: { name: "Initially empty environment" },
  });
  const fresh = await newResponse.json();
  await page.reload();
  await page.getByRole("button", { name: "Overview", exact: true }).click();
  await expect(
    page.getByRole("option", { name: "Initially empty environment" }),
  ).toBeAttached();
  await page.getByLabel("Select environment").selectOption(fresh.id);
  await page
    .getByRole("button", { name: "Load synthetic dataset", exact: true })
    .click();
  await expect(
    page.getByText("Prioritized findings", { exact: true }),
  ).toBeVisible();
  await page.getByLabel("Select environment").selectOption(original);
  await expect(
    page.getByText("Prioritized findings", { exact: true }),
  ).toBeVisible();
  await page.getByLabel("Select environment").selectOption(fresh.id);
  await expect(
    page.getByText("Prioritized findings", { exact: true }),
  ).toBeVisible();
  expect(errors).toEqual([]);
});
