import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { chromium } from "playwright";

const credentials = JSON.parse(
  await readFile(process.env.SW_ACCEPTANCE_CREDENTIALS, "utf8"),
);
const browser = await chromium.launch({
  headless: true,
  ...(process.env.SW_CHROMIUM_PATH
    ? { executablePath: process.env.SW_CHROMIUM_PATH }
    : {}),
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(process.env.SW_APP_URL || "http://localhost:8080");
  await page.getByLabel("Username").fill(credentials.username);
  await page.getByLabel("Password").fill(credentials.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  const navigate = (name) =>
    page
      .locator("nav")
      .getByRole("button", { name: new RegExp(name) })
      .click();
  await navigate("Notifications");
  const smtp = page
    .locator(".channel-status > span")
    .filter({ hasText: "SMTP" });
  await smtp.locator(".badge.configured").waitFor();
  assert.equal((await smtp.innerText()).trim(), "SMTP CONFIGURED");
  for (const name of ["TELEGRAM", "DISCORD"]) {
    assert.match(
      await page
        .locator(".channel-status > span")
        .filter({ hasText: name })
        .innerText(),
      /NOT CONFIGURED/,
    );
  }
  await page
    .getByRole("button", { name: "Send test", exact: true })
    .first()
    .click();
  await page.locator(".badge.sent").first().waitFor({ timeout: 30000 });
  await navigate("Targets");
  await page
    .getByRole("button", { name: "Acceptance lab", exact: true })
    .click();
  await page.getByRole("heading", { name: "Visible TCP services" }).waitFor();
  await page.getByRole("button", { name: "Inspect snapshot" }).first().click();
  const modal = page.getByRole("dialog");
  await modal.waitFor();
  assert.match(await modal.locator("pre").innerText(), /"state": "SUCCESS"/);
  await page.keyboard.press("Escape");
  await navigate("Events");
  await page.getByLabel("Severity").selectOption("HIGH");
  await page
    .locator("tbody")
    .getByText("TLS CRITICAL", { exact: true })
    .first()
    .waitFor();
  await navigate("Scan history");
  await page
    .getByRole("button", { name: "Inspect snapshot" })
    .first()
    .waitFor();
  await navigate("Overview");
  await page.setViewportSize({ width: 390, height: 844 });
  assert(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
    "Mobile document overflows",
  );
  assert.deepEqual(errors, [], "Unexpected JavaScript errors");
  console.log(
    "PASS browser: login, channel badges, SMTP test, detail, immutable snapshot, severity filter, history, mobile",
  );
} finally {
  await browser.close();
}
