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
  const testResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      /\/api\/notifications\/rules\/\d+\/test$/.test(
        new URL(response.url()).pathname,
      ),
  );
  await page
    .getByRole("button", { name: "Send test", exact: true })
    .first()
    .click();
  const testNote = await (await testResponse).json();
  const deliveryDeadline = Date.now() + 30000;
  let sent = false;
  while (Date.now() < deliveryDeadline && !sent) {
    const notes = await (
      await page.request.get(new URL("/api/notifications", page.url()).href)
    ).json();
    sent = notes.some(
      (note) => note.id === testNote.id && note.state === "SENT",
    );
    if (!sent) await page.waitForTimeout(250);
  }
  assert(sent, "The newly requested SMTP test was not SENT");
  await page.locator(".badge.sent").first().waitFor({ timeout: 10000 });
  await navigate("Targets");
  await page
    .getByRole("button", { name: "Acceptance lab", exact: true })
    .click();
  await page.getByRole("heading", { name: "Visible TCP services" }).waitFor();
  const targetList = await (
    await page.request.get(new URL("/api/targets", page.url()).href)
  ).json();
  const labId = targetList.find(
    (target) => target.name === "Acceptance lab",
  ).id;
  const targetRoute = "**/api/targets/" + labId;
  // API fixture represents an operator using critical=3, warning=30. The card
  // must honor the authoritative band rather than its old hardcoded 7-day cutoff.
  await page.route(targetRoute, async (route) => {
    const response = await route.fetch();
    const data = await response.json();
    data.certificates = data.certificates.map((certificate) => ({
      ...certificate,
      status: "WARNING",
    }));
    await route.fulfill({ response, json: data });
  });
  await page
    .locator(".tls-card .badge.warning")
    .first()
    .waitFor({ timeout: 10000 });
  await page.unroute(targetRoute);
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
  // Hold an actual HIGH response, complete a newer LOW request, then release HIGH.
  // The older refresh must not repaint the currently selected filter.
  await page.getByLabel("Severity").selectOption("LOW");
  await page
    .getByText(
      "No changes in this view. Events appear after a scan completes.",
      { exact: true },
    )
    .waitFor();
  let releaseOld;
  let observedOld;
  let finishedOld;
  const release = new Promise((resolve) => (releaseOld = resolve));
  const observed = new Promise((resolve) => (observedOld = resolve));
  const finished = new Promise((resolve) => (finishedOld = resolve));
  await page.route("**/api/events?**", async (route) => {
    if (
      new URL(route.request().url()).searchParams.get("severity") !== "HIGH"
    ) {
      await route.continue();
      return;
    }
    const response = await route.fetch();
    observedOld();
    await release;
    await route.fulfill({ response });
    finishedOld();
  });
  await page.getByLabel("Severity").selectOption("HIGH");
  await Promise.race([
    observed,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("No delayed HIGH request")), 10000),
    ),
  ]);
  const lowResponse = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return (
      url.pathname === "/api/events" &&
      url.searchParams.get("severity") === "LOW"
    );
  });
  await page.getByLabel("Severity").selectOption("LOW");
  await lowResponse;
  await page
    .getByText(
      "No changes in this view. Events appear after a scan completes.",
      { exact: true },
    )
    .waitFor();
  releaseOld();
  await finished;
  await page.waitForTimeout(250);
  assert.equal(
    await page
      .locator("tbody")
      .getByText("TLS CRITICAL", { exact: true })
      .count(),
    0,
    "An obsolete HIGH response replaced the active LOW filter",
  );
  await page.unroute("**/api/events?**");
  await navigate("Targets");
  await page.getByRole("button", { name: /Add target$/ }).click();
  await page.getByLabel("Display name").fill("Browser lifecycle");
  await page.getByLabel("Domain or IP address").fill("198.18.0.1");
  await page
    .getByLabel("I own this asset or have explicit permission to scan it.", {
      exact: true,
    })
    .check();
  const createdResponse = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === "/api/targets" &&
      response.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Save target", exact: true }).click();
  const created = await (await createdResponse).json();
  let row = page.locator("tbody tr").filter({
    has: page.getByRole("button", { name: "Browser lifecycle", exact: true }),
  });
  await row.getByRole("button", { name: "Scan", exact: true }).click();
  // Benchmark/private fixture IP is denied before Nmap; this exercises safe errors.
  await row.locator(".badge.scan-failed").waitFor({ timeout: 30000 });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByLabel("Display name").fill("Browser lifecycle edited");
  await page.getByLabel("Interval (minutes)").fill("10");
  await page
    .getByLabel("Enable scheduled monitoring", { exact: true })
    .uncheck();
  await page.getByRole("button", { name: "Save target", exact: true }).click();
  row = page.locator("tbody tr").filter({
    has: page.getByRole("button", {
      name: "Browser lifecycle edited",
      exact: true,
    }),
  });
  await row.locator(".badge.monitoring-disabled").waitFor();
  page.once("dialog", (dialog) => dialog.accept());
  await row.getByRole("button", { name: "Archive", exact: true }).click();
  await row.waitFor({ state: "detached" });
  await page.getByLabel("Show archived", { exact: true }).check();
  await page
    .getByRole("button", { name: "Browser lifecycle edited", exact: true })
    .waitFor();
  const preserved = await (
    await page.request.get(
      new URL("/api/scans?target_id=" + created.id, page.url()).href,
    )
  ).json();
  assert.equal(preserved.length, 1);
  assert.equal(preserved[0].state, "FAILED");
  await navigate("Scan history");
  await page
    .getByRole("button", { name: "Inspect snapshot" })
    .first()
    .waitFor();
  await navigate("Overview");
  await page.setViewportSize({ width: 390, height: 844 });
  for (const view of [
    "Targets",
    "Events",
    "Scan history",
    "Notifications",
    "Overview",
  ]) {
    await navigate(view);
    assert(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
      "Mobile document overflows: " + view,
    );
  }
  await navigate("Targets");
  await page.getByLabel("Show archived", { exact: true }).uncheck();
  await page
    .getByRole("button", { name: "Acceptance lab", exact: true })
    .waitFor();
  assert.deepEqual(errors, [], "Unexpected JavaScript errors");
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page
    .getByRole("heading", { name: "Sign in to SurfaceWatch" })
    .waitFor();
  assert.equal(
    (await page.request.get(new URL("/api/auth/me", page.url()).href)).status(),
    401,
  );
  let releaseOther;
  let observedOther;
  const otherRelease = new Promise((resolve) => (releaseOther = resolve));
  const otherObserved = new Promise((resolve) => (observedOther = resolve));
  await page.route("**/api/targets?archived=false", async (route) => {
    const response = await route.fetch();
    assert.deepEqual(
      await response.json(),
      [],
      "Other account should own no targets",
    );
    observedOther();
    await otherRelease;
    await route.fulfill({ response });
  });
  await page.getByLabel("Username").fill(credentials.other_username);
  await page.getByLabel("Password").fill(credentials.other_password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await otherObserved;
  await page
    .locator(".user")
    .getByText(credentials.other_username, { exact: true })
    .waitFor();
  assert.equal(
    await page
      .getByRole("button", { name: "Acceptance lab", exact: true })
      .count(),
    0,
    "New account rendered the previous owner's cached target while its refresh was pending",
  );
  otherRelease();
  await page.unroute("**/api/targets?archived=false");
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  console.log(
    "PASS browser: login, channel badges, new SMTP delivery, detail, configured TLS band, immutable snapshot, severity filter, stale-response race, create/scan/error/edit/disable/archive/history, mobile, logout, account isolation during delayed refresh",
  );
} finally {
  await browser.close();
}
