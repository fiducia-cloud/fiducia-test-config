// Small, framework-specific assertion helpers shared across the browser suites.
// Grouped here so specs stay terse; each spec imports only what its driver needs.

// --- Playwright ---------------------------------------------------------------

/** Wait until the first element containing `text` is visible (Playwright page). */
export async function assertVisibleText(page, text) {
  await page.getByText(text).first().waitFor({ state: "visible" });
}

// --- Puppeteer ----------------------------------------------------------------

/** Count elements matching `selector` (Puppeteer page). */
export async function disabledCount(page, selector) {
  return page.$$eval(selector, (nodes) => nodes.length);
}

/** Return the full document body text (Puppeteer page). */
export async function pageText(page) {
  return page.$eval("body", (body) => body.textContent ?? "");
}
