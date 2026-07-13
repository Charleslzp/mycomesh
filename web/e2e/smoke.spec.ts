import { expect, test, type Page } from "@playwright/test";

async function expectNoHorizontalOverflow(page: Page) {
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth + 1);
}

test("homepage renders the protocol experience", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { level: 1, name: "MycoMesh" })).toBeVisible();
  await expect(page.getByRole("link", { name: /Launch testnet/i })).toBeVisible();
  await expect(page.getByRole("link", { name: /Create API access/i })).toHaveAttribute("href", "/app/access");
  await expect(page.locator("main#main-content")).toBeVisible();
  await expect(page.locator("canvas")).toBeVisible();

  const canvasHasPixels = await page.locator("canvas").evaluate((canvas: HTMLCanvasElement) => {
    const context = canvas.getContext("2d");
    if (!context || canvas.width === 0 || canvas.height === 0) return false;
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
    for (let index = 3; index < pixels.length; index += 4) {
      if (pixels[index] > 0) return true;
    }
    return false;
  });
  expect(canvasHasPixels).toBe(true);
  await expectNoHorizontalOverflow(page);
});

test("application fails closed without a V3 deployment", async ({ page }) => {
  await page.goto("/app");

  await expect(page.getByRole("heading", { level: 1, name: "Protocol overview" })).toBeVisible();
  await expect(page.getByText("V3 deployment is not configured")).toBeVisible();
  await expect(page.getByRole("button", { name: "Connect wallet" })).toBeVisible();
  await expect(page.locator("main#main-content")).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("mobile homepage navigation is keyboard dismissible", async ({ page, isMobile }) => {
  test.skip(!isMobile, "Mobile navigation behavior");
  await page.goto("/");

  const trigger = page.getByRole("button", { name: "Open navigation" });
  await trigger.click();
  await expect(page.getByRole("dialog", { name: "Navigation menu" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: "Navigation menu" })).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("mobile navigation exposes every workspace", async ({ page, isMobile }) => {
  test.skip(!isMobile, "Mobile navigation behavior");
  await page.goto("/app");

  const more = page.getByRole("button", { name: "More" });
  await more.click();
  const menu = page.locator("#mobile-more-navigation");
  await expect(menu.getByRole("link", { name: "Access" })).toBeVisible();
  await expect(menu.getByRole("link", { name: "Funds" })).toBeVisible();
  await expect(menu.getByRole("link", { name: "Contracts" })).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(menu).toBeHidden();
});
