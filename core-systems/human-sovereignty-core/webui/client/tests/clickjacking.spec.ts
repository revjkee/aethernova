import { test, expect, APIResponse } from "@playwright/test";

type SecurityHeaders = {
  xFrameOptions?: string;
  contentSecurityPolicy?: string;
};

function getBaseUrl(): string {
  const base =
    process.env.WEBUI_BASE_URL ||
    process.env.PLAYWRIGHT_BASE_URL ||
    process.env.BASE_URL ||
    "";
  if (!base || !base.trim()) {
    throw new Error(
      "WEBUI_BASE_URL (or PLAYWRIGHT_BASE_URL/BASE_URL) must be set to the WebUI origin, e.g. https://webui.example.com"
    );
  }
  return base.replace(/\/+$/, "");
}

function normalizeHeaderValue(v: string | null): string {
  return (v || "").trim();
}

function parseFrameAncestors(csp: string): string[] {
  const normalized = csp
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean);

  const fa = normalized.find((d) => d.toLowerCase().startsWith("frame-ancestors "));
  if (!fa) return [];

  const parts = fa.split(/\s+/).slice(1);
  return parts.map((p) => p.trim()).filter(Boolean);
}

function isXfoProtective(xfo: string): boolean {
  const v = xfo.trim().toLowerCase();
  return v === "deny" || v === "sameorigin";
}

function isFrameAncestorsProtective(ancestors: string[]): boolean {
  if (!ancestors.length) return false;

  const normalized = ancestors.map((a) => a.toLowerCase());

  // Strongest: frame-ancestors 'none'
  if (normalized.includes("'none'")) return true;

  // Acceptable: frame-ancestors 'self' (still prevents cross-origin framing)
  if (normalized.includes("'self'")) return true;

  // Some deployments may use explicit allowlist; this is not inherently unsafe,
  // but it changes the threat model. We treat allowlists as "not protective enough"
  // unless they include only 'self' or 'none'.
  return false;
}

async function fetchHeaders(response: APIResponse): Promise<SecurityHeaders> {
  const headers = response.headers();
  const xfo = normalizeHeaderValue(headers["x-frame-options"] || null);
  const csp = normalizeHeaderValue(headers["content-security-policy"] || null);
  return {
    xFrameOptions: xfo || undefined,
    contentSecurityPolicy: csp || undefined,
  };
}

test.describe("Clickjacking protection", () => {
  test("must send anti-framing headers (X-Frame-Options and CSP frame-ancestors)", async ({
    request,
  }) => {
    const baseUrl = getBaseUrl();
    const url = `${baseUrl}/`;

    const res = await request.get(url, {
      failOnStatusCode: false,
      headers: {
        "cache-control": "no-cache",
      },
    });

    expect(
      res.ok(),
      `Expected HTTP 2xx/3xx from ${url}, got ${res.status()}`
    ).toBeTruthy();

    const { xFrameOptions, contentSecurityPolicy } = await fetchHeaders(res);

    expect(
      xFrameOptions,
      "Missing X-Frame-Options header. Expected DENY or SAMEORIGIN."
    ).toBeTruthy();

    expect(
      isXfoProtective(xFrameOptions || ""),
      `X-Frame-Options must be DENY or SAMEORIGIN, got: ${xFrameOptions}`
    ).toBeTruthy();

    expect(
      contentSecurityPolicy,
      "Missing Content-Security-Policy header. Expected to include frame-ancestors."
    ).toBeTruthy();

    const ancestors = parseFrameAncestors(contentSecurityPolicy || "");
    expect(
      ancestors.length > 0,
      `CSP must include frame-ancestors directive. Got CSP: ${contentSecurityPolicy}`
    ).toBeTruthy();

    expect(
      isFrameAncestorsProtective(ancestors),
      `CSP frame-ancestors must be 'none' or 'self'. Got: ${ancestors.join(" ")}`
    ).toBeTruthy();
  });

  test("must not render inside an iframe (behavioral)", async ({ page }) => {
    const baseUrl = getBaseUrl();
    const targetUrl = `${baseUrl}/`;

    // Create an attacker-like wrapper page and attempt to iframe the WebUI.
    // If anti-framing is effective, the iframe will not get a navigated frame to targetUrl.
    await page.setContent(
      `<!doctype html>
<html>
  <head><meta charset="utf-8"><title>frame-test</title></head>
  <body>
    <iframe id="victim" src="${targetUrl}" style="width:900px;height:700px;"></iframe>
  </body>
</html>`,
      { waitUntil: "domcontentloaded" }
    );

    // Give the browser time to attempt navigation.
    await page.waitForTimeout(1500);

    // In Playwright, if framing is blocked, there should be no child frame with the target origin URL.
    const frames = page.frames().map((f) => f.url());
    const hasVictimFrame = frames.some((u) => {
      try {
        return new URL(u).origin === new URL(targetUrl).origin;
      } catch {
        return false;
      }
    });

    expect(
      hasVictimFrame,
      `WebUI must not be embeddable in an iframe. Detected framed origin among frames: ${frames.join(", ")}`
    ).toBeFalsy();
  });
});
