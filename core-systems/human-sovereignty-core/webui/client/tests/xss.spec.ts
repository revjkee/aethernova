// human-sovereignty-core/webui/client/tests/xss.spec.ts
//
// Industrial-grade XSS regression suite (Playwright).
//
// Goals:
// - Detect common DOM XSS / reflected XSS regressions in WebUI routes
// - Ensure no JS dialog execution (alert/confirm/prompt) is triggered
// - Ensure common sink APIs are not invoked with attacker-controlled payloads
//
// Non-goals:
// - Prove absence of XSS (tests can only detect what they cover)
// - Require knowledge of app-specific selectors
//
// Notes:
// - Uses Playwright test runner.
// - Assumes Playwright is configured with baseURL (recommended).
// - Does not make network calls beyond visiting the app under test.

import { test, expect, Page } from "@playwright/test";

type Vector = {
  name: string;
  payload: string;
};

const VECTORS: Vector[] = [
  {
    name: "basic-script-tag",
    payload: `<script>window.__XSS__='script-tag'</script>`,
  },
  {
    name: "img-onerror",
    payload: `<img src=x onerror="window.__XSS__='img-onerror'">`,
  },
  {
    name: "svg-onload",
    payload: `<svg onload="window.__XSS__='svg-onload'"></svg>`,
  },
  {
    name: "iframe-srcdoc",
    payload: `<iframe srcdoc="<script>window.__XSS__='iframe-srcdoc'</script>"></iframe>`,
  },
  {
    name: "javascript-url",
    payload: `<a href="javascript:window.__XSS__='js-url'">click</a>`,
  },
  {
    name: "style-expression-legacy",
    payload: `<div style="background-image:url(javascript:window.__XSS__='style-js-url')">x</div>`,
  },
  {
    name: "event-handler-attr",
    payload: `<div onclick="window.__XSS__='onclick'">x</div>`,
  },
  {
    name: "template-injection-like",
    payload: `{{constructor.constructor("window.__XSS__='tpl'")()}}`,
  },
  {
    name: "html-entity-encoded",
    payload: `&lt;img src=x onerror=&quot;window.__XSS__='entity'&quot;&gt;`,
  },
];

const ROUTES_UNDER_TEST: string[] = [
  "/",
  "/login",
  "/auth",
  "/dashboard",
];

const QUERY_PARAM_NAMES: string[] = ["q", "query", "search", "next", "redirect", "returnTo", "r"];

function encodeForQuery(value: string): string {
  return encodeURIComponent(value);
}

function buildUrl(route: string, params: Record<string, string>): string {
  const u = new URL(route, "http://localhost");
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  // Return path+query only; Playwright baseURL should resolve this.
  return u.pathname + u.search;
}

async function hardenPageGuards(page: Page): Promise<void> {
  // 1) Fail test immediately on JS dialog usage (common XSS signal).
  page.on("dialog", async (d) => {
    // Close to keep browser stable; fail after.
    await d.dismiss().catch(() => undefined);
    throw new Error(`Unexpected dialog triggered: ${d.type()} "${d.message()}"`);
  });

  // 2) Install runtime tripwires before any app script executes.
  await page.addInitScript(() => {
    // Marker that payload should try to set if executed.
    (window as any).__XSS__ = undefined;

    // Tripwire counters for dangerous sinks.
    const counters: Record<string, number> = {
      "eval": 0,
      "Function": 0,
      "setTimeout:string": 0,
      "setInterval:string": 0,
      "document.write": 0,
      "insertAdjacentHTML": 0,
      "innerHTML:set": 0,
    };

    // Expose read-only getter for assertions.
    Object.defineProperty(window, "__XSS_SINKS__", {
      configurable: false,
      enumerable: false,
      get() {
        return { ...counters };
      },
    });

    // Guard eval / Function
    const originalEval = window.eval;
    Object.defineProperty(window, "eval", {
      configurable: true,
      enumerable: false,
      value: function guardedEval(...args: any[]) {
        counters["eval"] += 1;
        return originalEval.apply(this, args as any);
      },
    });

    const OriginalFunction = Function;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (window as any).Function = function GuardedFunction(this: any, ...args: any[]) {
      counters["Function"] += 1;
      // @ts-expect-error - intentional dynamic constructor wrapping
      return new OriginalFunction(...args);
    } as any;

    // Guard setTimeout/setInterval string forms
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function guardedSetTimeout(handler: any, timeout?: number, ...args: any[]) {
      if (typeof handler === "string") counters["setTimeout:string"] += 1;
      return originalSetTimeout(handler as any, timeout as any, ...args);
    } as any;

    const originalSetInterval = window.setInterval;
    window.setInterval = function guardedSetInterval(handler: any, timeout?: number, ...args: any[]) {
      if (typeof handler === "string") counters["setInterval:string"] += 1;
      return originalSetInterval(handler as any, timeout as any, ...args);
    } as any;

    // Guard document.write
    const originalWrite = document.write.bind(document);
    document.write = function guardedWrite(...args: any[]) {
      counters["document.write"] += 1;
      return originalWrite(...(args as any));
    } as any;

    // Guard insertAdjacentHTML (very common DOM XSS sink)
    const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function guardedInsertAdjacentHTML(position: any, text: any) {
      counters["insertAdjacentHTML"] += 1;
      return originalInsertAdjacentHTML.call(this, position, text);
    };

    // Guard innerHTML assignments
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
    if (desc && typeof desc.set === "function") {
      Object.defineProperty(Element.prototype, "innerHTML", {
        configurable: true,
        enumerable: false,
        get: desc.get,
        set: function guardedInnerHTML(v: any) {
          counters["innerHTML:set"] += 1;
          return desc.set!.call(this, v);
        },
      });
    }
  });
}

async function assertNoXssExecution(page: Page): Promise<void> {
  // Ensure payload did not set global marker.
  const marker = await page.evaluate(() => (window as any).__XSS__);
  expect(marker, "XSS marker must not be set").toBeUndefined();

  // Ensure no JS dialog was triggered (handled by event listener above).

  // Ensure sink usage counters remain sane.
  const sinks = await page.evaluate(() => (window as any).__XSS_SINKS__);
  expect(sinks).toBeTruthy();

  // Some frameworks legitimately set innerHTML / insertAdjacentHTML during render.
  // Therefore we do NOT fail on non-zero counts for these by default.
  // We do fail on eval/Function and string timers which should not be used in hardened builds.
  expect(sinks["eval"], "eval must not be used").toBe(0);
  expect(sinks["Function"], "Function constructor must not be used").toBe(0);
  expect(sinks["setTimeout:string"], "setTimeout with string must not be used").toBe(0);
  expect(sinks["setInterval:string"], "setInterval with string must not be used").toBe(0);
}

async function gotoStable(page: Page, url: string): Promise<void> {
  // Avoid relying on specific network idle semantics (apps may use websockets).
  await page.goto(url, { waitUntil: "domcontentloaded" });
  // Give the app a brief deterministic settling window for client-side routing.
  await page.waitForTimeout(250);
}

test.describe("XSS regression", () => {
  test.beforeEach(async ({ page }) => {
    await hardenPageGuards(page);
  });

  test("baseline: no dialogs or XSS marker on home", async ({ page }) => {
    await gotoStable(page, "/");
    await assertNoXssExecution(page);
  });

  for (const route of ROUTES_UNDER_TEST) {
    for (const vector of VECTORS) {
      test(`route ${route} blocks vector ${vector.name}`, async ({ page }) => {
        // Attempt multiple common reflection parameters.
        const params: Record<string, string> = {};
        for (const k of QUERY_PARAM_NAMES) params[k] = vector.payload;

        const url = buildUrl(route, Object.fromEntries(Object.entries(params).map(([k, v]) => [k, encodeForQuery(v)])));

        await gotoStable(page, url);

        // Additional check: ensure attacker HTML is not present as raw DOM (best-effort).
        // Not a proof; it only detects obvious reflections.
        const html = await page.content();
        expect(html.includes(vector.payload), "raw payload should not be reflected verbatim in HTML").toBeFalsy();

        // Check for URL-based javascript: reflections (best-effort).
        const hasJavascriptHref = await page.evaluate(() => {
          const links = Array.from(document.querySelectorAll("a[href]")) as HTMLAnchorElement[];
          return links.some((a) => (a.getAttribute("href") || "").trim().toLowerCase().startsWith("javascript:"));
        });
        expect(hasJavascriptHref, "javascript: href must not appear in DOM").toBeFalsy();

        await assertNoXssExecution(page);
      });
    }
  }

  test("DOM XSS: fragment payload must not execute", async ({ page }) => {
    // Many apps parse location.hash; test common sink.
    const payload = `<img src=x onerror="window.__XSS__='hash'">`;
    const url = "/#x=" + encodeForQuery(payload);

    await gotoStable(page, url);
    await assertNoXssExecution(page);
  });

  test("DOM XSS: postMessage payload must not execute", async ({ page }) => {
    await gotoStable(page, "/");

    // Send attacker-controlled message and ensure it doesn't result in execution.
    await page.evaluate(() => {
      const payload = `<svg onload="window.__XSS__='pm'"></svg>`;
      window.postMessage({ type: "xss-test", payload }, "*");
      window.postMessage(payload, "*");
    });

    await page.waitForTimeout(250);
    await assertNoXssExecution(page);
  });

  test("CSP presence: page should define a CSP header or meta (best-effort)", async ({ page }) => {
    // This is best-effort because CSP may be set at server/proxy; Playwright can read response headers.
    const resp = await page.goto("/", { waitUntil: "domcontentloaded" });

    const headerCsp = resp?.headers()["content-security-policy"];
    const metaCsp = await page.locator('meta[http-equiv="Content-Security-Policy"]').count();

    // At least one of them should exist in hardened deployments.
    // If your deployment uses only headers, metaCsp may be 0.
    // If your deployment uses only meta, headerCsp may be undefined.
    expect(Boolean(headerCsp) || metaCsp > 0, "CSP header or meta must be present in hardened WebUI").toBeTruthy();

    await assertNoXssExecution(page);
  });
});
