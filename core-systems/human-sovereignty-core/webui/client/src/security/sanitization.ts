// path: human-sovereignty-core/webui/client/src/security/sanitization.ts

/* eslint-disable @typescript-eslint/no-explicit-any */

export type SanitizationMode = "strict" | "balanced";

export interface SanitizationPolicy {
  mode: SanitizationMode;

  // If true, and DOMPurify is not available, HTML input will be escaped (no HTML allowed).
  failClosed: boolean;

  // Allowed URL protocols. Anything else becomes empty string.
  allowedUrlProtocols: ReadonlyArray<string>;

  // Allow relative URLs like "/path", "./x", "../x", "#hash", "?q=1"
  allowRelativeUrls: boolean;

  // If true, allows "data:" only for images in a tightly scoped way.
  allowDataImages: boolean;

  // Maximum length guards (fail-closed trims to empty or to safe fallback).
  maxInputLength: number;
  maxUrlLength: number;

  // HTML allowlist (applied only if DOMPurify exists).
  allowedTags: ReadonlyArray<string>;
  allowedAttributes: ReadonlyArray<string>;

  // Additional forbidden tags/attrs even if allowed by upstream configs.
  forbiddenTags: ReadonlyArray<string>;
  forbiddenAttributes: ReadonlyArray<string>;

  // If true, removes all "style" attributes regardless of purifier.
  dropStyleAttribute: boolean;

  // If true, removes all event handlers "on*".
  dropEventHandlers: boolean;
}

export const DEFAULT_POLICY: SanitizationPolicy = Object.freeze({
  mode: "strict",
  failClosed: true,

  allowedUrlProtocols: ["http:", "https:"],
  allowRelativeUrls: true,
  allowDataImages: false,

  maxInputLength: 200_000,
  maxUrlLength: 8_192,

  allowedTags: [
    "b",
    "strong",
    "i",
    "em",
    "u",
    "s",
    "p",
    "br",
    "ul",
    "ol",
    "li",
    "blockquote",
    "code",
    "pre",
    "span",
    "div",
    "hr",
    "a",
  ],
  allowedAttributes: ["href", "title", "target", "rel", "class", "aria-label"],

  forbiddenTags: [
    "script",
    "style",
    "iframe",
    "object",
    "embed",
    "link",
    "meta",
    "base",
    "form",
    "input",
    "textarea",
    "button",
    "select",
    "option",
    "svg",
    "math",
    "video",
    "audio",
    "canvas",
  ],
  forbiddenAttributes: ["srcset", "srcdoc", "xlink:href", "xmlns"],

  dropStyleAttribute: true,
  dropEventHandlers: true,
});

type TrustedHtml = any;

declare global {
  interface Window {
    DOMPurify?: any;
    trustedTypes?: any;
  }
}

const TT_POLICY_NAME = "aethernova-sanitization";
let _trustedTypesPolicy: any | null = null;

function getTrustedTypesPolicy(): any | null {
  try {
    if (typeof window === "undefined") return null;
    const tt = window.trustedTypes;
    if (!tt || typeof tt.createPolicy !== "function") return null;
    if (_trustedTypesPolicy) return _trustedTypesPolicy;

    _trustedTypesPolicy = tt.createPolicy(TT_POLICY_NAME, {
      createHTML: (s: string) => s,
      createScriptURL: (s: string) => s,
      createScript: (s: string) => s,
    });

    return _trustedTypesPolicy;
  } catch {
    return null;
  }
}

function coerceString(input: unknown, maxLen: number): string {
  const s = typeof input === "string" ? input : input == null ? "" : String(input);
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen);
}

export function escapeHtmlText(input: unknown, policy: SanitizationPolicy = DEFAULT_POLICY): string {
  const s = coerceString(input, policy.maxInputLength);
  // Strict HTML escaping
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function sanitizeText(input: unknown, policy: SanitizationPolicy = DEFAULT_POLICY): string {
  // For plain text nodes, escape is safe and deterministic.
  return escapeHtmlText(input, policy);
}

function isLikelyRelativeUrl(u: string): boolean {
  if (!u) return false;
  const s = u.trim();
  if (!s) return false;
  return (
    s.startsWith("/") ||
    s.startsWith("./") ||
    s.startsWith("../") ||
    s.startsWith("?") ||
    s.startsWith("#")
  );
}

function isAllowedDataImage(u: string): boolean {
  // Allow only data:image/<safe>;base64,...  (no svg)
  const s = u.trim().toLowerCase();
  if (!s.startsWith("data:image/")) return false;
  if (s.startsWith("data:image/svg")) return false;
  // require base64 marker
  return s.includes(";base64,");
}

export function sanitizeUrl(input: unknown, policy: SanitizationPolicy = DEFAULT_POLICY): string {
  const raw = coerceString(input, policy.maxUrlLength).trim();
  if (!raw) return "";

  // prevent control chars and whitespace tricks
  const cleaned = raw.replace(/[\u0000-\u001F\u007F\s]+/g, "");
  if (!cleaned) return "";

  if (policy.allowRelativeUrls && isLikelyRelativeUrl(cleaned)) return cleaned;

  if (policy.allowDataImages && isAllowedDataImage(cleaned)) return cleaned;

  // parse absolute URL
  try {
    const url = new URL(cleaned);
    const proto = url.protocol.toLowerCase();
    if (!policy.allowedUrlProtocols.map((p) => p.toLowerCase()).includes(proto)) return "";
    return url.toString();
  } catch {
    return "";
  }
}

export function sanitizeAttrValue(input: unknown, policy: SanitizationPolicy = DEFAULT_POLICY): string {
  // Attribute-safe value (no HTML), for setting via DOM APIs.
  // We still remove control chars and trim.
  const s = coerceString(input, policy.maxInputLength)
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim();
  return s;
}

export function sanitizeCssValue(input: unknown, policy: SanitizationPolicy = DEFAULT_POLICY): string {
  // Strict minimal CSS sanitizer: allow a conservative subset of characters.
  // Reject url(), expression(), and other dangerous patterns.
  const s = coerceString(input, policy.maxInputLength).trim();
  if (!s) return "";

  const lower = s.toLowerCase();
  if (lower.includes("url(")) return "";
  if (lower.includes("expression(")) return "";
  if (lower.includes("@import")) return "";
  if (lower.includes("javascript:")) return "";

  // Allow only safe chars commonly used in CSS values.
  // letters, digits, spaces, punctuation used by colors/lengths/vars.
  const ok = /^[a-z0-9\s#(),.%\-+/*:_!"']+$/i.test(s);
  if (!ok) return "";
  return s;
}

function hasDomPurify(): boolean {
  return typeof window !== "undefined" && typeof window.DOMPurify !== "undefined";
}

function domPurifySanitizeHtml(html: string, policy: SanitizationPolicy): string {
  const DOMPurify = window.DOMPurify;
  if (!DOMPurify || typeof DOMPurify.sanitize !== "function") {
    if (policy.failClosed) return escapeHtmlText(html, policy);
    return "";
  }

  // Configure strict allowlist
  const cfg: any = {
    ALLOWED_TAGS: Array.from(new Set(policy.allowedTags)),
    ALLOWED_ATTR: Array.from(new Set(policy.allowedAttributes)),
    FORBID_TAGS: Array.from(new Set(policy.forbiddenTags)),
    FORBID_ATTR: Array.from(new Set(policy.forbiddenAttributes)),
    KEEP_CONTENT: true,
    RETURN_TRUSTED_TYPE: false,
  };

  const out = DOMPurify.sanitize(html, cfg) as string;

  // Post-process defense-in-depth
  // Remove event handlers and style attr aggressively
  const hardened = hardenSanitizedHtml(out, policy);

  return hardened;
}

function hardenSanitizedHtml(html: string, policy: SanitizationPolicy): string {
  // Use DOM parsing to remove attributes that can slip through depending on upstream versions.
  // If DOM parsing fails (non-browser env), fall back to string-level safe output.
  try {
    if (typeof document === "undefined") {
      return policy.failClosed ? escapeHtmlText(html, policy) : "";
    }

    const tpl = document.createElement("template");
    tpl.innerHTML = html;

    const treeWalker = document.createTreeWalker(tpl.content, NodeFilter.SHOW_ELEMENT);
    let node = treeWalker.currentNode as Element | null;

    while (node) {
      const el = node as Element;

      // Drop all on* handlers
      if (policy.dropEventHandlers) {
        for (const attr of Array.from(el.attributes)) {
          if (attr.name.toLowerCase().startsWith("on")) {
            el.removeAttribute(attr.name);
          }
        }
      }

      // Drop style attribute
      if (policy.dropStyleAttribute) {
        el.removeAttribute("style");
      }

      // Harden anchor tags: sanitize href, set rel if target=_blank
      const tag = el.tagName.toLowerCase();
      if (tag === "a") {
        const href = el.getAttribute("href");
        if (href != null) {
          const safeHref = sanitizeUrl(href, policy);
          if (!safeHref) el.removeAttribute("href");
          else el.setAttribute("href", safeHref);
        }

        const target = (el.getAttribute("target") || "").toLowerCase();
        if (target === "_blank") {
          const rel = (el.getAttribute("rel") || "").toLowerCase();
          const needed = ["noopener", "noreferrer"];
          const relParts = new Set(rel.split(/\s+/).filter(Boolean));
          for (const x of needed) relParts.add(x);
          el.setAttribute("rel", Array.from(relParts).join(" "));
        }
      }

      node = treeWalker.nextNode() as Element | null;
    }

    return tpl.innerHTML;
  } catch {
    return policy.failClosed ? escapeHtmlText(html, policy) : "";
  }
}

export function sanitizeHtml(input: unknown, policy: SanitizationPolicy = DEFAULT_POLICY): string {
  const html = coerceString(input, policy.maxInputLength);

  if (!html) return "";

  if (!hasDomPurify()) {
    // Fail-closed: do not allow HTML if sanitizer dependency is missing
    return policy.failClosed ? escapeHtmlText(html, policy) : "";
  }

  const sanitized = domPurifySanitizeHtml(html, policy);

  // Additional strict-mode fallback: if sanitizer produced empty and input was non-empty, keep as escaped text.
  if (policy.mode === "strict" && !sanitized && html) {
    return policy.failClosed ? escapeHtmlText(html, policy) : "";
  }

  return sanitized;
}

export function sanitizeHtmlTrusted(input: unknown, policy: SanitizationPolicy = DEFAULT_POLICY): TrustedHtml {
  const sanitized = sanitizeHtml(input, policy);
  const tt = getTrustedTypesPolicy();
  if (tt && typeof tt.createHTML === "function") {
    try {
      return tt.createHTML(sanitized);
    } catch {
      return sanitized as any;
    }
  }
  return sanitized as any;
}

export function sanitizeJsonForDisplay(input: unknown, policy: SanitizationPolicy = DEFAULT_POLICY): string {
  try {
    const s = JSON.stringify(input, null, 2);
    return sanitizeText(s, policy);
  } catch {
    return sanitizeText(String(input ?? ""), policy);
  }
}

export function safeLinkProps(
  href: unknown,
  policy: SanitizationPolicy = DEFAULT_POLICY
): { href?: string; rel?: string } {
  const safeHref = sanitizeUrl(href, policy);
  if (!safeHref) return {};
  // defense: ensure external links do not get opener access
  return { href: safeHref, rel: "noopener noreferrer" };
}

export function isSanitizerAvailable(): boolean {
  return hasDomPurify();
}
