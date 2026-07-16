// human-sovereignty-core/webui/client/src/security/safe_markdown.ts

export type SafeMarkdownMode = "strict" | "balanced";

export interface SafeMarkdownOptions {
  mode?: SafeMarkdownMode;

  // Hard limits
  maxInputChars?: number;
  maxOutputChars?: number;

  // Link handling
  allowRelativeLinks?: boolean;
  allowMailto?: boolean;
  allowTel?: boolean;
  allowHttp?: boolean;
  allowHttps?: boolean;

  // Rendering behavior
  preserveLineBreaks?: boolean;
  openLinksInNewTab?: boolean;

  // Extra allowed tags (still sanitized)
  extraAllowedTags?: readonly string[];
}

export interface SafeMarkdownResult {
  ok: boolean;
  html: string;
  text: string;
  warnings: string[];
  meta: {
    inputChars: number;
    outputChars: number;
    mode: SafeMarkdownMode;
  };
}

const DEFAULTS: Required<SafeMarkdownOptions> = {
  mode: "strict",
  maxInputChars: 40_000,
  maxOutputChars: 120_000,

  allowRelativeLinks: true,
  allowMailto: true,
  allowTel: false,
  allowHttp: false,
  allowHttps: true,

  preserveLineBreaks: true,
  openLinksInNewTab: true,

  extraAllowedTags: [],
};

const ALLOWED_TAGS_STRICT = new Set([
  "p",
  "br",
  "pre",
  "code",
  "blockquote",
  "strong",
  "em",
  "b",
  "i",
  "hr",
  "ul",
  "ol",
  "li",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "a",
]);

const ALLOWED_TAGS_BALANCED = new Set([
  ...Array.from(ALLOWED_TAGS_STRICT),
  "table",
  "thead",
  "tbody",
  "tr",
  "th",
  "td",
]);

const ALLOWED_ATTRS_BY_TAG: Record<string, Set<string>> = {
  a: new Set(["href", "title", "rel", "target"]),
  code: new Set(["class"]),
  pre: new Set(["class"]),
  th: new Set(["colspan", "rowspan"]),
  td: new Set(["colspan", "rowspan"]),
};

const GLOBAL_DENY_ATTR_PREFIXES = ["on"]; // onclick, onerror, etc.
const DENY_ATTRS = new Set(["style", "srcset", "srcdoc", "formaction"]);

const SAFE_LANG_RE = /^[a-z0-9_+-]{1,24}$/i;

function mergeOptions(opts?: SafeMarkdownOptions): Required<SafeMarkdownOptions> {
  return {
    ...DEFAULTS,
    ...(opts || {}),
    extraAllowedTags: (opts?.extraAllowedTags || []).filter(Boolean),
  };
}

function normalizeInput(input: string, maxChars: number): { value: string; truncated: boolean } {
  const s = (input ?? "").toString().replace(/\u0000/g, "");
  if (s.length <= maxChars) return { value: s, truncated: false };
  return { value: s.slice(0, maxChars), truncated: true };
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function stripControlChars(s: string): string {
  // Remove most control chars except LF/CR/TAB
  return s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
}

function isLikelyUrl(s: string): boolean {
  return /^(https?:\/\/|mailto:|tel:|\/|\.\/|\.\.\/|#)/i.test(s.trim());
}

function sanitizeUrl(raw: string, o: Required<SafeMarkdownOptions>): string | null {
  const url = stripControlChars(raw || "").trim();

  if (!url) return null;

  // Block common obfuscations
  const lowered = url.replace(/\s+/g, "").toLowerCase();
  if (lowered.startsWith("javascript:")) return null;
  if (lowered.startsWith("data:")) return null;
  if (lowered.startsWith("vbscript:")) return null;
  if (lowered.startsWith("file:")) return null;

  // Allow anchors
  if (lowered.startsWith("#")) return url;

  // Relative URLs
  if (lowered.startsWith("/") || lowered.startsWith("./") || lowered.startsWith("../")) {
    return o.allowRelativeLinks ? url : null;
  }

  if (lowered.startsWith("mailto:")) return o.allowMailto ? url : null;
  if (lowered.startsWith("tel:")) return o.allowTel ? url : null;

  if (lowered.startsWith("https://")) return o.allowHttps ? url : null;
  if (lowered.startsWith("http://")) return o.allowHttp ? url : null;

  // Bare domain or other scheme not allowed
  return null;
}

function safeRel(openInNewTab: boolean): string {
  // Prevent reverse tabnabbing and leaking opener
  return openInNewTab ? "noopener noreferrer" : "noreferrer";
}

function clampOutput(html: string, maxChars: number): { value: string; truncated: boolean } {
  if (html.length <= maxChars) return { value: html, truncated: false };
  return { value: html.slice(0, maxChars), truncated: true };
}

function parseFencedCodeBlocks(md: string): Array<{ type: "code"; lang: string | null; content: string } | { type: "text"; content: string }> {
  const parts: Array<{ type: "code"; lang: string | null; content: string } | { type: "text"; content: string }> = [];
  const re = /```([^\n`]*)\n([\s\S]*?)\n```/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(md)) !== null) {
    const start = m.index;
    const end = re.lastIndex;
    if (start > last) parts.push({ type: "text", content: md.slice(last, start) });

    const rawLang = (m[1] || "").trim();
    const lang = SAFE_LANG_RE.test(rawLang) ? rawLang.toLowerCase() : null;
    parts.push({ type: "code", lang, content: m[2] || "" });

    last = end;
  }
  if (last < md.length) parts.push({ type: "text", content: md.slice(last) });
  return parts;
}

function renderInlineMarkdown(text: string, o: Required<SafeMarkdownOptions>): string {
  // Start from escaped text to ensure raw HTML is never interpreted.
  let s = escapeHtml(text);

  // Inline code: `code`
  s = s.replace(/`([^`]+)`/g, (_m, code) => `<code>${escapeHtml(code)}</code>`);

  // Bold: **text**
  s = s.replace(/\*\*([^\*]+)\*\*/g, (_m, inner) => `<strong>${inner}</strong>`);

  // Italic: *text*
  s = s.replace(/\*([^*\n]+)\*/g, (_m, inner) => `<em>${inner}</em>`);

  // Links: [text](url)
  s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, label, rawUrl) => {
    const safe = sanitizeUrl(rawUrl, o);
    const safeLabel = label;
    if (!safe) return safeLabel; // drop link, keep text
    const target = o.openLinksInNewTab ? ` target="_blank"` : "";
    const rel = ` rel="${escapeHtml(safeRel(o.openLinksInNewTab))}"`;
    return `<a href="${escapeHtml(safe)}"${target}${rel}>${safeLabel}</a>`;
  });

  // Autolinks (very conservative): only if it looks like url with scheme/relative/anchor
  s = s.replace(/(^|[\s(])((https?:\/\/|mailto:|tel:|\/|\.\/|\.\.\/|#)[^\s<>"')\]]+)/g, (m, prefix, url) => {
    const safe = sanitizeUrl(url, o);
    if (!safe) return m;
    const target = o.openLinksInNewTab ? ` target="_blank"` : "";
    const rel = ` rel="${escapeHtml(safeRel(o.openLinksInNewTab))}"`;
    return `${prefix}<a href="${escapeHtml(safe)}"${target}${rel}>${escapeHtml(url)}</a>`;
  });

  return s;
}

function renderBlockMarkdown(md: string, o: Required<SafeMarkdownOptions>): string {
  const src = stripControlChars(md);

  // Headings
  const lines = src.split(/\r?\n/);
  const out: string[] = [];

  let inUl = false;
  let inOl = false;
  let inBlockquote = false;

  const closeLists = () => {
    if (inUl) {
      out.push("</ul>");
      inUl = false;
    }
    if (inOl) {
      out.push("</ol>");
      inOl = false;
    }
  };

  const closeBlockquote = () => {
    if (inBlockquote) {
      out.push("</blockquote>");
      inBlockquote = false;
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const line = raw.replace(/\t/g, "    ");

    // Horizontal rule
    if (/^\s*([-*_])\1\1+\s*$/.test(line)) {
      closeLists();
      closeBlockquote();
      out.push("<hr />");
      continue;
    }

    // Blockquote
    const bq = /^\s*>\s?(.*)$/.exec(line);
    if (bq) {
      closeLists();
      if (!inBlockquote) {
        out.push("<blockquote>");
        inBlockquote = true;
      }
      const content = renderInlineMarkdown(bq[1] || "", o);
      out.push(`<p>${content}</p>`);
      continue;
    } else {
      closeBlockquote();
    }

    // Ordered list
    const ol = /^\s*\d+\.\s+(.*)$/.exec(line);
    if (ol) {
      if (!inOl) {
        closeLists();
        out.push("<ol>");
        inOl = true;
      }
      const content = renderInlineMarkdown(ol[1] || "", o);
      out.push(`<li>${content}</li>`);
      continue;
    }

    // Unordered list
    const ul = /^\s*[-*]\s+(.*)$/.exec(line);
    if (ul) {
      if (!inUl) {
        closeLists();
        out.push("<ul>");
        inUl = true;
      }
      const content = renderInlineMarkdown(ul[1] || "", o);
      out.push(`<li>${content}</li>`);
      continue;
    }

    // Empty line
    if (!line.trim()) {
      closeLists();
      if (o.preserveLineBreaks) out.push("<br />");
      continue;
    }

    // Heading (limit to h6)
    const h = /^\s*(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      closeLists();
      const level = Math.min(6, Math.max(1, h[1].length));
      const content = renderInlineMarkdown(h[2] || "", o);
      out.push(`<h${level}>${content}</h${level}>`);
      continue;
    }

    // Paragraph
    closeLists();
    const content = renderInlineMarkdown(line, o);
    out.push(`<p>${content}</p>`);
  }

  closeLists();
  closeBlockquote();

  return out.join("\n");
}

function sanitizeHtml(html: string, o: Required<SafeMarkdownOptions>): string {
  // Browser-only sanitizer using DOMParser allowlist.
  // If DOMParser is unavailable, return escaped text.
  if (typeof window === "undefined" || typeof DOMParser === "undefined") {
    return escapeHtml(html);
  }

  const allowed = new Set<string>(
    (o.mode === "balanced" ? Array.from(ALLOWED_TAGS_BALANCED) : Array.from(ALLOWED_TAGS_STRICT)).concat(
      (o.extraAllowedTags || []).map((t) => (t || "").toLowerCase().trim()).filter(Boolean),
    ),
  );

  const parser = new DOMParser();
  const doc = parser.parseFromString(`<div>${html}</div>`, "text/html");
  const root = doc.body.firstElementChild as HTMLElement | null;
  if (!root) return "";

  const walk = (node: Node) => {
    if (node.nodeType === Node.ELEMENT_NODE) {
      const el = node as Element;
      const tag = el.tagName.toLowerCase();

      if (!allowed.has(tag)) {
        // Replace disallowed element with its text content
        const text = doc.createTextNode(el.textContent || "");
        el.replaceWith(text);
        return;
      }

      // Remove dangerous attributes
      const attrs = Array.from(el.attributes);
      for (const a of attrs) {
        const name = (a.name || "").toLowerCase();
        const value = a.value || "";

        if (DENY_ATTRS.has(name)) {
          el.removeAttribute(a.name);
          continue;
        }

        for (const pref of GLOBAL_DENY_ATTR_PREFIXES) {
          if (name.startsWith(pref)) {
            el.removeAttribute(a.name);
            continue;
          }
        }

        // Allowlist per tag (and no global attrs except safe ones)
        const allowedAttrs = ALLOWED_ATTRS_BY_TAG[tag];
        if (allowedAttrs) {
          if (!allowedAttrs.has(name)) {
            el.removeAttribute(a.name);
            continue;
          }
        } else {
          // No attrs allowed for this tag
          el.removeAttribute(a.name);
          continue;
        }

        // Special handling for href
        if (tag === "a" && name === "href") {
          const safe = sanitizeUrl(value, o);
          if (!safe) {
            el.removeAttribute("href");
            el.removeAttribute("target");
            el.removeAttribute("rel");
          } else {
            el.setAttribute("href", safe);
            if (o.openLinksInNewTab) {
              el.setAttribute("target", "_blank");
              el.setAttribute("rel", safeRel(true));
            } else {
              el.removeAttribute("target");
              el.setAttribute("rel", safeRel(false));
            }
          }
        }

        // Normalize class on code/pre
        if ((tag === "code" || tag === "pre") && name === "class") {
          const v = value.trim();
          if (!v) el.removeAttribute("class");
          // Keep only "language-xxx" or "lang-xxx"
          const m = /(language|lang)-([a-z0-9_+-]{1,24})/i.exec(v);
          if (!m) el.removeAttribute("class");
          else el.setAttribute("class", `${m[1].toLowerCase()}-${m[2].toLowerCase()}`);
        }

        // Normalize numeric attrs on td/th
        if ((tag === "td" || tag === "th") && (name === "colspan" || name === "rowspan")) {
          const n = parseInt(value, 10);
          if (!Number.isFinite(n) || n <= 0 || n > 1000) el.removeAttribute(name);
          else el.setAttribute(name, String(n));
        }
      }
    }

    // Recurse into children (copy list because we may mutate)
    const children = Array.from(node.childNodes);
    for (const c of children) walk(c);
  };

  walk(root);

  // Final pass: remove comments
  const removeComments = (n: Node) => {
    const cs = Array.from(n.childNodes);
    for (const c of cs) {
      if (c.nodeType === Node.COMMENT_NODE) {
        c.parentNode?.removeChild(c);
        continue;
      }
      removeComments(c);
    }
  };
  removeComments(root);

  return root.innerHTML;
}

function htmlToText(html: string): string {
  if (typeof window === "undefined" || typeof DOMParser === "undefined") {
    return stripControlChars(html).replace(/<[^>]*>/g, "");
  }
  const doc = new DOMParser().parseFromString(`<div>${html}</div>`, "text/html");
  return (doc.body.textContent || "").trim();
}

export function safeMarkdownToHtml(markdown: string, options?: SafeMarkdownOptions): SafeMarkdownResult {
  const o = mergeOptions(options);
  const warnings: string[] = [];

  const norm = normalizeInput(markdown ?? "", o.maxInputChars);
  if (norm.truncated) warnings.push("input_truncated");

  // Render limited markdown safely.
  const parts = parseFencedCodeBlocks(norm.value);
  const rendered: string[] = [];

  for (const p of parts) {
    if (p.type === "code") {
      const langClass = p.lang ? ` class="language-${escapeHtml(p.lang)}"` : "";
      const code = escapeHtml(p.content);
      rendered.push(`<pre${langClass}><code${langClass}>${code}</code></pre>`);
    } else {
      rendered.push(renderBlockMarkdown(p.content, o));
    }
  }

  const rawHtml = rendered.join("\n");
  const sanitized = sanitizeHtml(rawHtml, o);

  const clamped = clampOutput(sanitized, o.maxOutputChars);
  if (clamped.truncated) warnings.push("output_truncated");

  const text = htmlToText(clamped.value);

  return {
    ok: true,
    html: clamped.value,
    text,
    warnings,
    meta: {
      inputChars: norm.value.length,
      outputChars: clamped.value.length,
      mode: o.mode,
    },
  };
}

export function safeMarkdownToText(markdown: string, options?: SafeMarkdownOptions): string {
  return safeMarkdownToHtml(markdown, options).text;
}

export function sanitizeRenderedHtml(html: string, options?: SafeMarkdownOptions): string {
  const o = mergeOptions(options);
  const norm = normalizeInput(html ?? "", o.maxInputChars);
  return clampOutput(sanitizeHtml(stripControlChars(norm.value), o), o.maxOutputChars).value;
}
