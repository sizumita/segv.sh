// Message text as Markdown, the subset Discord renders: **bold**, *italic* / _italic_, __underline__,
// ~~strikethrough~~, ||spoiler||, `code`, ```code blocks```, > quotes, >>> quotes, # headings, -# subtext,
// - / 1. lists, links (bare, <url> and [label](url)) and \ escapes. The text is parsed into a small tree that the UI
// turns into elements: never into HTML, which the CSP would refuse anyway (no innerHTML).
// Pure functions, no Qwik APIs.

export type Inline =
  | { t: "text"; v: string }
  | { t: "b" | "i" | "u" | "s" | "spoiler"; c: Inline[] }
  | { t: "code"; v: string }
  /** `masked`: written as [label](url), so the label may say something other than where the link goes */
  | { t: "link"; href: string; masked: boolean; c: Inline[] };

export interface ListBlock {
  t: "list";
  ordered: boolean;
  /** the number of the first item of an ordered list */
  start: number;
  /** `sub`: the lists within an item */
  items: { c: Inline[]; sub?: ListBlock[] }[];
}

export type Block =
  /** a run of lines; its newlines are kept */
  | { t: "p"; c: Inline[] }
  | { t: "h"; level: 1 | 2 | 3; c: Inline[] }
  | { t: "sub"; c: Inline[] }
  | { t: "quote"; c: Block[] }
  | ListBlock
  | { t: "pre"; lang: string; v: string };

/** Nesting deeper than this (styles within styles, lists within lists) stays as it was written. */
const MAX_DEPTH = 8;

export function parse(text: string): Block[] {
  return blocks(text.replace(/\r\n?/g, "\n"), true);
}

// ---- blocks ----

const HEADING = /^(#{1,3}) +(\S.*)$/;
const SUBTEXT = /^-# +(\S.*)$/;
const ITEM = /^( *)([-*]|\d{1,9}\.) +(\S.*)$/;
const QUOTE_REST = /^>>>(?: |$)/;

interface ItemLine {
  indent: number;
  ordered: boolean;
  num: number;
  text: string;
}

/**
 * Splits text into blocks. A heading, subtext, list or quote starts at the start of a line and a code block
 * anywhere; the newline that ends a block belongs to it. Quotes do not nest.
 */
function blocks(s: string, quotes: boolean): Block[] {
  const out: Block[] = [];
  const n = s.length;
  let para = -1; // start of the open paragraph
  const flush = (end: number) => {
    if (para < 0) return;
    const text = s.slice(para, s[end - 1] === "\n" ? end - 1 : end);
    if (text) out.push({ t: "p", c: inline(text, 0, true) });
    para = -1;
  };

  let i = 0;
  while (i < n) {
    const eol = s.indexOf("\n", i);
    const end = eol < 0 ? n : eol;
    const next = eol < 0 ? n : eol + 1;

    if (i === 0 || s[i - 1] === "\n") {
      const line = s.slice(i, end);
      let m: RegExpExecArray | null;
      if (quotes && (m = QUOTE_REST.exec(line))) {
        flush(i);
        const rest = s.slice(i + m[0].length);
        out.push({ t: "quote", c: blocks(rest.startsWith("\n") ? rest.slice(1) : rest, false) });
        return out;
      }
      if (quotes && line.startsWith("> ")) {
        flush(i);
        const lines: string[] = [];
        let k = i;
        while (k < n && s.startsWith("> ", k)) {
          const e = s.indexOf("\n", k);
          lines.push(s.slice(k + 2, e < 0 ? n : e));
          k = e < 0 ? n : e + 1;
        }
        out.push({ t: "quote", c: blocks(lines.join("\n"), false) });
        i = k;
        continue;
      }
      if ((m = HEADING.exec(line))) {
        flush(i);
        out.push({ t: "h", level: m[1].length as 1 | 2 | 3, c: inline(m[2], 0, true) });
        i = next;
        continue;
      }
      if ((m = SUBTEXT.exec(line))) {
        flush(i);
        out.push({ t: "sub", c: inline(m[1], 0, true) });
        i = next;
        continue;
      }
      if (ITEM.test(line)) {
        flush(i);
        const items: ItemLine[] = [];
        let k = i;
        while (k < n) {
          const e = s.indexOf("\n", k);
          const im = ITEM.exec(s.slice(k, e < 0 ? n : e));
          if (!im) break;
          const ordered = im[2] !== "-" && im[2] !== "*";
          items.push({
            indent: im[1].length,
            ordered,
            num: ordered ? Number.parseInt(im[2], 10) : 1,
            text: im[3],
          });
          k = e < 0 ? n : e + 1;
        }
        out.push(...lists(items, 0, items.length, 0));
        i = k;
        continue;
      }
    }

    // A code block may open anywhere in this line and close on a later one.
    let fence: Fence | null = null;
    for (let f = s.indexOf("```", i); f >= 0 && f <= end; f = s.indexOf("```", f + 1)) {
      fence = codeBlock(s, f);
      if (fence) break;
      if (s.indexOf("```", f + 3) < 0) break; // no closing fence for this one, nor for any later one
    }
    if (fence) {
      if (para < 0) para = i;
      flush(fence.start);
      out.push({ t: "pre", lang: fence.lang, v: fence.v });
      i = s[fence.end] === "\n" ? fence.end + 1 : fence.end;
      continue;
    }
    if (para < 0) para = i;
    i = next;
  }
  flush(n);
  return out;
}

interface Fence {
  lang: string;
  v: string;
  start: number;
  end: number;
}

const LANG = /^([\w+#.-]+)\n/;

/** ```[lang\n]code``` at i: the code, with one leading and one trailing newline dropped. */
function codeBlock(s: string, i: number): Fence | null {
  if (!s.startsWith("```", i)) return null;
  const close = s.indexOf("```", i + 3);
  if (close < 0) return null;
  let v = s.slice(i + 3, close);
  let lang = "";
  const m = LANG.exec(v);
  if (m && v.length > m[0].length) {
    lang = m[1];
    v = v.slice(m[0].length);
  }
  if (v.startsWith("\n")) v = v.slice(1);
  if (v.endsWith("\n")) v = v.slice(0, -1);
  if (!v.trim()) return null;
  return { lang, v, start: i, end: close + 3 };
}

/**
 * The lists of items [from, to): an item indented further than the one before starts a list within it, and a
 * change between - and 1. items starts another list.
 */
function lists(items: ItemLine[], from: number, to: number, depth: number): ListBlock[] {
  const out: ListBlock[] = [];
  let cur: ListBlock | null = null;
  let k = from;
  while (k < to) {
    const it = items[k++];
    // A - item after 1. items (or the other way round) starts another list.
    if (!cur || cur.ordered !== it.ordered) {
      cur = { t: "list", ordered: it.ordered, start: it.num, items: [] };
      out.push(cur);
    }
    let j = k;
    if (depth + 1 < MAX_DEPTH) while (j < to && items[j].indent > it.indent) j++;
    cur.items.push(
      j > k
        ? { c: inline(it.text, 0, true), sub: lists(items, k, j, depth + 1) }
        : { c: inline(it.text, 0, true) },
    );
    k = j;
  }
  return out;
}

// ---- inline ----

/** A link target: http(s) only, as the URL parser normalises it (an IDN host becomes punycode). */
export function safeHref(raw: string): string | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
}

const URL_RE = /https?:\/\/[^\s<]+[^<.,:;"')\]\s]/iy;
const AUTOLINK = /<(https?:\/\/[^\s>]+)>/iy;
const MASKED = /\[((?:\\.|[^\\[\]])+)\]\(\s*<?(https?:\/\/(?:\([^\s()]*\)|[^\s()<>])+)>?\s*\)/iy;
const ESCAPABLE = /[^0-9A-Za-z\s]/;
const WORD = /\w/;
const SPACE = /\s/;

interface Span {
  t: "b" | "i" | "u" | "s" | "spoiler";
  /** the content, [a, b) */
  a: number;
  b: number;
  end: number;
}

/**
 * Inline styles, code and links within one block. `links` is false inside a link's label (links do not nest).
 * `none` remembers, per kind of closing delimiter, the position from which a search for one found nothing: a later
 * search from further on finds nothing either, which keeps a text full of unclosed delimiters linear.
 */
function inline(s: string, depth: number, links: boolean): Inline[] {
  const out: Inline[] = [];
  const none = new Map<string, number>();
  const n = s.length;
  let buf = "";
  const push = (node: Inline) => {
    if (buf) out.push({ t: "text", v: buf });
    buf = "";
    out.push(node);
  };

  let i = 0;
  while (i < n) {
    const c = s[i];
    if (c === "\\" && i + 1 < n && ESCAPABLE.test(s[i + 1])) {
      buf += s[i + 1];
      i += 2;
      continue;
    }
    if (c === "`") {
      let r = 1;
      while (s[i + r] === "`") r++;
      const close = codeClose(s, i + r, r, none);
      if (close >= 0) {
        push({ t: "code", v: s.slice(i + r, close) });
        i = close + r;
      } else {
        buf += s.slice(i, i + r);
        i += r;
      }
      continue;
    }
    if (links && (c === "h" || c === "H" || c === "<" || c === "[")) {
      const link = linkAt(s, i, depth);
      if (link) {
        push(link.node);
        i = link.end;
        continue;
      }
    }
    if (depth < MAX_DEPTH && (c === "*" || c === "_" || c === "~" || c === "|")) {
      const sp = styled(s, i, none);
      if (sp) {
        push({ t: sp.t, c: inline(s.slice(sp.a, sp.b), depth + 1, links) });
        i = sp.end;
        continue;
      }
    }
    buf += c;
    i++;
  }
  if (buf) out.push({ t: "text", v: buf });
  return out;
}

function linkAt(s: string, i: number, depth: number): { node: Inline; end: number } | null {
  const c = s[i];
  if (c === "[") {
    MASKED.lastIndex = i;
    const m = MASKED.exec(s);
    // A label that is itself a URL could name another site than the one the link opens: leave it as text.
    if (!m || /:\/\//.test(m[1])) return null;
    const href = safeHref(m[2]);
    if (!href) return null;
    return {
      node: { t: "link", href, masked: true, c: inline(m[1], depth + 1, false) },
      end: MASKED.lastIndex,
    };
  }
  if (c === "<") {
    AUTOLINK.lastIndex = i;
    const m = AUTOLINK.exec(s);
    const href = m && safeHref(m[1]);
    if (!m || !href) return null;
    return {
      node: { t: "link", href, masked: false, c: [{ t: "text", v: m[1] }] },
      end: AUTOLINK.lastIndex,
    };
  }
  URL_RE.lastIndex = i;
  const m = URL_RE.exec(s);
  if (!m) return null;
  let url = m[0];
  // Keep a closing parenthesis that closes one opened in the URL (https://en.wikipedia.org/wiki/Foo_(bar)).
  while (s[i + url.length] === ")" && count(url, "(") > count(url, ")")) url += ")";
  const href = safeHref(url);
  if (!href) return null;
  return {
    node: { t: "link", href, masked: false, c: [{ t: "text", v: url }] },
    end: i + url.length,
  };
}

const count = (s: string, ch: string): number => s.split(ch).length - 1;

/** The closing run of exactly r backticks for code opened before `from`, or -1. */
function codeClose(s: string, from: number, r: number, none: Map<string, number>): number {
  const key = `\`${r}`;
  if (from >= (none.get(key) ?? Infinity)) return -1;
  let k = from + 1; // the code holds at least one character
  while (k < s.length) {
    const j = s.indexOf("`", k);
    if (j < 0) break;
    let e = j;
    while (s[e] === "`") e++;
    if (e - j === r) return j;
    k = e;
  }
  none.set(key, Math.min(from, none.get(key) ?? Infinity));
  return -1;
}

/** **bold**, __underline__, ~~strike~~, ||spoiler||, *italic* or _italic_ opening at i. */
function styled(s: string, i: number, none: Map<string, number>): Span | null {
  const c = s[i];
  const double = s[i + 1] === c;
  if (c === "|" || c === "~")
    return double ? pair(s, i, c, c === "|" ? "spoiler" : "s", none) : null;
  if (double) {
    const sp = pair(s, i, c, c === "*" ? "b" : "u", none);
    if (sp) return sp;
  }
  return c === "*" ? emStar(s, i, none) : emUnderscore(s, i, none);
}

/** A doubled delimiter: the first doubled one after a non-empty content (for ** and __, one not followed by a third). */
function pair(
  s: string,
  i: number,
  c: string,
  t: Span["t"],
  none: Map<string, number>,
): Span | null {
  const from = i + 3;
  if (from >= (none.get(c + c) ?? Infinity)) return null;
  const third = c === "*" || c === "_";
  for (let k = from; k < s.length; k++) {
    if (s[k] === "\\") {
      k++;
      continue;
    }
    if (s[k] === c && s[k + 1] === c && !(third && s[k + 2] === c)) {
      return { t, a: i + 2, b: k, end: k + 2 };
    }
  }
  none.set(c + c, Math.min(from, none.get(c + c) ?? Infinity));
  return null;
}

/**
 * *italic*: it opens before a non-space, and closes at a single * after a non-space. Within it, ** pairs are
 * content (bold inside italic), and a lone * after a space ends the attempt.
 */
function emStar(s: string, i: number, none: Map<string, number>): Span | null {
  const n = s.length;
  if (i + 1 >= n || SPACE.test(s[i + 1])) return null;
  if (i + 1 >= (none.get("*") ?? Infinity)) return null;
  let k = i + 1;
  while (k < n) {
    const ch = s[k];
    if (ch === "\\") {
      k += 2;
    } else if (ch === "*") {
      if (s[k + 1] === "*") {
        k += 2;
        continue;
      }
      if (k === i + 1 || SPACE.test(s[k - 1])) return null;
      return { t: "i", a: i + 1, b: k, end: k + 1 };
    } else {
      k++;
    }
  }
  none.set("*", Math.min(i + 1, none.get("*") ?? Infinity));
  return null;
}

/** _italic_: only between word boundaries (snake_case_names stay as they are); __ pairs are content. */
function emUnderscore(s: string, i: number, none: Map<string, number>): Span | null {
  const n = s.length;
  if (i > 0 && WORD.test(s[i - 1])) return null;
  if (i + 1 >= (none.get("_") ?? Infinity)) return null;
  let k = i + 1;
  while (k < n) {
    const ch = s[k];
    if (ch === "\\") {
      k += 2;
    } else if (ch === "_") {
      if (s[k + 1] === "_") {
        k += 2;
        continue;
      }
      if (k === i + 1 || (k + 1 < n && WORD.test(s[k + 1]))) return null;
      return { t: "i", a: i + 1, b: k, end: k + 1 };
    } else {
      k++;
    }
  }
  none.set("_", Math.min(i + 1, none.get("_") ?? Infinity));
  return null;
}
