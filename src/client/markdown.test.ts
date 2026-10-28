import { describe, expect, it } from "vite-plus/test";
import { parse, plainText, safeHref, SPOILER, type Block, type Inline } from "./markdown";

const text = (v: string): Inline => ({ t: "text", v });
const p = (...c: Inline[]): Block => ({ t: "p", c });
/** The inline nodes of a message that is one paragraph. */
const one = (src: string): Inline[] => {
  const doc = parse(src);
  expect(doc).toHaveLength(1);
  expect(doc[0].t).toBe("p");
  return (doc[0] as { c: Inline[] }).c;
};

describe("inline styles", () => {
  it("leaves plain text alone", () => {
    expect(parse("hello")).toEqual([p(text("hello"))]);
    expect(parse("こんにちは 世界")).toEqual([p(text("こんにちは 世界"))]);
    expect(parse("")).toEqual([]);
  });

  it("parses each style", () => {
    expect(one("**b**")).toEqual([{ t: "b", c: [text("b")] }]);
    expect(one("*i*")).toEqual([{ t: "i", c: [text("i")] }]);
    expect(one("_i_")).toEqual([{ t: "i", c: [text("i")] }]);
    expect(one("__u__")).toEqual([{ t: "u", c: [text("u")] }]);
    expect(one("~~s~~")).toEqual([{ t: "s", c: [text("s")] }]);
    expect(one("||x||")).toEqual([{ t: "spoiler", c: [text("x")] }]);
    expect(one("`c`")).toEqual([{ t: "code", v: "c" }]);
  });

  it("nests styles", () => {
    expect(one("***bi***")).toEqual([{ t: "b", c: [{ t: "i", c: [text("bi")] }] }]);
    expect(one("___ui___")).toEqual([{ t: "u", c: [{ t: "i", c: [text("ui")] }] }]);
    expect(one("*a **b** c*")).toEqual([
      { t: "i", c: [text("a "), { t: "b", c: [text("b")] }, text(" c")] },
    ]);
    expect(one("||**x**||")).toEqual([{ t: "spoiler", c: [{ t: "b", c: [text("x")] }] }]);
  });

  it("styles text around and across lines", () => {
    expect(one("a **b** c")).toEqual([text("a "), { t: "b", c: [text("b")] }, text(" c")]);
    expect(one("太字は**ここ**です")).toEqual([
      text("太字は"),
      { t: "b", c: [text("ここ")] },
      text("です"),
    ]);
    expect(one("**a\nb**")).toEqual([{ t: "b", c: [text("a\nb")] }]);
  });

  it("leaves unclosed and spaced delimiters as text", () => {
    expect(one("**a")).toEqual([text("**a")]);
    expect(one("a * b * c")).toEqual([text("a * b * c")]);
    expect(one("*a *")).toEqual([text("*a *")]);
    expect(one("2 * 3 = 6")).toEqual([text("2 * 3 = 6")]);
    expect(one("|| ~ |")).toEqual([text("|| ~ |")]);
  });

  it("keeps underscores inside words", () => {
    expect(one("snake_case_name")).toEqual([text("snake_case_name")]);
    expect(one("a _b_ c")).toEqual([text("a "), { t: "i", c: [text("b")] }, text(" c")]);
  });

  it("does not parse inside code", () => {
    expect(one("`**x**`")).toEqual([{ t: "code", v: "**x**" }]);
    expect(one("``a ` b``")).toEqual([{ t: "code", v: "a ` b" }]);
    expect(one("``")).toEqual([text("``")]);
    expect(one("`a")).toEqual([text("`a")]);
  });

  it("honours escapes", () => {
    expect(one("\\*a\\*")).toEqual([text("*a*")]);
    expect(one("\\||x||")).toEqual([text("||x||")]);
    expect(one("\\# not a heading")).toEqual([text("# not a heading")]);
    expect(one("a\\b")).toEqual([text("a\\b")]);
  });
});

describe("links", () => {
  it("links bare URLs and trims trailing punctuation", () => {
    expect(one("see https://example.com/a?b=1.")).toEqual([
      text("see "),
      {
        t: "link",
        href: "https://example.com/a?b=1",
        masked: false,
        c: [text("https://example.com/a?b=1")],
      },
      text("."),
    ]);
    expect(one("(https://example.com)")).toEqual([
      text("("),
      { t: "link", href: "https://example.com/", masked: false, c: [text("https://example.com")] },
      text(")"),
    ]);
  });

  it("keeps a closing parenthesis that the URL opened", () => {
    const [l] = one("https://en.wikipedia.org/wiki/Foo_(bar)");
    expect(l).toMatchObject({ t: "link", c: [text("https://en.wikipedia.org/wiki/Foo_(bar)")] });
  });

  it("does not style inside a URL", () => {
    const [l] = one("https://example.com/a_b_c/**x**");
    expect(l).toMatchObject({ t: "link", masked: false });
  });

  it("links <url>", () => {
    expect(one("<https://example.com>")).toEqual([
      { t: "link", href: "https://example.com/", masked: false, c: [text("https://example.com")] },
    ]);
  });

  it("links [label](url) as masked", () => {
    expect(one("[the **docs**](https://example.com/docs)")).toEqual([
      {
        t: "link",
        href: "https://example.com/docs",
        masked: true,
        c: [text("the "), { t: "b", c: [text("docs")] }],
      },
    ]);
  });

  it("refuses masked links whose label is a URL", () => {
    const c = one("[https://bank.example](https://evil.example)");
    expect(c.some((n) => n.t === "link" && n.masked)).toBe(false);
    // What is linked shows where it goes.
    expect(c.filter((n) => n.t === "link")).toEqual([
      {
        t: "link",
        href: "https://evil.example/",
        masked: false,
        c: [text("https://evil.example")],
      },
    ]);
  });

  it("only links http and https", () => {
    expect(one("[x](javascript:alert(1))")).toEqual([text("[x](javascript:alert(1))")]);
    expect(one("<data:text/html,x>")).toEqual([text("<data:text/html,x>")]);
    expect(safeHref("javascript:alert(1)")).toBeNull();
    expect(safeHref("https://例え.jp/")).toBe("https://xn--r8jz45g.jp/");
  });
});

describe("blocks", () => {
  it("keeps newlines in a paragraph", () => {
    expect(parse("a\n\nb")).toEqual([p(text("a\n\nb"))]);
  });

  it("parses headings and subtext at the start of a line", () => {
    expect(parse("# one\n## two\n### three\n-# small\nbody")).toEqual([
      { t: "h", level: 1, c: [text("one")] },
      { t: "h", level: 2, c: [text("two")] },
      { t: "h", level: 3, c: [text("three")] },
      { t: "sub", c: [text("small")] },
      p(text("body")),
    ]);
    expect(parse("#tag")).toEqual([p(text("#tag"))]);
    expect(parse("#### four")).toEqual([p(text("#### four"))]);
    expect(parse("a # b")).toEqual([p(text("a # b"))]);
  });

  it("parses quotes", () => {
    expect(parse("> a\n> **b**\nc")).toEqual([
      { t: "quote", c: [p(text("a\n"), { t: "b", c: [text("b")] })] },
      p(text("c")),
    ]);
    expect(parse("x\n>>> a\n\nb")).toEqual([p(text("x")), { t: "quote", c: [p(text("a\n\nb"))] }]);
    expect(parse(">>>\na")).toEqual([{ t: "quote", c: [p(text("a"))] }]);
    expect(parse(">no space")).toEqual([p(text(">no space"))]);
  });

  it("does not nest quotes", () => {
    expect(parse("> > a")).toEqual([{ t: "quote", c: [p(text("> a"))] }]);
  });

  it("parses lists, nested by indentation", () => {
    expect(parse("- a\n* b\n  - c\n- d")).toEqual([
      {
        t: "list",
        ordered: false,
        start: 1,
        items: [
          { c: [text("a")] },
          {
            c: [text("b")],
            sub: [{ t: "list", ordered: false, start: 1, items: [{ c: [text("c")] }] }],
          },
          { c: [text("d")] },
        ],
      },
    ]);
    expect(parse("3. x\n4. y")).toEqual([
      { t: "list", ordered: true, start: 3, items: [{ c: [text("x")] }, { c: [text("y")] }] },
    ]);
    expect(parse("*not a list*")).toEqual([p({ t: "i", c: [text("not a list")] })]);
  });

  it("starts another list where - and 1. items meet", () => {
    expect(parse("- a\n1. b\n2. c\n- d")).toEqual([
      { t: "list", ordered: false, start: 1, items: [{ c: [text("a")] }] },
      { t: "list", ordered: true, start: 1, items: [{ c: [text("b")] }, { c: [text("c")] }] },
      { t: "list", ordered: false, start: 1, items: [{ c: [text("d")] }] },
    ]);
    expect(parse("- a\n  1. b\n  - c")).toEqual([
      {
        t: "list",
        ordered: false,
        start: 1,
        items: [
          {
            c: [text("a")],
            sub: [
              { t: "list", ordered: true, start: 1, items: [{ c: [text("b")] }] },
              { t: "list", ordered: false, start: 1, items: [{ c: [text("c")] }] },
            ],
          },
        ],
      },
    ]);
  });

  it("parses code blocks, with an optional language", () => {
    expect(parse("```js\nlet a = 1;\n```")).toEqual([{ t: "pre", lang: "js", v: "let a = 1;" }]);
    expect(parse("```\n**not bold**\n```")).toEqual([{ t: "pre", lang: "", v: "**not bold**" }]);
    expect(parse("```js```")).toEqual([{ t: "pre", lang: "", v: "js" }]);
    expect(parse("look: ```x``` done")).toEqual([
      p(text("look: ")),
      { t: "pre", lang: "", v: "x" },
      p(text(" done")),
    ]);
    expect(parse("a\n```\nb\n\nc\n```\nd")).toEqual([
      p(text("a")),
      { t: "pre", lang: "", v: "b\n\nc" },
      p(text("d")),
    ]);
    expect(parse("``` x")).toEqual([p(text("``` x"))]);
    expect(parse("``````")).toEqual([p(text("``````"))]);
  });

  it("keeps block syntax inside code blocks as it is", () => {
    expect(parse("```\n# h\n> q\n- l\n```")).toEqual([{ t: "pre", lang: "", v: "# h\n> q\n- l" }]);
  });

  it("parses blocks inside quotes", () => {
    expect(parse("> # h\n> - a\n> ```x```")).toEqual([
      {
        t: "quote",
        c: [
          { t: "h", level: 1, c: [text("h")] },
          { t: "list", ordered: false, start: 1, items: [{ c: [text("a")] }] },
          { t: "pre", lang: "", v: "x" },
        ],
      },
    ]);
  });

  it("normalises CRLF", () => {
    expect(parse("a\r\n# b")).toEqual([p(text("a")), { t: "h", level: 1, c: [text("b")] }]);
  });
});

describe("plain text", () => {
  it("drops the syntax and keeps the words", () => {
    expect(plainText("plain")).toBe("plain");
    expect(plainText("**b** *i* __u__ ~~s~~ `c` \\*x\\*")).toBe("b i u s c *x*");
    expect(plainText("# 見出し\n-# small\nbody")).toBe("見出し\nsmall\nbody");
    expect(plainText("> a\n> b\nc")).toBe("a\nb\nc");
    expect(plainText("```js\nlet a = 1;\n```")).toBe("let a = 1;");
    expect(plainText("a\n\nb")).toBe("a\n\nb");
  });

  it("shows links by their label or URL", () => {
    expect(plainText("[the docs](https://example.com) and <https://example.org>")).toBe(
      "the docs and https://example.org",
    );
  });

  it("keeps list markers and numbers", () => {
    expect(plainText("- a\n  - b\n3. c\n4. d")).toBe("- a\n  - b\n3. c\n4. d");
  });

  it("shows nothing of a spoiler, not even its length", () => {
    for (const src of [
      "||secret||",
      "||a much longer secret, with **bold** in it||",
      "> ||secret||",
      "- ||secret||",
      "# ||secret||",
      "[||secret||](https://example.com)",
      "**||secret||**",
    ]) {
      const out = plainText(src);
      expect(out).toContain(SPOILER);
      expect(out).not.toMatch(/secret|bold|longer/);
    }
    expect(plainText("a ||x|| b")).toBe(`a ${SPOILER} b`);
    expect(plainText("||x||")).toBe(plainText("||xxxxxxxxxxxxxxxx||"));
  });

  it("leaves || in code as it is (not a spoiler in the app either)", () => {
    expect(plainText("`||x||`")).toBe("||x||");
  });
});

describe("hostile input", () => {
  const depth = (nodes: Inline[]): number =>
    nodes.reduce((d, n) => Math.max(d, "c" in n ? 1 + depth(n.c) : 0), 0);

  it("caps nesting", () => {
    const src = `${"**".repeat(200)}x${"**".repeat(200)}`;
    expect(depth(one(src))).toBe(8);
    const list = Array.from({ length: 200 }, (_, k) => `${" ".repeat(k)}- x`).join("\n");
    const listDepth = (b: Block): number =>
      b.t === "list"
        ? 1 + Math.max(0, ...b.items.flatMap((it) => (it.sub ?? []).map(listDepth)))
        : 0;
    expect(listDepth(parse(list)[0])).toBe(8);
  });

  it("stays fast on unclosed delimiters", () => {
    const units = [
      "*a ",
      "*a**",
      "**a ",
      "_a ",
      "_a__",
      "__a ",
      "~~a ",
      "||a ",
      "`a ",
      "`a``",
      "[a](",
      "[a](https://",
      "<https://a ",
      "```a ",
      "```",
      "> ",
      "\n> ",
      "- ",
      "\n - ",
      "\\",
    ];
    for (const unit of units) {
      for (const src of [unit.repeat(Math.ceil(15_000 / unit.length)), unit + "a ".repeat(7_500)]) {
        const t0 = performance.now();
        parse(src);
        expect(performance.now() - t0, JSON.stringify(unit)).toBeLessThan(200);
      }
    }
  });
});
