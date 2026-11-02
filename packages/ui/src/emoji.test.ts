import { describe, expect, it } from "vite-plus/test";
import * as proto from "@segv/protocol/proto";
import raw from "emojibase-data/en/data.json";
import {
  drawn,
  emojiSet,
  QUICK_DEFAULT,
  quickList,
  search,
  TABS,
  toned,
  wireForm,
  type Emoji,
  type RawEmoji,
} from "./emoji";

const set = emojiSet(raw as unknown as RawEmoji[]);
const all: Emoji[] = set.groups.flatMap((g) => g.list.flatMap((em) => [em, ...(em.skins ?? [])]));
const byName = (name: string): Emoji => {
  const em = all.find((x) => x.name === name);
  if (!em) throw new Error(`no emoji named ${name}`);
  return em;
};

describe("the emoji set", () => {
  it("has every group, in Unicode's order, without regional indicators and lone components", () => {
    expect(set.groups.map((g) => g.key)).toEqual(TABS.slice(1).map((t) => t.key));
    for (const g of set.groups) expect(g.list.length).toBeGreaterThan(50);
    expect(set.groups.reduce((n, g) => n + g.list.length, 0)).toBeGreaterThan(1900);
    expect(all.length).toBeGreaterThan(3900);
    expect(all.some((x) => x.e === "🇦" || x.e === "🏻" || x.e === "🦰")).toBe(false);
    expect(set.groups[0].list[0].e).toBe("😀");
  });

  it("sends each emoji in a form that a REACTION carries, and finds it by that form", () => {
    let shortened = 0;
    for (const x of all) {
      const w = wireForm(x.e);
      const size = proto.utf8(w).length;
      expect(size).toBeGreaterThanOrEqual(1);
      expect(size).toBeLessThanOrEqual(proto.MAX_EMOJI_BYTES);
      if (w !== x.e) {
        shortened++;
        expect(proto.utf8(x.e).length).toBeGreaterThan(proto.MAX_EMOJI_BYTES);
        expect(w).toBe(x.e.replaceAll("\uFE0F", ""));
      }
      expect(set.byForm.get(x.e)).toBe(x);
      expect(set.byForm.get(w)).toBe(x);
    }
    // the kisses with skin tones (95 in Emoji 18)
    expect(shortened).toBeGreaterThan(0);
    expect(shortened).toBeLessThan(200);
  });

  it("keeps the first release's palette as it was sent", () => {
    for (const e of QUICK_DEFAULT) {
      expect(set.byForm.get(e)?.e).toBe(e);
      expect(wireForm(e)).toBe(e);
    }
  });

  it("probes one emoji of one code point per Emoji version from 11, newest first", () => {
    const versions = set.probes.map(([v]) => v);
    expect(versions).toEqual([...versions].sort((a, b) => b - a));
    expect(versions).toEqual(expect.arrayContaining([11, 12, 13, 14, 15, 16]));
    for (const [, e] of set.probes) expect([...e]).toHaveLength(1);
  });
});

describe("drawn", () => {
  it("takes the .1 versions with their whole version", () => {
    const at = (v: number): Emoji => ({ e: "x", name: "x", v, tone: [], words: [] });
    expect(drawn(at(0.6), 11)).toBe(true);
    expect(drawn(at(12.1), 12)).toBe(true);
    expect(drawn(at(13), 12)).toBe(false);
    expect(drawn(at(18), Infinity)).toBe(true);
  });
});

describe("toned", () => {
  it("picks the variant with that tone for every person, where there is one", () => {
    expect(toned(byName("thumbs up"), 3, Infinity).e).toBe("👍🏽");
    expect(toned(byName("handshake"), 1, Infinity).e).toBe("🤝🏻");
    expect(toned(byName("thumbs up"), 0, Infinity).e).toBe("👍");
    expect(toned(byName("grinning face"), 3, Infinity).e).toBe("😀");
  });

  it("keeps the emoji without a tone where the device does not draw the variant", () => {
    const wrestling = byName("people wrestling");
    const v = toned(wrestling, 2, Infinity);
    expect(v).not.toBe(wrestling);
    expect(toned(wrestling, 2, Math.floor(v.v) - 1)).toBe(wrestling);
  });

  it("lists mixed tones among the variants of two people", () => {
    const tones = byName("handshake").skins?.map((s) => s.tone.join(","));
    expect(tones).toHaveLength(25);
    expect(tones).toEqual(expect.arrayContaining(["1", "1,2", "5,4"]));
  });
});

describe("search", () => {
  it("finds by name, best match first", () => {
    expect(search(set, "thumbs up", Infinity)[0].e).toBe("👍");
    expect(search(set, "Thumbs", Infinity)[0].e).toBe("👍");
    expect(search(set, "grinning face", Infinity)[0].e).toBe("😀");
  });

  it("finds by keyword and by word prefix", () => {
    expect(search(set, "+1", Infinity).map((x) => x.e)).toContain("👍");
    expect(search(set, "tea", Infinity).map((x) => x.e)).toContain("🍵");
    expect(search(set, "jap fl", Infinity).map((x) => x.e)).toContain("🇯🇵");
  });

  it("ignores case and accents", () => {
    expect(search(set, "CÔTE", Infinity).map((x) => x.name)).toContain("flag: Côte d’Ivoire");
    expect(search(set, "cote divoire", Infinity).map((x) => x.name)).toContain(
      "flag: Côte d’Ivoire",
    );
  });

  it("finds an emoji typed or pasted, a skin tone included", () => {
    expect(search(set, "👍🏽", Infinity)[0].e).toBe("👍🏽");
    expect(search(set, "😀", Infinity)[0].e).toBe("😀");
  });

  it("leaves out what the device does not draw", () => {
    const newest = set.probes[0];
    expect(search(set, newest[1], Infinity)).toHaveLength(1);
    expect(search(set, newest[1], newest[0] - 1)).toHaveLength(0);
  });

  it("finds nothing for nothing", () => {
    expect(search(set, "  ", Infinity)).toEqual([]);
    expect(search(set, "zzzzqqq", Infinity)).toEqual([]);
  });
});

describe("quickList", () => {
  it("puts this session's picks first, then the conversation's, then the defaults, once each", () => {
    expect(quickList(["🎉", "👍"], ["👍", "🔥"], 5)).toEqual(["🎉", "👍", "🔥", "❤\uFE0F", "😂"]);
    expect(quickList([], [])).toEqual(QUICK_DEFAULT);
  });
});
