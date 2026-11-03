// The emoji that the reaction picker offers (§11.12): every fully-qualified emoji of Unicode's emoji-test.txt with its
// skin tones, in Unicode's order, named and searched by CLDR's English short names and keywords (emojibase-data).
// Plain functions without Qwik or the DOM, so that Node can test them.
// emojibase-data's English data as a file of the build, fetched when the picker first opens.
import DATA_URL from "emojibase-data/en/data.json?url";
import { MAX_EMOJI_BYTES } from "./util";

/** The fields of an emojibase-data entry that the picker reads. */
export interface RawEmoji {
  label: string;
  emoji: string;
  tags?: string[];
  group?: number;
  order?: number;
  version: number;
  tone?: number | number[];
  skins?: RawEmoji[];
}

/** One emoji of the picker, or one of its skin tone variants. */
export interface Emoji {
  /** the emoji, fully qualified */
  e: string;
  /** its CLDR short name, such as "thumbs up" or "handshake: light skin tone, dark skin tone" */
  name: string;
  /** the Emoji version that added it */
  v: number;
  /** its skin tones, 1 (light) to 5 (dark), one for all of its people or one per person; empty without a tone */
  tone: number[];
  /** its variants with skin tones, in Unicode's order; absent where it has none */
  skins?: Emoji[];
  /** the words of its name and keywords, folded (`fold`), which a search matches by prefix; empty for a variant */
  words: string[];
}

/** One of Unicode's emoji groups, as a section of the picker. */
export interface Group {
  key: string;
  name: string;
  /** the emoji on its tab */
  icon: string;
  list: Emoji[];
}

export interface EmojiSet {
  groups: Group[];
  /** every emoji and variant, by its fully-qualified form and by its form as sent (`wireForm`) */
  byForm: Map<string, Emoji>;
  /**
   * For each Emoji version from 11 on that added an emoji of one code point, the first such emoji, newest first:
   * whether a device draws it tells whether its emoji font has that version.
   */
  probes: [number, string][];
}

/** emojibase's group numbers, in Unicode's order. 2 (skin tones and hair alone) is left out: they are parts of emoji. */
const GROUPS: [number, string, string, string][] = [
  [0, "smileys", "smileys & emotion", "😀"],
  [1, "people", "people & body", "👋"],
  [3, "nature", "animals & nature", "🐻"],
  [4, "food", "food & drink", "🍔"],
  [5, "travel", "travel & places", "🚗"],
  [6, "activities", "activities", "⚽"],
  [7, "objects", "objects", "💡"],
  [8, "symbols", "symbols", "🔣"],
  [9, "flags", "flags", "🏁"],
];

/** The picker's tabs: the "frequently used" row, then the groups. */
export const TABS: { key: string; name: string; icon: string }[] = [
  { key: "quick", name: "frequently used", icon: "🕘" },
  ...GROUPS.map(([, key, name, icon]) => ({ key, name, icon })),
];

/** The reactions offered before self has used any: the palette of the first release. */
export const QUICK_DEFAULT = ["👍", "❤\uFE0F", "😂", "😮", "😢", "🙏"];

/** Lowercase and without accents, as a search compares words ("Côte" finds "cote"). */
export const fold = (s: string): string => s.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase();

/** The folded words of a name or keyword: "flag: Côte d’Ivoire" → ["flag", "cote", "divoire"]. */
const wordsOf = (s: string): string[] =>
  fold(s)
    .replace(/['’]/g, "")
    .split(/[\s:,.!?()"“”]+/u)
    .filter(Boolean);

const utf8 = new TextEncoder();

/**
 * The form of `e` that a REACTION carries: `e` itself, or, where it is longer than 32 bytes, `e` without U+FE0F, which
 * fits (§3.3). Only kisses with skin tones are that long, and only by their U+FE0F.
 */
export function wireForm(e: string): string {
  return utf8.encode(e).length <= MAX_EMOJI_BYTES ? e : e.replace(/\uFE0F/g, "");
}

/** The picker's emoji from emojibase-data's entries: the groups in Unicode's order, without regional indicators. */
export function emojiSet(raw: RawEmoji[]): EmojiSet {
  const byForm = new Map<string, Emoji>();
  const make = (x: RawEmoji, words: string[]): Emoji => {
    const em: Emoji = {
      e: x.emoji,
      name: x.label,
      v: x.version,
      tone: x.tone === undefined ? [] : typeof x.tone === "number" ? [x.tone] : x.tone,
      words,
    };
    byForm.set(em.e, em);
    byForm.set(wireForm(em.e), em);
    return em;
  };
  const groups: Group[] = GROUPS.map(([, key, name, icon]) => ({ key, name, icon, list: [] }));
  const at = new Map(GROUPS.map(([n], i) => [n, i]));
  for (const x of [...raw].sort((a, b) => (a.order ?? 0) - (b.order ?? 0))) {
    const i = x.group === undefined ? undefined : at.get(x.group);
    if (i === undefined) continue;
    const words = new Set(wordsOf(x.label));
    for (const t of x.tags ?? []) for (const w of [fold(t), ...wordsOf(t)]) words.add(w);
    const em = make(x, [...words]);
    if (x.skins?.length) em.skins = x.skins.map((s) => make(s, []));
    groups[i].list.push(em);
  }
  const probes = new Map<number, string>();
  for (const g of groups)
    for (const em of g.list)
      for (const x of [em, ...(em.skins ?? [])])
        if (x.v >= 11 && Number.isInteger(x.v) && [...x.e].length === 1 && !probes.has(x.v))
          probes.set(x.v, x.e);
  return { groups, byForm, probes: [...probes].sort((a, b) => b[0] - a[0]) };
}

let loading: Promise<EmojiSet> | undefined;
/**
 * The picker's emoji, fetched once, on first use (about 90 KB compressed). Fetched as data rather than imported as a
 * module, so that only the converted set stays in memory, not emojibase-data's whole list as well.
 */
export function loadEmoji(): Promise<EmojiSet> {
  loading ??= fetch(DATA_URL)
    .then((r) => {
      if (!r.ok) throw new Error(`emoji data: HTTP ${r.status}`);
      return r.json() as Promise<RawEmoji[]>;
    })
    .then(emojiSet, (e: unknown) => {
      loading = undefined;
      throw e;
    });
  return loading;
}

/**
 * Whether a device whose emoji font has the Emoji versions up to `max` draws `em`. The versions 12.1, 13.1 and 15.1
 * added only sequences, which fonts added with 12, 13 and 15.
 */
export const drawn = (em: Emoji, max: number): boolean => Math.floor(em.v) <= max;

/** `em` in skin tone `tone` (1 light … 5 dark, for all of its people), where it has that tone and the device draws it. */
export function toned(em: Emoji, tone: number, max: number): Emoji {
  if (!tone || !em.skins) return em;
  const s = em.skins.find((x) => x.tone.length > 0 && x.tone.every((t) => t === tone));
  return s && drawn(s, max) ? s : em;
}

/**
 * The emoji that a search finds, best first: an emoji typed or pasted into the search finds itself; words find the
 * emoji with a word of name or keywords starting with each of them, those whose name is the query, then those whose
 * name starts with it, then those with a word of the name starting with the first word.
 */
export function search(set: EmojiSet, query: string, max: number, limit = 200): Emoji[] {
  const q = query.trim();
  if (!q) return [];
  const exact = set.byForm.get(q);
  const fq = wordsOf(q).join(" ");
  const terms = wordsOf(q);
  const hits: [number, number, Emoji][] = [];
  let n = 0;
  for (const g of set.groups)
    for (const em of g.list) {
      n++;
      if (!drawn(em, max)) continue;
      if (exact && (exact === em || em.skins?.includes(exact))) {
        hits.push([0, n, exact]);
        continue;
      }
      if (!terms.length || !terms.every((t) => em.words.some((w) => w.startsWith(t)))) continue;
      const name = wordsOf(em.name);
      const joined = name.join(" ");
      const rank =
        joined === fq
          ? 1
          : joined.startsWith(fq)
            ? 2
            : name.some((w) => w.startsWith(terms[0]))
              ? 3
              : 4;
      hits.push([rank, n, em]);
    }
  return hits
    .sort((a, b) => a[0] - b[0] || a[1] - b[1])
    .slice(0, limit)
    .map((h) => h[2]);
}

/**
 * The "frequently used" row, as sent: self's picks of this session, newest first, then self's reactions in the
 * conversation, then `QUICK_DEFAULT`, without repeats.
 */
export function quickList(recent: string[], mine: string[], n = 16): string[] {
  return [...new Set([...recent, ...mine, ...QUICK_DEFAULT])].slice(0, n);
}
