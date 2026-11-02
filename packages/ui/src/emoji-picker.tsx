import {
  $,
  component$,
  noSerialize,
  sync$,
  useOnDocument,
  useSignal,
  useStore,
  useVisibleTask$,
  type NoSerialize,
  type QRL,
  type Signal,
} from "@qwik.dev/core";
import {
  drawn,
  loadEmoji,
  search,
  TABS,
  toned,
  wireForm,
  type Emoji,
  type EmojiSet,
} from "./emoji";
import { newestDrawn } from "./emoji-draw";
import { errMsg, MAX_REACTIONS } from "./util";

/** The button that opened the picker, in viewport pixels. */
export interface Anchor {
  top: number;
  bottom: number;
  left: number;
  right: number;
}

const TONES = ["", "🏻", "🏼", "🏽", "🏾", "🏿"];
const TONE_NAMES = [
  "no skin tone",
  "light skin tone",
  "medium-light skin tone",
  "medium skin tone",
  "medium-dark skin tone",
  "dark skin tone",
];
/** The skin tone that the picker shows its emoji in, on this device (1 light … 5 dark; absent: none). */
const TONE_KEY = "segv.skinTone";

function readTone(): number {
  try {
    const n = Number(localStorage.getItem(TONE_KEY));
    return Number.isInteger(n) && n >= 1 && n <= 5 ? n : 0;
  } catch {
    return 0;
  }
}

function saveTone(n: number): void {
  try {
    if (n) localStorage.setItem(TONE_KEY, String(n));
    else localStorage.removeItem(TONE_KEY);
  } catch {
    // storage off: the tone lasts until the page closes
  }
}

/** The picker opens on a click, so its tasks run once it is drawn, not once it scrolls into view. */
const DOC_READY = { strategy: "document-ready" } as const;

/** A long press on an emoji opens its skin tones where there is no right click (a touch screen). */
const press: { timer?: ReturnType<typeof setTimeout>; long: boolean } = { long: false };

/** Down from the search box goes to the first emoji, and enter picks it. */
const SEARCH_KEYS = sync$((e: KeyboardEvent, el: HTMLInputElement): void => {
  if (e.isComposing || e.keyCode === 229) return;
  const first = el.closest(".picker")?.querySelector<HTMLElement>(".egrid [data-e]");
  if (!first) return;
  if (e.key === "ArrowDown") {
    e.preventDefault();
    first.focus();
  } else if (e.key === "Enter" && el.value.trim()) {
    e.preventDefault();
    first.click();
  }
});

/** Arrow keys move between the emoji as they are laid out; up from the top row goes back to the search box. */
const GRID_KEYS = sync$((e: KeyboardEvent, box: HTMLElement): void => {
  const cur = e.target as HTMLElement;
  if (!cur.matches("[data-e]")) return;
  const all = Array.from(box.querySelectorAll<HTMLElement>("[data-e]"));
  const i = all.indexOf(cur);
  let next: HTMLElement | null | undefined;
  if (e.key === "ArrowLeft") next = all[i - 1];
  else if (e.key === "ArrowRight") next = all[i + 1];
  else if (e.key === "Home") next = all[0];
  else if (e.key === "End") next = all[all.length - 1];
  else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    const step = e.key === "ArrowDown" ? 1 : -1;
    let row: number | undefined;
    let dx = Infinity;
    for (let k = i + step; k >= 0 && k < all.length; k += step) {
      const b = all[k];
      if (b.offsetTop === cur.offsetTop && b.offsetParent === cur.offsetParent) continue;
      if (row === undefined) row = b.offsetTop;
      else if (b.offsetTop !== row) break;
      const d = Math.abs(b.offsetLeft - cur.offsetLeft);
      if (d < dx) {
        dx = d;
        next = b;
      }
    }
    if (!next && step < 0) next = box.closest(".picker")?.querySelector<HTMLElement>("input");
  } else return;
  e.preventDefault();
  next?.focus();
  next?.scrollIntoView({ block: "nearest" });
});

/**
 * The reaction picker (§11.12): every emoji that this device draws, by group or by search, in the skin tone chosen on
 * this device, with each emoji's other tones on a right click or a long press. A pick adds the emoji, or removes it
 * when self has it on; a shift-click keeps the picker open. Escape, or a click outside, closes it.
 */
export const EmojiPicker = component$<{
  anchor: Anchor;
  /** the emoji that self has on for the message, as sent */
  on: string[];
  /** the "frequently used" row, as sent */
  quick: string[];
  onPick$: QRL<(emoji: string, on: boolean) => void>;
  /** `refocus`: give the focus back to the message (escape, a pick), not on a click elsewhere */
  onClose$: QRL<(refocus: boolean) => void>;
}>((props) => {
  const box = useSignal<HTMLElement>();
  const input = useSignal<HTMLInputElement>();
  const grid = useSignal<HTMLElement>();
  const data = useStore<{ set: NoSerialize<EmojiSet>; max: number; error: string }>({
    set: undefined,
    max: Infinity,
    error: "",
  });
  const q = useSignal("");
  const tone = useSignal(0);
  const toneMenu = useSignal(false);
  /** the emoji whose skin tones are open ('' = none) */
  const variants = useSignal("");
  /** the emoji whose skin tones were open before, to give the focus back to */
  const last = useSignal("");
  /** the emoji under the pointer or the focus, named at the bottom */
  const preview = useSignal("");
  const note = useSignal("");
  /** the group in view, lit on its tab */
  const tab = useSignal("quick");
  /** the group to scroll to once it is drawn */
  const goto = useSignal("");

  useVisibleTask$(async () => {
    tone.value = readTone();
    try {
      const set = await loadEmoji();
      data.max = newestDrawn(set.probes);
      data.set = noSerialize(set);
    } catch (e) {
      data.error = errMsg(e);
    }
  }, DOC_READY);

  // Beside the button that opened it, below or else above, inside the window; a sheet at the bottom on a phone. It is
  // hidden until placed, and only then can the search box take the focus (not on a touch screen, where the keyboard
  // would cover the sheet).
  useVisibleTask$(({ track }) => {
    const a = track(() => props.anchor);
    const el = box.value;
    if (!el) return;
    if (matchMedia("(max-width: 720px)").matches) {
      el.style.removeProperty("left");
      el.style.removeProperty("top");
    } else {
      const m = 8;
      const w = el.offsetWidth;
      const h = el.offsetHeight;
      const left = Math.max(m, Math.min(a.right - w, innerWidth - w - m));
      const below = a.bottom + 4;
      const above = a.top - 4 - h;
      const top =
        below + h <= innerHeight - m
          ? below
          : above >= m
            ? above
            : Math.max(m, innerHeight - h - m);
      el.style.setProperty("left", `${left}px`);
      el.style.setProperty("top", `${top}px`);
    }
    const first = !el.hasAttribute("data-placed");
    el.setAttribute("data-placed", "");
    if (first && matchMedia("(hover: hover) and (pointer: fine)").matches) input.value?.focus();
  }, DOC_READY);

  useVisibleTask$(({ track }) => {
    const key = track(() => goto.value);
    track(() => q.value);
    track(() => data.set);
    const g = grid.value;
    const sec = key ? g?.querySelector<HTMLElement>(`[data-g="${key}"]`) : null;
    if (!g || !sec) return;
    g.scrollTop = sec.offsetTop;
    goto.value = "";
  }, DOC_READY);

  // The focus goes into the skin tones when they open, and back to their emoji when they close.
  useVisibleTask$(({ track }) => {
    const k = track(() => variants.value);
    const lost = !document.activeElement || document.activeElement === document.body;
    const sel = k ? ".evars [data-e]" : `.egrid [data-k="${CSS.escape(last.value)}"]`;
    if (k || (last.value && lost))
      box.value?.querySelector<HTMLElement>(sel)?.focus({ preventScroll: true });
    last.value = k;
  }, DOC_READY);

  useOnDocument(
    "keydown",
    $((e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      if (variants.value) variants.value = "";
      else if (toneMenu.value) toneMenu.value = false;
      else props.onClose$(true);
    }),
  );
  useOnDocument(
    "click",
    $((e: MouseEvent) => {
      const t = e.target as Element | null;
      // A click on something that the click itself took away (the tone menu) was inside.
      if (!t?.isConnected || t.closest(".picker, [data-react-open]")) return;
      props.onClose$(false);
    }),
  );

  const choose = $((e: string, keep: boolean) => {
    const w = wireForm(e);
    const on = props.on.includes(w);
    if (!on && props.on.length >= MAX_REACTIONS) {
      note.value = `at most ${MAX_REACTIONS} of your reactions on one message`;
      return;
    }
    note.value = "";
    void props.onPick$(w, !on);
    if (!keep) void props.onClose$(true);
  });

  const onGridClick = $((ev: MouseEvent) => {
    if (press.long) {
      press.long = false;
      return;
    }
    const e = (ev.target as Element).closest<HTMLElement>("[data-e]")?.dataset.e;
    if (e) void choose(e, ev.shiftKey);
  });
  const onGridMenu = $((ev: MouseEvent) => {
    const k = (ev.target as Element).closest<HTMLElement>("[data-k]")?.dataset.k;
    if (k) variants.value = k;
  });
  const onGridDown = $((ev: PointerEvent) => {
    clearTimeout(press.timer);
    press.long = false;
    const k = (ev.target as Element).closest<HTMLElement>("[data-k]")?.dataset.k;
    if (!k || ev.pointerType === "mouse") return;
    press.timer = setTimeout(() => {
      press.long = true;
      variants.value = k;
    }, 450);
  });
  const endPress = $(() => clearTimeout(press.timer));
  const onOver = $((ev: Event) => {
    const e = (ev.target as Element).closest<HTMLElement>("[data-e]")?.dataset.e;
    if (e && e !== preview.value) preview.value = e;
  });
  const onGridScroll = $((_: Event, g: HTMLElement) => {
    clearTimeout(press.timer);
    let cur = "";
    for (const sec of Array.from(g.querySelectorAll<HTMLElement>("[data-g]"))) {
      if (sec.offsetTop - 8 > g.scrollTop) break;
      cur = sec.dataset.g ?? "";
    }
    if (cur && cur !== tab.value) tab.value = cur;
  });
  // After a long press a touch screen may still send a click, to whatever now lies under the finger.
  const onVarsDown = $(() => {
    press.long = false;
  });
  const onVarsClick = $((ev: MouseEvent) => {
    if (press.long) {
      press.long = false;
      return;
    }
    const e = (ev.target as Element).closest<HTMLElement>("[data-e]")?.dataset.e;
    if (e) void choose(e, ev.shiftKey);
  });
  const go = $((key: string) => {
    q.value = "";
    variants.value = "";
    tab.value = key;
    goto.value = key;
  });
  const setTone = $((n: number) => {
    tone.value = n;
    toneMenu.value = false;
    saveTone(n);
  });

  const set = data.set;
  const base = variants.value ? set?.byForm.get(variants.value) : undefined;
  return (
    <>
      {/* The picker comes first: Qwik runs the visible tasks once the first element shows, and the backdrop shows on
          phones only. */}
      <div class="picker" ref={box} role="dialog" aria-label="add a reaction">
        <div class="phead">
          <input
            ref={input}
            type="text"
            placeholder="search emoji"
            aria-label="search emoji"
            autocomplete="off"
            spellcheck={false}
            enterKeyHint="search"
            bind:value={q}
            onKeyDown$={SEARCH_KEYS}
          />
          <div class="tonepick">
            <button
              type="button"
              class="ptool"
              title="skin tone"
              aria-label={`skin tone: ${TONE_NAMES[tone.value]}`}
              aria-expanded={toneMenu.value}
              onClick$={() => (toneMenu.value = !toneMenu.value)}
            >
              <span class="ej">✋{TONES[tone.value]}</span>
            </button>
            {toneMenu.value && (
              <div class="tones" role="group" aria-label="skin tone">
                {TONES.map((t, n) => (
                  <button
                    type="button"
                    key={n}
                    class={["ptool", n === tone.value && "on"]}
                    aria-label={TONE_NAMES[n]}
                    title={TONE_NAMES[n]}
                    aria-pressed={n === tone.value}
                    onClick$={() => setTone(n)}
                  >
                    <span class="ej">✋{t}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
        <Tabs tab={tab} onGo$={go} />
        <div
          class="egrid"
          ref={grid}
          preventdefault:contextmenu
          onClick$={onGridClick}
          onContextMenu$={onGridMenu}
          onPointerDown$={onGridDown}
          onPointerUp$={endPress}
          onPointerCancel$={endPress}
          onPointerOver$={onOver}
          onFocusIn$={onOver}
          onKeyDown$={GRID_KEYS}
          onScroll$={onGridScroll}
        >
          {data.error ? (
            <p class="pmsg">could not load the emoji: {data.error}</p>
          ) : (
            <Cells
              set={set}
              max={data.max}
              tone={tone.value}
              q={q.value}
              on={props.on}
              quick={props.quick}
            />
          )}
        </div>
        <Foot set={set} preview={preview} note={note} />
        {base && (
          <div
            class="evars"
            role="group"
            aria-label={`${base.name}: skin tones`}
            onPointerDown$={onVarsDown}
            onClick$={onVarsClick}
            onPointerOver$={onOver}
            onFocusIn$={onOver}
            onKeyDown$={GRID_KEYS}
          >
            <p class="evhead">
              <span>{base.name}</span>
              <button type="button" class="link" onClick$={() => (variants.value = "")}>
                back
              </button>
            </p>
            <Variants base={base} max={data.max} on={props.on} />
          </div>
        )}
      </div>
      <div class="picker-back" />
    </>
  );
});

/** One emoji to pick; `base` is the emoji whose skin tones a right click or a long press opens. */
function cell(em: Emoji, on: Set<string>, first: boolean, base: Emoji = em) {
  const isOn = on.has(wireForm(em.e));
  return (
    <button
      type="button"
      key={em.e}
      class={isOn ? "eb on" : "eb"}
      data-e={em.e}
      data-k={base.skins ? base.e : undefined}
      aria-label={em.name}
      aria-pressed={isOn || undefined}
      tabIndex={first ? 0 : -1}
    >
      {em.e}
    </button>
  );
}

/** The emoji: the search's results, or the "frequently used" row and every group. */
const Cells = component$<{
  set: NoSerialize<EmojiSet>;
  max: number;
  tone: number;
  q: string;
  on: string[];
  quick: string[];
}>((props) => {
  const set = props.set;
  if (!set) return <p class="pmsg dim">loading emoji…</p>;
  const on = new Set(props.on);
  const { max, tone } = props;
  let first = true;
  const at = (em: Emoji, base?: Emoji) => {
    const b = cell(em, on, first, base);
    first = false;
    return b;
  };
  if (props.q.trim()) {
    const found = search(set, props.q, max);
    if (!found.length) return <p class="pmsg dim">no emoji found</p>;
    return (
      <section data-g="search">
        <h3>search results</h3>
        <div class="ecells">{found.map((em) => at(toned(em, tone, max), em))}</div>
      </section>
    );
  }
  const quick = props.quick
    .map((e) => set.byForm.get(e))
    .filter((em): em is Emoji => !!em && drawn(em, max));
  return (
    <>
      <section data-g="quick">
        <h3>frequently used</h3>
        <div class="ecells">{quick.map((em) => at(em))}</div>
      </section>
      {set.groups.map((g) => (
        <section key={g.key} data-g={g.key}>
          <h3>{g.name}</h3>
          <div class="ecells">
            {g.list.filter((em) => drawn(em, max)).map((em) => at(toned(em, tone, max), em))}
          </div>
        </section>
      ))}
    </>
  );
});

/** An emoji without a tone, then its skin tones: one row, or, for two people, a row per tone of the first. */
const Variants = component$<{ base: Emoji; max: number; on: string[] }>((props) => {
  const on = new Set(props.on);
  const rank = (x: Emoji) => x.tone[0] * 10 + (x.tone[1] ?? x.tone[0]);
  const skins = (props.base.skins ?? [])
    .filter((x) => drawn(x, props.max))
    .sort((a, b) => rank(a) - rank(b));
  return (
    <div class="evcells">
      {cell(props.base, on, true)}
      {skins.map((x) => cell(x, on, false))}
    </div>
  );
});

const Tabs = component$<{ tab: Signal<string>; onGo$: QRL<(key: string) => void> }>((props) => (
  <nav class="etabs" aria-label="emoji groups">
    {TABS.map((t) => (
      <button
        type="button"
        key={t.key}
        class={["ptool", props.tab.value === t.key && "on"]}
        aria-label={t.name}
        title={t.name}
        aria-current={props.tab.value === t.key || undefined}
        onClick$={() => props.onGo$(t.key)}
      >
        <span class="ej">{t.icon}</span>
      </button>
    ))}
  </nav>
));

/** The emoji under the pointer or the focus with its name, or why a pick did nothing. */
const Foot = component$<{
  set: NoSerialize<EmojiSet>;
  preview: Signal<string>;
  note: Signal<string>;
}>((props) => {
  const em = props.preview.value ? props.set?.byForm.get(props.preview.value) : undefined;
  return (
    <div class="efoot">
      <p class="enote" role="status">
        {props.note.value}
      </p>
      {!props.note.value &&
        (em ? (
          <p class="eprev">
            <span class="ej">{em.e}</span>
            <span class="ename">
              {em.name}
              {em.skins && <span class="dim"> · right-click or hold for skin tones</span>}
            </span>
          </p>
        ) : (
          <p class="eprev dim">shift-click to pick more than one</p>
        ))}
    </div>
  );
});
