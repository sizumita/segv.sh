import {
  $,
  component$,
  sync$,
  useContext,
  useId,
  useSignal,
  useVisibleTask$,
} from "@qwik.dev/core";
import type { EngineState, IdentityView, PersonView } from "@segv/engine/types";
import { Errors } from "./errors";
import { showChat } from "./route";
import { StateCtx, UiCtx } from "./state";
import {
  act,
  addChips,
  ALIAS_CAP,
  atAliasCap,
  byNickname,
  identitiesOf,
  makeAlias,
  MAX_NAME,
  namesExactly,
  nameWithHandle,
  runs,
  startsNickname,
  suggest,
} from "./util";

/** What ends a handle in the "people" box: white space, commas (、 and ， from Japanese IMEs) and semicolons. */
const SEPARATOR = /[\s,、;]/;

/**
 * The accounts that can start a conversation (the owner and its live temporary handles, §2.6) and the one shown as
 * chosen: the last one used while it is still live, else the owner. Starting never falls back to the owner: see
 * `stopped`.
 */
function accounts(state: EngineState, startAs: string) {
  const all = identitiesOf(state);
  const live = all.filter(runs);
  const as = live.find((i) => i.uid === startAs) ?? live.find((i) => !i.alias) ?? live[0];
  // the user's other handles, which are never invited (§2.6)
  const own = all.map((i) => i.handle).filter((h) => h && h !== as?.handle);
  return { all, live, as, own };
}

/** The temporary handle chosen (`ui.startAs`) no longer runs here: retired, failed or idle since (§2.6). */
const stopped = (state: EngineState, startAs: string) =>
  startAs !== "" && !identitiesOf(state).some((i) => runs(i) && i.uid === startAs);

/** The suggestions for what is typed: never someone already added, nor one of the user's own accounts. */
const optionsFor = (state: EngineState, as: IdentityView, typed: string, chips: string[]) =>
  suggest(state.people, typed, as.uid, [...chips, ...identitiesOf(state).map((i) => i.handle)]);

/** A key of the "people" box to act on, with what the box held when it was pressed (more may be typed since). */
type Act = { act: "add" | "down" | "up" | "close" | "pop"; typed: string };
type PeopleBox = HTMLInputElement & { _acts?: Act[]; _acting?: boolean };

/**
 * Keys of the "people" box that are decided while the event is dispatched, since only a synchronous handler can stop
 * the browser's own action: Enter and Tab add the highlighted suggestion or what is typed (Enter with neither sends the
 * form), the arrows move through the suggestions, Escape closes them and not the dialog, and Backspace in the empty
 * box takes the last person off. They queue up on the box, in order, for the handler after it.
 */
const PEOPLE_KEYS = sync$((e: KeyboardEvent, el: HTMLInputElement): void => {
  if (e.isComposing || e.keyCode === 229 || e.altKey || e.ctrlKey || e.metaKey) return;
  const some = el.value.trim() !== "" || el.hasAttribute("aria-activedescendant");
  let act = "";
  if (e.key === "Enter" || (e.key === "Tab" && !e.shiftKey)) act = some ? "add" : "";
  else if (e.key === "ArrowDown") act = "down";
  else if (e.key === "ArrowUp") act = "up";
  else if (e.key === "Escape") act = el.getAttribute("aria-expanded") === "true" ? "close" : "";
  else if (e.key === "Backspace" && el.value === "") act = "pop";
  if (!act) return;
  if (act !== "pop") e.preventDefault();
  const box = el as HTMLInputElement & { _acts?: { act: string; typed: string }[] };
  (box._acts ??= []).push({ act, typed: el.value });
});

/** A tap or click on a suggestion keeps the focus in the box. */
const KEEP_FOCUS = sync$((e: Event): void => e.preventDefault());

/**
 * The "new conversation" dialog: who starts it (the owner or one of its temporary handles, §2.6), with whom (a box of
 * handles with suggestions from the people the user's accounts know, by handle or nickname, §11.19), and a group's
 * name. A modal <dialog> like the settings: every way of closing clears `ui.newChat`. A conversation that is still
 * starting when the dialog closes opens once it has started.
 */
export const NewChat = component$(() => {
  const state = useContext(StateCtx);
  const ui = useContext(UiCtx);
  const dlg = useSignal<HTMLDialogElement>();
  const inp = useSignal<HTMLInputElement>();
  /** the handles added, in order */
  const chips = useSignal<string[]>([]);
  /** what is typed in the "people" box (mirrors its value) */
  const text = useSignal("");
  /** why something typed was not added */
  const error = useSignal("");
  /** why the conversation cannot start as the account chosen */
  const asError = useSignal("");
  const name = useSignal("");
  const nameError = useSignal("");
  /** the suggestions are open, and the one highlighted (-1 = none) */
  const open = useSignal(false);
  const active = useSignal(-1);
  const busy = useSignal(false);
  const id = useId();
  const ids = {
    title: `nc-title-${id}`,
    people: `nc-people-${id}`,
    list: `nc-list-${id}`,
    hint: `nc-hint-${id}`,
    note: `nc-note-${id}`,
    err: `nc-err-${id}`,
    asErr: `nc-as-err-${id}`,
    name: `nc-name-${id}`,
    radio: `nc-as-${id}`,
  };

  useVisibleTask$(
    ({ cleanup }) => {
      // a temporary handle chosen last time that has stopped running since: the owner is shown as chosen
      if (stopped(state, ui.startAs)) ui.startAs = "";
      const d = dlg.value;
      if (!d) return;
      const onClose = () => (ui.newChat = false);
      d.addEventListener("close", onClose);
      if (!d.open) d.showModal();
      // never on a touch screen, where it would bring up the keyboard over the dialog
      if (matchMedia("(hover: hover) and (pointer: fine)").matches) inp.value?.focus();
      cleanup(() => d.removeEventListener("close", onClose));
    },
    { strategy: "document-ready" },
  );

  /**
   * Adds what `raw` names (a nickname whole, §11.19, else handles), and takes `typed` off the start of the box: what
   * was typed since stays, and so does what could not be added.
   */
  const commit = $((raw: string, typed: string) => {
    const { as, own } = accounts(state, ui.startAs);
    if (!as) return;
    const r = addChips(chips.value, byNickname(state.people, raw) ?? raw, as.handle, own);
    chips.value = r.chips;
    error.value = r.error;
    open.value = false;
    active.value = -1;
    const el = inp.value;
    const now = el?.value ?? "";
    // the box changed some other way meanwhile: it is left as it is
    if (!now.startsWith(typed)) return;
    const v = [r.rest, now.slice(typed.length).trimStart()].filter(Boolean).join(" ");
    if (el && el.value !== v) el.value = v;
    text.value = v;
  });

  /**
   * What was typed or pasted: a paste is added whole; a separator typed after a handle adds what comes before it,
   * unless it may belong to a nickname being typed ("mom " of "mom smith").
   */
  const took = $(async (el: HTMLInputElement, paste: boolean) => {
    const v = el.value;
    text.value = v;
    error.value = "";
    if (paste) return commit(v, v);
    if (!SEPARATOR.test(v.normalize("NFKC")) || startsNickname(state.people, v)) {
      open.value = v.trim() !== "";
      const { as } = accounts(state, ui.startAs);
      const first = as ? optionsFor(state, as, v, chips.value)[0] : undefined;
      // what is typed names someone exactly: Enter adds them
      active.value = first && namesExactly(first, v) ? 0 : -1;
      return;
    }
    const cut = lastSeparator(v);
    await commit(v.slice(0, cut), v.slice(0, cut + 1));
  });

  /** Adds a suggestion, in place of what was typed for it. */
  const pick = $((p: PersonView, typed = inp.value?.value ?? "") => commit(p.handle, typed));

  /** Acts on the keys queued on the box, one at a time and in order, however fast they came. */
  const onKey = $(async (_: KeyboardEvent, el: HTMLInputElement) => {
    const box = el as PeopleBox;
    if (box._acting) return;
    box._acting = true;
    try {
      // what an earlier "add" took off the start of the box, which later keys still saw there
      let gone = "";
      for (let a = box._acts?.shift(); a; a = box._acts?.shift()) {
        const typed =
          gone && a.typed.startsWith(gone) ? a.typed.slice(gone.length).trimStart() : a.typed;
        const { as } = accounts(state, ui.startAs);
        if (!as) return;
        const opts = optionsFor(state, as, typed, chips.value);
        if (a.act === "pop") {
          chips.value = chips.value.slice(0, -1);
          error.value = "";
        } else if (a.act === "close") {
          open.value = false;
          active.value = -1;
        } else if (a.act === "down" || a.act === "up") {
          // round the suggestions and what is typed (-1): down from the last one, or up from the first, is back to it
          const n = opts.length;
          if (!n) continue;
          const down = a.act === "down";
          if (!open.value) active.value = down ? 0 : n - 1;
          else active.value = ((active.value + 1 + (down ? 1 : n)) % (n + 1)) - 1;
          open.value = true;
        } else if (a.act === "add") {
          const p = open.value && active.value >= 0 ? opts[active.value] : undefined;
          await (p ? pick(p, typed) : commit(typed, typed));
          gone = a.typed;
        }
      }
    } finally {
      box._acting = false;
    }
  });

  const start = $(async () => {
    if (busy.value || ui.makingAlias) return;
    // Never as another account than the one chosen (§2.6): a temporary handle that stopped running while the dialog
    // was open is not swapped for the owner. The owner is shown as chosen after this, for the user to confirm.
    if (stopped(state, ui.startAs)) {
      ui.startAs = "";
      asError.value = "that temporary handle is no longer active here; choose who to start as";
      return;
    }
    const want = ui.startAs;
    const typed = inp.value?.value ?? "";
    if (typed.trim()) {
      const before = chips.value.length;
      await commit(typed, typed);
      if (error.value) return;
      // Text that does not plainly name someone (a whole nickname, or the handle of someone known) only becomes
      // chips: the user sees who it is with ("1:1 with @mom") before starting.
      const known = new Set(state.people.map((p) => p.handle));
      const added = chips.value.slice(before);
      if (byNickname(state.people, typed) === undefined && added.some((h) => !known.has(h))) return;
    }
    if (!chips.value.length) {
      error.value = "add someone to talk to";
      inp.value?.focus();
      return;
    }
    const group = chips.value.length > 1;
    const n = group ? name.value.trim() : "";
    if ([...n].length > MAX_NAME) {
      nameError.value = `group name: at most ${MAX_NAME} characters`;
      return;
    }
    const { as } = accounts(state, ui.startAs);
    if (!as) return;
    busy.value = true;
    const handles = [...chips.value];
    // the account chosen itself: the engine refuses one that has stopped since, rather than starting as another
    const convId = await act(ui, (e) =>
      e.createConversation(handles, n || undefined, want || undefined),
    );
    busy.value = false;
    if (!convId) return;
    // Closed by now if the user closed it while it started: the conversation opens all the same. A dialog opened since
    // then is another one, and left alone: its input, and the account chosen in it, stay.
    const d = dlg.value;
    const mine = d?.isConnected === true;
    if (mine || !ui.newChat) ui.startAs = want;
    if (d && mine) {
      if (d.open) d.close();
      ui.newChat = false;
    }
    const c = state.conversations.find((x) => x.id === convId);
    if (c) showChat(ui, c);
    else {
      ui.wanted = "";
      ui.active = convId;
      ui.list = "chats";
      ui.members = false;
    }
  });

  const { all, live, as } = accounts(state, ui.startAs);
  if (!as) return null;
  const owner = all.find((i) => !i.alias) ?? as;
  const opts = optionsFor(state, as, text.value, chips.value);
  const shown = open.value && opts.length > 0;
  const act0 = shown && active.value >= 0 && active.value < opts.length ? active.value : -1;
  const nick = (h: string) => state.people.find((p) => p.handle === h)?.nickname ?? "";
  const making = ui.makingAlias;
  const capped = !making && atAliasCap(all);
  const group = chips.value.length > 1;
  const first = chips.value[0];
  return (
    <dialog
      ref={dlg}
      class="newchat"
      aria-labelledby={ids.title}
      // A click on the backdrop lands on the <dialog> itself; the sheet inside covers the rest.
      onClick$={(e, el) => {
        if (e.target === el) el.close();
      }}
    >
      <form class="sheet" preventdefault:submit onSubmit$={start} aria-busy={busy.value}>
        <header class="nc-head">
          <h2 id={ids.title}>new conversation</h2>
          <button
            type="button"
            class="xbtn"
            aria-label="close"
            title="close (esc)"
            onClick$={() => dlg.value?.close()}
          >
            ×
          </button>
        </header>

        <div class="nc-body">
          <Errors />

          <fieldset
            class="nc-as"
            disabled={busy.value}
            aria-describedby={asError.value ? ids.asErr : undefined}
          >
            <legend class="nc-label">start as</legend>
            <div class="idcards">
              {live.map((i) => (
                <label key={i.uid} class={["idcard", i.uid === as.uid && "on"]}>
                  <input
                    type="radio"
                    class="vh"
                    name={ids.radio}
                    value={i.uid}
                    checked={i.uid === as.uid}
                    onChange$={() => {
                      ui.startAs = i.alias ? i.uid : "";
                      error.value = "";
                      asError.value = "";
                    }}
                  />
                  <span class="idmark" aria-hidden="true" />
                  <span class="idtext">
                    <span class="idhandle">@{i.handle || "…"}</span>
                    <span class="idtag">
                      {i.alias
                        ? i.status === "starting"
                          ? "temporary · starting…"
                          : "temporary"
                        : "main"}
                    </span>
                  </span>
                </label>
              ))}
            </div>
            <button
              type="button"
              class="idcard idnew"
              disabled={making || capped}
              aria-busy={making}
              aria-describedby={ids.note}
              onClick$={async () => {
                const uid = await makeAlias(ui);
                if (uid) {
                  ui.startAs = uid;
                  asError.value = "";
                }
              }}
            >
              <span class="idplus" aria-hidden="true">
                +
              </span>
              <span class="idtext">
                <span>{making ? "making a handle…" : "new temporary handle"}</span>
                <span class="idtag">
                  {making ? "a few seconds" : capped ? "retire one first" : "a random name"}
                </span>
              </span>
            </button>
            <p class="nc-hint small" id={ids.hint}>
              {as.alias ? (
                <>
                  people you invite see only <b>@{as.handle || "…"}</b>, never {`@${owner.handle}`}.
                </>
              ) : (
                <>
                  people you invite see your handle <b>@{as.handle}</b>.
                </>
              )}{" "}
              <button
                type="button"
                class="link"
                aria-haspopup="dialog"
                onClick$={() => (ui.settings = true)}
              >
                manage temporary handles
              </button>
            </p>
            <p class="nc-note small" id={ids.note}>
              {capped
                ? `${ALIAS_CAP}.`
                : "when a handle is made is public: handles made close together, or soon after you signed up, can be linked by that time."}
            </p>
            {asError.value && (
              <p class="nc-err small" id={ids.asErr} role="alert">
                {asError.value}
              </p>
            )}
          </fieldset>

          <div class="nc-field">
            <label class="nc-label" for={ids.people}>
              with
            </label>
            <div
              class={["chipbox", busy.value && "off"]}
              onClick$={(e, el) => {
                if (e.target === el) inp.value?.focus();
              }}
            >
              {chips.value.length > 0 && (
                <ul class="chips" role="list" aria-label="people added">
                  {chips.value.map((h) => {
                    const n = nick(h);
                    return (
                      <li key={h} class="chip">
                        {n ? (
                          <span title={`@${h}`}>
                            <b>{n}</b> <span class="dim">@{h}</span>
                          </span>
                        ) : (
                          <span>@{h}</span>
                        )}
                        <button
                          type="button"
                          class="chipx"
                          aria-label={`remove @${h}`}
                          title="remove"
                          disabled={busy.value}
                          onClick$={() => {
                            chips.value = chips.value.filter((x) => x !== h);
                            error.value = "";
                            if (matchMedia("(hover: hover) and (pointer: fine)").matches)
                              inp.value?.focus();
                          }}
                        >
                          ×
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
              <input
                ref={inp}
                id={ids.people}
                type="text"
                role="combobox"
                aria-label="people"
                aria-autocomplete="list"
                aria-expanded={shown}
                aria-controls={ids.list}
                aria-activedescendant={act0 >= 0 ? `${ids.list}-${act0}` : undefined}
                aria-describedby={error.value ? ids.err : undefined}
                aria-invalid={error.value ? true : undefined}
                placeholder={chips.value.length ? "add someone else" : "a handle or a nickname"}
                autocapitalize="none"
                autocomplete="off"
                spellcheck={false}
                maxLength={2000}
                value={text.value}
                disabled={busy.value}
                onKeyDown$={[PEOPLE_KEYS, onKey]}
                onInput$={(e: InputEvent, el: HTMLInputElement) => {
                  if (e.isComposing) {
                    text.value = el.value;
                    return;
                  }
                  return took(
                    el,
                    e.inputType === "insertFromPaste" || e.inputType === "insertFromDrop",
                  );
                }}
                onCompositionEnd$={(_, el: HTMLInputElement) => took(el, false)}
                onClick$={() => {
                  open.value = true;
                }}
                onBlur$={() => {
                  open.value = false;
                  active.value = -1;
                }}
              />
            </div>
            <ul
              id={ids.list}
              class="suggest"
              role="listbox"
              aria-label="suggestions"
              hidden={!shown}
              onMouseDown$={KEEP_FOCUS}
            >
              {shown &&
                opts.map((p, i) => (
                  <li
                    key={p.uid}
                    id={`${ids.list}-${i}`}
                    role="option"
                    aria-selected={i === act0}
                    class={["sopt", i === act0 && "on"]}
                    onClick$={() => pick(p)}
                  >
                    {p.nickname ? (
                      <>
                        <b>{p.nickname}</b> <span class="dim">@{p.handle}</span>
                      </>
                    ) : (
                      <b>@{p.handle}</b>
                    )}
                    {p.contactOf.includes(as.uid) && <span class="stag">contact</span>}
                  </li>
                ))}
            </ul>
            {error.value && (
              <p class="nc-err small" id={ids.err} role="alert">
                {error.value}
              </p>
            )}
          </div>

          {group && (
            <div class="nc-field">
              <label class="nc-label" for={ids.name}>
                group name <span class="dim">(optional)</span>
              </label>
              <input
                id={ids.name}
                type="text"
                autocomplete="off"
                placeholder="what is it about?"
                maxLength={MAX_NAME * 2}
                value={name.value}
                disabled={busy.value}
                aria-invalid={nameError.value ? true : undefined}
                onInput$={(_, el: HTMLInputElement) => {
                  name.value = el.value;
                  nameError.value = "";
                }}
              />
              {nameError.value && (
                <p class="nc-err small" role="alert">
                  {nameError.value}
                </p>
              )}
            </div>
          )}
        </div>

        <footer class="nc-foot">
          <div class="nc-sum">
            <p aria-live="polite">
              {!first ? (
                <span class="dim">add someone by handle, or pick a suggestion.</span>
              ) : (
                <>
                  {group ? (
                    `a group of ${chips.value.length + 1}`
                  ) : (
                    <>
                      1:1 with <b>{nameWithHandle(first, nick(first))}</b>
                    </>
                  )}
                  , as <b>@{as.handle || "…"}</b>
                </>
              )}
            </p>
            {(busy.value || making) && state.progress && (
              <p class="small dim" role="status">
                {state.progress}
              </p>
            )}
          </div>
          <div class="nc-actions">
            <button type="button" class="link" onClick$={() => dlg.value?.close()}>
              cancel
            </button>
            <button
              type="submit"
              class="go"
              disabled={busy.value || making || (!chips.value.length && !text.value.trim())}
            >
              {busy.value ? "starting…" : "start"}
            </button>
          </div>
        </footer>
      </form>
    </dialog>
  );
});

/** The index of the last separator in `v` (-1 for none). */
function lastSeparator(v: string): number {
  for (let i = v.length - 1; i >= 0; i--) if (SEPARATOR.test(v[i].normalize("NFKC"))) return i;
  return -1;
}
