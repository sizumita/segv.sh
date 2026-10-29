import { $, component$, Slot, sync$, useContext, useSignal, type JSXOutput } from "@qwik.dev/core";
import { parse, type Block, type Inline, type ListBlock } from "~/client/markdown";
import { UiCtx } from "./state";

/** The text of a message, with its Markdown (src/client/markdown.ts) as elements. */
export const MsgText = component$<{ text: string }>((props) => (
  <div class="body">{parse(props.text).map(block)}</div>
));

function block(b: Block, k: number): JSXOutput {
  switch (b.t) {
    case "p":
      return <p key={k}>{b.c.map(inline)}</p>;
    // Not <h1>..<h3>: a message's headings are not headings of the page.
    case "h":
      return (
        <p key={k} class={`md-h${b.level}`}>
          {b.c.map(inline)}
        </p>
      );
    case "sub":
      return (
        <p key={k} class="md-sub">
          {b.c.map(inline)}
        </p>
      );
    case "quote":
      return <blockquote key={k}>{b.c.map(block)}</blockquote>;
    case "list":
      return list(b, k);
    case "pre":
      return (
        <pre key={k}>
          <code>{b.v}</code>
        </pre>
      );
  }
}

function list(b: ListBlock, k: number): JSXOutput {
  const items = b.items.map((it, j) => (
    <li key={j}>
      {it.c.map(inline)}
      {it.sub?.map(list)}
    </li>
  ));
  return b.ordered ? (
    <ol key={k} start={b.start}>
      {items}
    </ol>
  ) : (
    <ul key={k}>{items}</ul>
  );
}

function inline(n: Inline, k: number): JSXOutput {
  switch (n.t) {
    case "text":
      return n.v;
    case "b":
      return <strong key={k}>{n.c.map(inline)}</strong>;
    case "i":
      return <em key={k}>{n.c.map(inline)}</em>;
    case "u":
      return <u key={k}>{n.c.map(inline)}</u>;
    case "s":
      return <s key={k}>{n.c.map(inline)}</s>;
    case "code":
      return <code key={k}>{n.v}</code>;
    case "spoiler":
      return <Spoiler key={k}>{n.c.map(inline)}</Spoiler>;
    case "link":
      return n.masked ? (
        <MaskedLink key={k} href={n.href}>
          {n.c.map(inline)}
        </MaskedLink>
      ) : (
        <a key={k} href={n.href} target="_blank" rel="noopener noreferrer">
          {n.c.map(inline)}
        </a>
      );
  }
}

/** Hidden until clicked; while hidden its content is inert (no focus, no clicks, not read out). */
const Spoiler = component$(() => {
  const shown = useSignal(false);
  return (
    <span
      class={["spoiler", shown.value && "shown"]}
      role={shown.value ? undefined : "button"}
      tabIndex={shown.value ? undefined : 0}
      aria-label={shown.value ? undefined : "spoiler: show"}
      onClick$={() => (shown.value = true)}
      onKeyDown$={[
        // Space would also scroll the message list.
        sync$((e: KeyboardEvent, el: HTMLElement) => {
          if ((e.key === " " || e.key === "Enter") && !el.classList.contains("shown"))
            e.preventDefault();
        }),
        $((e: KeyboardEvent) => {
          if (e.key === " " || e.key === "Enter") shown.value = true;
        }),
      ]}
    >
      <span inert={!shown.value}>
        <Slot />
      </span>
    </span>
  );
});

/**
 * A [label](url) link: its label can say anything, so a click first shows where it goes (./leaving.tsx). The href
 * stays on the element, for the browser's own preview of it.
 */
const MaskedLink = component$<{ href: string }>((props) => {
  const ui = useContext(UiCtx);
  return (
    <a
      href={props.href}
      target="_blank"
      rel="noopener noreferrer"
      preventdefault:click
      onClick$={() => (ui.leaving = props.href)}
    >
      <Slot />
    </a>
  );
});
