// The engine's states as the UI's store holds them (app.tsx): copies that never share an object with the engine, and
// that keep what they copied before for whatever did not change, so that the UI renders only what changed. Every
// object handed to the UI's components outlives the render that used it (Qwik keeps the signals of a render), so a
// fresh copy of every conversation on every change would keep piling up. The engine replaces a message's object when
// the message changes (engine/src/conv.ts), which lets a message's copy be found by the engine's object.
import type { ConversationView, EngineState, MessageView } from "@segv/engine/types";

function copy<T>(x: T): T {
  try {
    return structuredClone(x);
  } catch {
    return JSON.parse(JSON.stringify(x)) as T;
  }
}

/** Equal as data (small values only: everything but a conversation's messages). */
const same = (a: unknown, b: unknown): boolean =>
  a === b || JSON.stringify(a) === JSON.stringify(b);

const sameItems = <T>(a: readonly T[], b: readonly T[]): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * A copy of the fields of `next`, each one the same object as in `prev` when it did not change; `prev` itself when no
 * field changed.
 */
function merge<T extends object>(prev: T | null, next: T, skip?: keyof T): T {
  const out = {} as Record<string, unknown>;
  let changed = !prev || Object.keys(prev).length !== Object.keys(next).length;
  for (const k of Object.keys(next) as (keyof T & string)[]) {
    if (k === skip) continue;
    if (prev && same(prev[k], next[k])) out[k] = prev[k];
    else {
      out[k] = copy(next[k]);
      changed = true;
    }
  }
  return changed || !prev ? (out as T) : prev;
}

export class StateCopier {
  private prev: EngineState | null = null;
  private convs = new Map<string, ConversationView>();
  /** the copy of each of the engine's message objects */
  private readonly msgs = new WeakMap<MessageView, MessageView>();

  /** The UI's copy of `s`: what did not change since the last one is the same object as in it. */
  copy(s: EngineState): EngineState {
    const convs = s.conversations.map((c) => this.conv(c));
    const conversations =
      this.prev && sameItems(this.prev.conversations, convs) ? this.prev.conversations : convs;
    const rest = merge(this.prev, s, "conversations");
    const out =
      this.prev && rest === this.prev && conversations === this.prev.conversations
        ? this.prev
        : { ...rest, conversations };
    this.convs = new Map(convs.map((c) => [c.id, c]));
    this.prev = out;
    return out;
  }

  private conv(c: ConversationView): ConversationView {
    const messages = c.messages.map((m) => this.msg(m));
    const old = this.convs.get(c.id) ?? null;
    const rest = merge(old, c, "messages");
    const sameMessages = !!old && sameItems(old.messages, messages);
    if (old && rest === old && sameMessages) return old;
    return { ...rest, messages: sameMessages ? old!.messages : messages };
  }

  private msg(m: MessageView): MessageView {
    let x = this.msgs.get(m);
    if (!x) this.msgs.set(m, (x = copy(m)));
    return x;
  }
}
