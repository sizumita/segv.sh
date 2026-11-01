// Notifications of an app without push (docs/PROTOCOL.md §11.13 "Apps without push", §11.14 "Desktop"): while the app
// runs, also with its window closed, each TEXT or IMAGE row of another member that reaches it while it is not in use, in
// a copy whose bell its registration set would hold, gets the notification that the push handler would show for that
// copy with the device's preview, at most one per copy per PUSH_WINDOW. The app sends nothing for them. The system's
// notifications themselves are the app's (LocalNotifier); this module decides what they say and when.
import { plainText } from "./markdown";
import type { Preview } from "./notify-cache";
import type { EngineClock, EngineTimer } from "./options";
import { FIXED } from "./sw-core";

/** One notification, as the system shows it. */
export interface LocalNotification {
  /** what the system groups it under and replaces it by: the copy's ref, or the fixed `segv` */
  tag: string;
  title: string;
  body: string;
  /** the URL fragment that a click opens in the app: `#c/<ref>`, or "" for the start page */
  open: string;
}

export type LocalPermission = "granted" | "denied" | "default";

/** The system's notifications, supplied by the app. */
export interface LocalNotifier {
  permission(): Promise<LocalPermission>;
  /** Asks the user; called from the click that turns notifications on. */
  requestPermission(): Promise<LocalPermission>;
  /** Shows a notification, replacing a delivered one with the same tag. */
  show(n: LocalNotification): void;
  /** Removes the delivered notifications of a tag. */
  close(tag: string): void;
  /** Removes every delivered notification of the app (also those of an earlier run). */
  closeAll(): void;
  /** The app's badge: a count, or 0 for none. */
  badge(count: number): void;
}

/** Whether the device's notifications are on: its own setting, off by default and never synced (§11.13). */
export interface LocalStore {
  load(): boolean;
  save(on: boolean): void;
}

/** The setting in localStorage (storage that throws or is missing reads as off). */
export function localSettingStore(key = "segv.notify"): LocalStore {
  return {
    load() {
      try {
        return globalThis.localStorage?.getItem(key) === "on";
      } catch {
        return false;
      }
    },
    save(on) {
      try {
        globalThis.localStorage?.setItem(key, on ? "on" : "off");
      } catch {
        // blocked storage: the setting lasts for this page only
      }
    },
  };
}

/** A row that may notify: its copy's ref and shown name, the row, and how many rows of the copy are unread. */
export interface Arrival {
  ref: string;
  name: string;
  handle: string;
  /** the TEXT's text, or null for an IMAGE */
  text: string | null;
  unread: number;
}

/** PUSH_WINDOW (§9.8) when the deployment reports none. */
export const DEFAULT_WINDOW_MS = 60_000;
/** The body's length in characters (§11.13 step 3). */
const MAX_BODY = 200;

/** The notification of step 2 of §11.13 for a copy, with step 3's text when the preview is `message`. */
export function noteFor(a: Arrival, preview: Preview): LocalNotification {
  if (preview === "none") return { tag: FIXED.tag, title: FIXED.title, body: FIXED.body, open: "" };
  const open = `#c/${a.ref}`;
  if (preview === "name") return { tag: a.ref, title: a.name, body: FIXED.body, open };
  // As plain text: a notification can neither style nor hide, and a spoiler must not reach the lock screen.
  const who = `@${a.handle}`;
  const text = a.text === null ? `${who} sent an image` : `${who}: ${plainText(a.text)}`;
  const chars = Array.from(text);
  const cut = chars.length > MAX_BODY ? `${chars.slice(0, MAX_BODY - 1).join("")}…` : text;
  const more = Math.max(0, a.unread - 1);
  return { tag: a.ref, title: a.name, body: more > 0 ? `${cut} (+${more})` : cut, open };
}

export interface LocalNotifyOptions {
  notifier: LocalNotifier;
  store: LocalStore;
  clock: EngineClock;
  /** the device's preview (§11.13) */
  preview(): Preview;
  /** PUSH_WINDOW in ms */
  windowMs(): number;
  /** whether the device is in use (§11.13 "Seen elsewhere"): then nothing notifies */
  inUse(): boolean;
}

export class LocalNotify {
  private readonly o: LocalNotifyOptions;
  private enabled: boolean;
  /** per tag: when its last notification was shown (monotonic), and the one waiting for the window to end */
  private readonly tags = new Map<
    string,
    { last: number; next: LocalNotification | null; timer: EngineTimer | null }
  >();
  private lastBadge = -1;

  constructor(o: LocalNotifyOptions) {
    this.o = o;
    this.enabled = o.store.load();
  }

  get on(): boolean {
    return this.enabled;
  }

  /** Turns notifications on, asking for the system's permission (from the user's click). Resolves with whether they are on. */
  async enable(): Promise<boolean> {
    let p = await this.o.notifier.permission();
    if (p !== "granted") p = await this.o.notifier.requestPermission();
    this.enabled = p === "granted";
    this.o.store.save(this.enabled);
    return this.enabled;
  }

  /** At start: notifications stay on only while the system still allows them. */
  async check(): Promise<void> {
    if (!this.enabled) return;
    if ((await this.o.notifier.permission().catch(() => "default")) === "denied") {
      this.enabled = false;
      this.o.store.save(false);
    }
  }

  disable(): void {
    this.enabled = false;
    this.o.store.save(false);
    this.clearAll();
  }

  /** A row reached the device (§11.6): notify unless the device is in use, at most once per tag per PUSH_WINDOW. */
  arrived(a: Arrival): void {
    if (!this.enabled || this.o.inUse()) return;
    const note = noteFor(a, this.o.preview());
    const now = this.o.clock.mono();
    const t = this.tags.get(note.tag) ?? { last: -Infinity, next: null, timer: null };
    this.tags.set(note.tag, t);
    const due = t.last + this.o.windowMs();
    if (now >= due) {
      t.last = now;
      this.o.notifier.show(note);
      return;
    }
    // Within the window: the newest row waits for its end, and replaces the notification then.
    t.next = note;
    t.timer ??= this.o.clock.setTimer(() => {
      t.timer = null;
      const n = t.next;
      t.next = null;
      if (!n || !this.enabled) return;
      t.last = this.o.clock.mono();
      this.o.notifier.show(n);
    }, due - now);
  }

  /** The copy is shown on this device: its notifications close (§11.13 "Closing and the badge"). */
  shown(ref: string): void {
    const t = this.tags.get(ref);
    if (t) {
      t.timer?.cancel();
      t.timer = null;
      t.next = null;
    }
    this.o.notifier.close(ref);
  }

  /** The number of copies that count as unread (§11.13): set whenever it changes. */
  badge(count: number): void {
    if (count === this.lastBadge) return;
    this.lastBadge = count;
    this.o.notifier.badge(count);
  }

  /** `logout`, or notifications turned off: nothing waits, nothing stays on screen, no badge. */
  clearAll(): void {
    for (const t of this.tags.values()) t.timer?.cancel();
    this.tags.clear();
    this.o.notifier.closeAll();
  }

  stop(): void {
    this.clearAll();
    this.badge(0);
  }
}
