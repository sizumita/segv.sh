/**
 * Web Push in the engine tests (docs/PROTOCOL.md §9.8, §10.10, §11.13).
 *
 * - FakePush is the server side, reduced to what the engine can observe: `push/sub` replaces an endpoint's bells and
 *   quiet tag, a `ring` of a fresh row "pushes" to every endpoint registered under one of its bells, and `seen` marks
 *   rows for the endpoints of the account whose quiet tag hashes from its secret (the windows, jitter, dedup and
 *   storage of the real PushDO are tested in packages/server/test/push.spec.ts). With `holdMs` set, a push to an
 *   endpoint with a quiet tag waits that long (real time) and a mark of its row cancels it, as PUSH_HOLD does;
 *   otherwise pushes are immediate. A push to an ended subscription is refused (410) and deletes it, as the real push
 *   services and PushDO do.
 * - FakePushDevice is a browser's side: the notification permission and a PushManager with one subscription.
 */
import type {
  PushManagerLike,
  PushPlatform,
  PushSetting,
  PushStore,
  PushSubscriptionLike,
} from "../../src/push";
import { b64u, fromB64u, quietTag, random } from "@segv/protocol/proto";

type Bytes = Uint8Array;

/** The VAPID public key the fake server reports (any uncompressed point works for the client). */
export const FAKE_VAPID: Bytes = Uint8Array.of(4, ...random(64));

export type PushCall =
  | { kind: "sub"; endpoint: string; tokens: string[]; quiet: string | null }
  | { kind: "ring"; E: number; label: string; tokens: string[] }
  | { kind: "seen"; quiet: string; rows: { E: number; label: string }[] };

export class FakePush {
  /** registered endpoints and their bells (b64u) */
  readonly subs = new Map<string, Set<string>>();
  readonly calls: PushCall[] = [];
  /** the pushes sent: the endpoint, and the row whose ring caused it */
  readonly pushes: { endpoint: string; E: number; label: string }[] = [];
  /** endpoints whose subscriptions have ended: their push services refuse every push */
  readonly ended = new Set<string>();
  /** registered quiet tags (b64u) by endpoint */
  readonly quiet = new Map<string, string>();
  /** rows marked seen: `${tag} ${E} ${label}` */
  readonly marks = new Set<string>();
  /** how long a push to an endpoint with a quiet tag waits for a mark (real ms); 0: no wait */
  holdMs = 0;
  private readonly held: {
    endpoint: string;
    E: number;
    label: string;
    timer: ReturnType<typeof setTimeout>;
  }[] = [];

  sub(endpoint: string, tokens: string[], quiet: string | null = null): void {
    this.calls.push({ kind: "sub", endpoint, tokens, quiet });
    this.quiet.delete(endpoint);
    if (tokens.length === 0) this.subs.delete(endpoint);
    else {
      this.subs.set(endpoint, new Set(tokens));
      if (quiet) this.quiet.set(endpoint, quiet);
    }
  }

  /** `seen` with the account's secret: the Worker hashes it into the quiet tag (§10.10). */
  seen(qS: Bytes, rows: { E: number; label: Bytes }[]): void {
    const tag = b64u(quietTag(qS));
    this.calls.push({
      kind: "seen",
      quiet: tag,
      rows: rows.map((r) => ({ E: r.E, label: b64u(r.label) })),
    });
    for (const r of rows) {
      const label = b64u(r.label);
      this.marks.add(`${tag} ${r.E} ${label}`);
      for (let i = this.held.length - 1; i >= 0; i--) {
        const h = this.held[i];
        if (h.E !== r.E || h.label !== label || this.quiet.get(h.endpoint) !== tag) continue;
        clearTimeout(h.timer);
        this.held.splice(i, 1);
      }
    }
  }

  seens(): Extract<PushCall, { kind: "seen" }>[] {
    return this.calls.filter((c): c is Extract<PushCall, { kind: "seen" }> => c.kind === "seen");
  }

  ring(E: number, label: Bytes, tokens: Bytes[], fresh: boolean): void {
    const ts = tokens.map(b64u);
    this.calls.push({ kind: "ring", E, label: b64u(label), tokens: ts });
    if (!fresh) return;
    const l = b64u(label);
    for (const [endpoint, bells] of this.subs) {
      if (!ts.some((t) => bells.has(t))) continue;
      const tag = this.quiet.get(endpoint);
      if (tag && this.marks.has(`${tag} ${E} ${l}`)) continue;
      if (tag && this.holdMs > 0) {
        const h = {
          endpoint,
          E,
          label: l,
          timer: setTimeout(() => {
            this.held.splice(this.held.indexOf(h), 1);
            this.deliver(endpoint, E, l);
          }, this.holdMs),
        };
        this.held.push(h);
        continue;
      }
      this.deliver(endpoint, E, l);
    }
  }

  private deliver(endpoint: string, E: number, label: string): void {
    if (this.ended.has(endpoint)) {
      this.subs.delete(endpoint); // a 410 deletes the endpoint (§9.8)
      return;
    }
    this.pushes.push({ endpoint, E, label });
  }

  rings(): Extract<PushCall, { kind: "ring" }>[] {
    return this.calls.filter((c): c is Extract<PushCall, { kind: "ring" }> => c.kind === "ring");
  }

  subsOf(endpoint: string): Extract<PushCall, { kind: "sub" }>[] {
    return this.calls.filter(
      (c): c is Extract<PushCall, { kind: "sub" }> => c.kind === "sub" && c.endpoint === endpoint,
    );
  }
}

class FakeSubscription implements PushSubscriptionLike {
  readonly p256dh = Uint8Array.of(4, ...random(64));
  readonly auth = random(16);
  ended = false;
  constructor(
    readonly endpoint: string,
    private readonly key: Bytes,
    private readonly device: FakePushDevice,
  ) {}
  get options() {
    return { applicationServerKey: this.key.slice().buffer as ArrayBuffer };
  }
  getKey(name: "p256dh" | "auth"): ArrayBuffer {
    return (name === "p256dh" ? this.p256dh : this.auth).slice().buffer as ArrayBuffer;
  }
  async unsubscribe(): Promise<boolean> {
    this.ended = true;
    this.device.log.push(`unsubscribe ${this.endpoint}`);
    this.device.onUnsubscribe?.(this.endpoint);
    return true;
  }
}

/** A browser profile with Web Push: its permission, its subscription, and the setting it stores. */
export class FakePushDevice implements PushPlatform {
  permissionState: NotificationPermission = "default";
  sub: FakeSubscription | null = null;
  readonly log: string[] = [];
  onUnsubscribe: ((endpoint: string) => void) | null = null;
  private seq = 0;
  private setting: PushSetting = { on: false, endpoint: null };
  readonly store: PushStore = {
    load: () => this.setting,
    save: (s) => {
      this.setting = s;
    },
  };

  constructor(readonly name: string) {}

  permission(): NotificationPermission {
    return this.permissionState;
  }

  async requestPermission(): Promise<NotificationPermission> {
    this.log.push("permission");
    if (this.permissionState === "default") this.permissionState = "granted";
    return this.permissionState;
  }

  private readonly manager_: PushManagerLike = {
    getSubscription: async () => (this.sub && !this.sub.ended ? this.sub : null),
    subscribe: async (o) => {
      this.sub = new FakeSubscription(
        `https://push.test/${this.name}/${this.seq++}`,
        new Uint8Array(o.applicationServerKey as ArrayBuffer),
        this,
      );
      this.log.push(`subscribe ${this.sub.endpoint}`);
      return this.sub;
    },
  };

  async manager(): Promise<PushManagerLike> {
    return this.manager_;
  }

  async existing(): Promise<PushManagerLike | null> {
    return this.manager_;
  }

  /** The engine options that give an engine this device. */
  get options() {
    return { push: { platform: this as PushPlatform, store: this.store } };
  }

  get endpoint(): string {
    if (!this.sub) throw new Error(`${this.name} has no subscription`);
    return this.sub.endpoint;
  }
}

/** b64u bells as the fake server records them. */
export const bellsB64 = (bells: readonly Bytes[]): string[] => bells.map(b64u);
export const fromBells = (ts: readonly string[]): Bytes[] => ts.map(fromB64u);
