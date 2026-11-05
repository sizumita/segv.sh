// The device's realtime sockets (docs/PROTOCOL.md §10.8, §11.6, §2.6): at most 2 in all, for every account the session
// runs (the owner and its aliases). Each account gives its topics by priority class; the hub merges them (every
// account's Tself, owner first, then every inbox notice topic, then the current epochs of every account's accepted
// copies by activity, then followed old epochs, then links), drops repeats, cuts them at 2 × 256 and routes what the
// sockets receive: ROWS to every account that holds the topic (one T_e can be the owner's and an alias's), INBOX
// notices to every account (each checks its own bucket), and missed rows to the accounts concerned.
import * as P from "@segv/protocol/proto";
import type * as W from "@segv/protocol/wire";
import type { EngineClock, WebSocketCtor } from "./options";
import { Realtime } from "./realtime";

type Bytes = Uint8Array;

/** Topics per realtime socket (§10.8). */
const RT_TOPICS = 256;

/** One account's topics, by priority class (§10.8). */
export interface AccountTopics {
  self: Bytes;
  inbox: Bytes[];
  /** current epochs of accepted copies, with their copy's lastTs */
  current: { topic: Bytes; lastTs: number }[];
  /** earlier epochs with followed lanes, with their copy's lastTs */
  old: { topic: Bytes; lastTs: number }[];
  links: Bytes[];
}

/** What the hub needs of an account (its Messaging). */
export interface HubAccount {
  /** null while it does not run */
  topicSet(): AccountTopics | null;
  onRows(rows: W.RtRow[]): void;
  onInbox(E: number, g: number, rel: number): void;
  /** rows of its topics may have been missed (a GAP, a first connection, new topics): it catches up */
  missed(): void;
}

export interface HubHost {
  clock: EngineClock;
  /** the deployment's canonical origin of a native app (§11.14) */
  origin?: string;
  /** a HELLO's server time and the socket's upgrade-to-HELLO interval (§10.1) */
  onHello(s: number, sentMono: number, recvMono: number): void;
  onState(connected: boolean): void;
}

export class RealtimeHub {
  /** the running accounts, the owner first, then the aliases by index */
  private accounts: HubAccount[] = [];
  private readonly rts: Realtime[] = [];
  /** the accounts that want each topic, by b64u */
  private routes = new Map<string, HubAccount[]>();
  private stopped = false;

  constructor(
    private readonly WS: WebSocketCtor | null,
    private readonly h: HubHost,
  ) {}

  /** Replaces the running accounts (in priority order) and subscribes again. */
  setAccounts(list: HubAccount[]): void {
    this.accounts = list;
    this.subscribe();
  }

  /** Every account's topics, merged and cut at 2 × 256, onto the sockets (§10.8). */
  subscribe(): void {
    if (this.stopped || !this.WS) return;
    const sets: { a: HubAccount; t: AccountTopics }[] = [];
    for (const a of this.accounts) {
      const t = a.topicSet();
      if (t) sets.push({ a, t });
    }
    const ordered: { topic: Bytes; a: HubAccount }[] = [];
    for (const { a, t } of sets) ordered.push({ topic: t.self, a });
    for (const { a, t } of sets) for (const topic of t.inbox) ordered.push({ topic, a });
    const byActivity = (k: "current" | "old") =>
      sets
        .flatMap(({ a, t }) => t[k].map((x) => ({ ...x, a })))
        .sort((x, y) => y.lastTs - x.lastTs);
    for (const x of byActivity("current")) ordered.push(x);
    for (const x of byActivity("old")) ordered.push(x);
    for (const { a, t } of sets) for (const topic of t.links) ordered.push({ topic, a });
    const routes = new Map<string, HubAccount[]>();
    const topics: Bytes[] = [];
    for (const { topic, a } of ordered) {
      const k = P.b64u(topic);
      let r = routes.get(k);
      if (!r) {
        routes.set(k, (r = []));
        topics.push(topic);
      }
      if (!r.includes(a)) r.push(a);
    }
    this.routes = routes;
    const parts = [topics.slice(0, RT_TOPICS), topics.slice(RT_TOPICS, 2 * RT_TOPICS)];
    parts.forEach((part, i) => {
      if (part.length === 0) return;
      this.rts[i] ??= this.newSocket();
      this.rts[i].setTopics(part);
    });
    if (parts[1].length === 0 && this.rts[1]) {
      this.rts[1].stop();
      this.rts.length = 1;
    }
  }

  /** The first socket is open (the periodic catch-up's cadence, §11.6). */
  get connected(): boolean {
    return this.rts[0]?.connected ?? false;
  }

  /** The system woke or the page came back: sockets reconnect or check that they still answer. */
  wake(): void {
    if (this.stopped) return;
    for (const rt of this.rts) rt.wake();
  }

  stop(): void {
    this.stopped = true;
    for (const rt of this.rts) rt.stop();
    this.rts.length = 0;
    this.accounts = [];
    this.routes.clear();
  }

  private newSocket(): Realtime {
    const rt = new Realtime(
      this.WS!,
      this.h.clock,
      {
        onRows: (rows) => this.onRows(rows),
        onMissed: () => {
          for (const a of this.accounts) a.missed();
        },
        onSubscribed: (topics) => {
          const hit = new Set<HubAccount>();
          for (const t of topics) for (const a of this.routes.get(P.b64u(t)) ?? []) hit.add(a);
          for (const a of hit) a.missed();
        },
        onHello: (s, sent, recv) => this.h.onHello(s, sent, recv),
        onInbox: (E, g, rel) => {
          for (const a of this.accounts) a.onInbox(E, g, rel);
        },
        onState: () => this.h.onState(this.rts.some((x) => x.connected)),
      },
      this.h.origin,
    );
    rt.start();
    return rt;
  }

  /** ROWS to every account that holds the row's topic, in seq order per account. */
  private onRows(rows: W.RtRow[]): void {
    const by = new Map<HubAccount, W.RtRow[]>();
    for (const r of rows)
      for (const a of this.routes.get(P.b64u(r.topic)) ?? []) {
        let list = by.get(a);
        if (!list) by.set(a, (list = []));
        list.push(r);
      }
    for (const [a, list] of by) a.onRows(list);
  }
}
