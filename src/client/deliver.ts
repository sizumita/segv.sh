// The J delivery queue (docs/PROTOCOL-v2.md §6.11, §6.12): every recipient of a creation or a commit gets J by a
// WELCOME in a qualifying 1:1 or by an inbox invite; a creation's (or commit's) first attempt ends with one padded
// DELIVERED row, later successes add further rows; pending recipients are retried with back-off (10 s doubling to
// 10 min, honouring `retry-after`) with one noise warning each; and unfinished deliveries of the account, found in
// its EPOCH_PENDING records, are resumed by any device once they are RESUME_AFTER old.
import * as P from "~/lib/proto";
import type { Api, Params } from "./api";
import { deliverInvites, type Recipient } from "./create";
import { SessionEnded } from "./errors";

type Bytes = Uint8Array;

const RETRY_MIN = 10_000;
const RETRY_MAX = 600_000;

export const notNotified = (handle: string): string =>
  `@${handle} has not been notified yet; retrying`;

/** One J and the recipients still waiting for it. */
export interface DeliveryJob {
  /** copyKey : e : b64u(bundleId), the key of its EPOCH_PENDING and DELIVERED records */
  key: string;
  conv: Bytes;
  root: Bytes;
  e: number;
  J: P.Join;
  /** uids (b64u) still waiting */
  uids: Set<string>;
  /** the first attempt writes its DELIVERED row even when nobody succeeded (the device that created or committed) */
  writeEmpty: boolean;
  attempt: number;
  warned: Set<string>;
  running: boolean;
}

export const jobKey = (copyKey: string, e: number, bundleId: Bytes): string =>
  `${copyKey}:${e}:${P.b64u(bundleId)}`;

/** What a WELCOME attempt came to: delivered, refused by §11.3 step 2 (give an invite instead), or pending. */
export type WelcomeOutcome = "ok" | "invite" | "pending";

export interface DeliveryHost {
  api: Api;
  params(): Params;
  check(): void;
  /** waits on a protocol timer */
  wait(ms: number): Promise<void>;
  /** counts background work as in flight */
  track<T>(p: Promise<T>): Promise<T>;
  warn(text: string): void;
  /** the recipients' kemPk by b64u uid, from the epoch's bundle (never the directory, §6.12 step 2) */
  pks(job: DeliveryJob): Promise<Map<string, Bytes>>;
  handleOf(uidB: string): string;
  /** a 1:1 copy in which a WELCOME to `uid` qualifies (§6.12 step 1), or null */
  welcomeChannel(uid: Bytes): Promise<unknown | null>;
  sendWelcome(channel: unknown, uid: Bytes, J: P.Join): Promise<WelcomeOutcome>;
  /** writes the DELIVERED row of these uids (padded to class 1, §6.12 step 3) */
  delivered(job: DeliveryJob, uids: Bytes[]): Promise<void>;
}

export class Deliveries {
  readonly jobs = new Map<string, DeliveryJob>();

  constructor(private readonly h: DeliveryHost) {}

  /** Adds (or merges into) a job and starts its loop unless one runs. */
  enqueue(job: Omit<DeliveryJob, "attempt" | "warned" | "running">): DeliveryJob {
    const had = this.jobs.get(job.key);
    if (had) {
      for (const u of job.uids) had.uids.add(u);
      return had;
    }
    const j: DeliveryJob = { ...job, attempt: 0, warned: new Set(), running: false };
    this.jobs.set(j.key, j);
    return j;
  }

  /** Runs a job's attempts until every recipient got J (or the session ends), in the background. */
  start(job: DeliveryJob): void {
    if (job.running || job.uids.size === 0) return;
    job.running = true;
    void this.h
      .track(this.loop(job))
      .catch(() => {})
      .finally(() => {
        job.running = false;
      });
  }

  /** The first attempt (awaited by a creation, §6.1 steps 8–9); later ones run in the background. */
  async first(job: DeliveryJob): Promise<void> {
    job.running = true;
    try {
      await this.round(job);
    } finally {
      job.running = false;
    }
    this.start(job);
  }

  private async loop(job: DeliveryJob): Promise<void> {
    for (;;) {
      this.h.check();
      if (job.uids.size === 0) break;
      const retryAfter = await this.round(job);
      if (job.uids.size === 0) break;
      for (const u of job.uids)
        if (!job.warned.has(u)) {
          job.warned.add(u);
          this.h.warn(notNotified(this.h.handleOf(u)));
        }
      const backoff = Math.min(RETRY_MAX, RETRY_MIN * 2 ** job.attempt);
      job.attempt++;
      await this.h.wait(Math.max(backoff, retryAfter * 1000));
    }
    this.jobs.delete(job.key);
  }

  /** One attempt for every waiting recipient (§6.12 steps 1–4); records the successes. Returns retry-after (s). */
  private async round(job: DeliveryJob): Promise<number> {
    let pks: Map<string, Bytes>;
    try {
      pks = await this.h.pks(job);
    } catch (e) {
      if (e instanceof SessionEnded) throw e;
      return 0;
    }
    const delivered: Bytes[] = [];
    const invites: Recipient[] = [];
    for (const uidB of job.uids) {
      const uid = P.fromB64u(uidB);
      const channel = await this.h.welcomeChannel(uid);
      if (channel) {
        const r: WelcomeOutcome = await this.h
          .sendWelcome(channel, uid, job.J)
          .catch((e: unknown) => {
            if (e instanceof SessionEnded) throw e;
            return "pending" as const;
          });
        if (r === "ok") delivered.push(uid);
        if (r !== "invite") continue;
      }
      const kemPk = pks.get(uidB);
      if (kemPk) invites.push({ uid, kemPk, handle: this.h.handleOf(uidB) });
    }
    let retryAfter = 0;
    if (invites.length) {
      try {
        const r = await deliverInvites(
          {
            api: this.h.api,
            params: () => this.h.params(),
            wait: (ms) => this.h.wait(ms),
            check: () => this.h.check(),
            progress: () => {},
          },
          job.J,
          invites,
        );
        delivered.push(...r.delivered);
        retryAfter = r.retryAfter;
      } catch (e) {
        if (e instanceof SessionEnded) throw e;
      }
    }
    for (const u of delivered) job.uids.delete(P.b64u(u));
    if (delivered.length || job.writeEmpty) await this.writeDelivered(job, delivered);
    job.writeEmpty = false;
    return retryAfter;
  }

  private async writeDelivered(job: DeliveryJob, uids: Bytes[]): Promise<void> {
    for (let attempt = 0; ; attempt++) {
      this.h.check();
      try {
        return await this.h.delivered(job, uids);
      } catch (e) {
        if (e instanceof SessionEnded) throw e;
        await this.h.wait(Math.min(RETRY_MAX, 500 * 2 ** attempt));
      }
    }
  }
}
