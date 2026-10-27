// Links (docs/PROTOCOL.md §4.3, §5.5, §7.2): the owner's LINK records, the `Tlink` subscriptions and the hello
// probing (every era of a link's lifetime up to the first MISS), one-shot and expiry; and the opener's hello, put at
// the first empty slot of the era. The engine implements links internally: there is no link UI and no Engine method
// in stage 1 (§11.11, §14).
import * as P from "~/lib/proto";
import { ApiError, type Api } from "./api";
import { W_SLOTS } from "./conv";
import { MALFORMED_KEY } from "./join";
import { UNDECRYPTABLE } from "./sync";

type Bytes = Uint8Array;

/** A link is valid for at most 4 eras (§5.5): Ecreated .. Ecreated + 3. */
export const LINK_ERAS = 4;

/** A link the owner still listens on. */
export interface LiveLink {
  s: Bytes;
  sB: string;
  keys: P.LinkKeys;
  Ecreated: number;
  Eexpires: number;
  oneShot: boolean;
  /** Tlink */
  topic: Bytes;
}

/** The live links of the fold at era Enow: not expired and not revoked (a one-shot link revokes itself, §5.5). */
export function liveLinks(links: ReadonlyMap<string, P.LinkRec>, Enow: number): LiveLink[] {
  const out: LiveLink[] = [];
  for (const [sB, r] of links) {
    if (
      (r.flags & P.LINK_REVOKED) !== 0 ||
      Enow > r.Eexpires ||
      r.Eexpires - r.Ecreated >= LINK_ERAS
    )
      continue;
    const keys = P.linkKeys(r.s);
    out.push({
      s: r.s,
      sB,
      keys,
      Ecreated: r.Ecreated,
      Eexpires: r.Eexpires,
      oneShot: (r.flags & P.LINK_ONE_SHOT) !== 0,
      topic: P.topicLink(keys.nL),
    });
  }
  return out;
}

/** A hello that opened under the owner's key: its slot and J. */
export interface FoundHello {
  link: LiveLink;
  E: number;
  j: number;
  J: P.Join;
}

/**
 * The owner's probing (§5.5): `Lhello(E, j..)` up to the first MISS for every era of each live link's lifetime, from
 * the slot after the last one this session processed. A row that does not open gives a noise warning.
 */
export class HelloProber {
  /** the next slot to probe, per link and era */
  private readonly next = new Map<string, number>();

  async probe(
    api: Api,
    kemSk: Bytes,
    links: readonly LiveLink[],
    Enow: number,
    warn: (text: string) => void,
  ): Promise<FoundHello[]> {
    const found: FoundHello[] = [];
    let todo = links.flatMap((link) => {
      const out: { link: LiveLink; E: number; j: number }[] = [];
      for (let E = link.Ecreated; E <= Math.min(link.Eexpires, Enow); E++)
        out.push({ link, E, j: this.next.get(`${link.sB}:${E}`) ?? 0 });
      return out;
    });
    for (let round = 0; round < 64 && todo.length; round++) {
      const keys = todo.flatMap((x) =>
        Array.from({ length: W_SLOTS }, (_, i) => ({
          E: x.E,
          label: P.Lhello(x.link.keys.kL, x.E, x.j + i),
          mode: 0 as const,
        })),
      );
      const st = await api.get(keys);
      const again: typeof todo = [];
      todo.forEach((x, k) => {
        let j = x.j;
        for (let i = 0; i < W_SLOTS; i++) {
          const s = st[k * W_SLOTS + i];
          if (s.s !== "hit" || !s.body) break;
          const opened = P.openHello(kemSk, x.link.s, x.E, keys[k * W_SLOTS + i].label, s.body);
          if (opened?.kind === "join") found.push({ link: x.link, E: x.E, j, J: opened.join });
          else warn(opened ? MALFORMED_KEY : UNDECRYPTABLE);
          j++;
        }
        this.next.set(`${x.link.sB}:${x.E}`, j);
        if (j - x.j === W_SLOTS) again.push({ ...x, j });
      });
      todo = again;
    }
    return found;
  }
}

/**
 * The opener's hello (§5.5 step 2): sealed to the owner's kemPk and put at `Lhello(E_now, j)` for the first empty j,
 * with topic Tlink and class 2. A CONFLICT takes the next slot; WRONG_ERA moves to the returned era.
 */
export async function putHello(
  api: Api,
  owner: { kemPk: Bytes },
  s: Bytes,
  J: P.Join,
  check: () => void,
): Promise<void> {
  const keys = P.linkKeys(s);
  const topic = P.topicLink(keys.nL);
  let E = P.era(api.serverNow());
  let j = 0;
  for (let attempt = 0; attempt < 16; attempt++) {
    check();
    // The first empty slot of the era: exists probes, galloping by W.
    for (;;) {
      const st = await api.get(
        Array.from({ length: W_SLOTS }, (_, i) => ({
          E,
          label: P.Lhello(keys.kL, E, j + i),
          mode: 1 as const,
        })),
      );
      const miss = st.findIndex((x) => x.s !== "hit");
      if (miss >= 0) {
        j += miss;
        break;
      }
      j += W_SLOTS;
    }
    const label = P.Lhello(keys.kL, E, j);
    const row = P.makeHello(owner.kemPk, s, E, label, J);
    const [r] = await api.put([{ E, label, cls: row.cls, topic, body: row.body }]);
    if (r.s === "ok") return;
    if (r.s === "conflict") {
      j++;
      continue;
    }
    if (r.s === "wrong_era") {
      E = r.era;
      j = 0;
      continue;
    }
    throw new ApiError(0, `hello refused (${r.s})`);
  }
  throw new ApiError(0, "could not place the hello");
}
