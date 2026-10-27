// The inbox trial-decryption Web Worker (docs/PROTOCOL-v2.md §11.5 step 2): one X-Wing decapsulation per invite, off
// the page's thread. Messages: {id, kemSk, E, rows: [{eid, body}]} → {id, out: (J bytes | 0 malformed | null)[]}.
import * as P from "~/lib/proto";

interface Request {
  id: number;
  kemSk: Uint8Array;
  E: number;
  rows: { eid: Uint8Array; body: Uint8Array }[];
}

self.onmessage = (ev: MessageEvent<Request>) => {
  const { id, kemSk, E, rows } = ev.data;
  const out = rows.map((r) => {
    const opened = P.tryOpenInvite(kemSk, E, 0, r.eid, r.body);
    if (!opened) return null;
    return opened.kind === "join" ? P.encodeJ(opened.join) : 0;
  });
  (self as unknown as Worker).postMessage({ id, out });
};
