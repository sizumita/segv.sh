// HTTP + WebSocket client for the public log (docs/PROTOCOL.md §5). Browser only.
import * as P from "~/lib/proto";

export interface WireRow {
  seq: number;
  kind: number;
  tag: string;
  body: string;
  ts: number;
  h: string;
}

export interface Params {
  now: number;
  window: number;
  pow: Record<P.PowScope, number>;
  limits: { batch: number; blobMax: number };
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

let params: Params | null = null;
let paramsAt = 0; // local time when params were fetched
let clockOffset = 0; // serverNow - localNow

async function readError(res: Response): Promise<ApiError> {
  let msg = `${res.status} ${res.statusText}`;
  try {
    const j = (await res.json()) as { error?: unknown };
    if (typeof j.error === "string") msg = j.error;
  } catch {
    /* not JSON */
  }
  return new ApiError(res.status, msg);
}

export async function getParams(force = false): Promise<Params> {
  if (!force && params && Date.now() - paramsAt < 5 * 60_000) return params;
  const res = await fetch("/api/params", { cache: "no-store" });
  if (!res.ok) throw await readError(res);
  const p = (await res.json()) as Params;
  params = p;
  paramsAt = Date.now();
  clockOffset = p.now - paramsAt;
  return p;
}

const powWindow = () => Math.floor((Date.now() + clockOffset) / P.POW_WINDOW_MS);

export type Progress = (msg: string) => void;

/** Refuse absurd difficulties from a misbehaving server instead of hashing for minutes. */
const MAX_POW_BITS = 26;

async function powHeader(
  scope: P.PowScope,
  digest: Uint8Array,
  bytes: number,
  onProgress?: Progress,
): Promise<string> {
  const p = await getParams();
  const base = p.pow[scope];
  if (!Number.isInteger(base) || base < 0 || base > MAX_POW_BITS)
    throw new ApiError(0, `server requested unreasonable proof of work (${base} bits)`);
  const bits = P.powDifficulty(scope, base, bytes); // scales with the bytes everyone has to store
  const window = powWindow();
  onProgress?.("solving proof of work…");
  const nonce = await P.powSolve(P.powPre(scope, window, digest), bits);
  return `${window}.${nonce}`;
}

/** POSTs JSON with a proof of work. Retries once with fresh params when the server rejects the PoW. */
async function postPow<T>(
  path: string,
  scope: P.PowScope,
  body: unknown,
  onProgress?: Progress,
): Promise<T> {
  const bytes = P.utf8(JSON.stringify(body));
  const digest = P.H(bytes);
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-segv-pow": await powHeader(scope, digest, bytes.length, onProgress),
      },
      body: bytes as BodyInit,
    });
    if (res.ok) return (await res.json()) as T;
    const err = await readError(res);
    if (res.status === 403 && attempt === 0) {
      await getParams(true);
      continue;
    }
    throw err;
  }
}

export interface WrapJson {
  record: string;
  sig: string;
}

export const register = (
  body: { bundle: string; sig: string; wraps: WrapJson[] },
  onProgress?: Progress,
) => postPow<{ seq: number }>("/api/register", "register", body, onProgress);

export const postWrap = (body: WrapJson, onProgress?: Progress) =>
  postPow<{ seq: number }>("/api/wraps", "wrap", body, onProgress);

export async function append(rows: P.Row[], onProgress?: Progress): Promise<number[]> {
  const body = {
    rows: rows.map((r) => ({ kind: r.kind, tag: P.b64u(r.tag), body: P.b64u(r.body) })),
  };
  const res = await postPow<{ seqs: number[] }>("/api/append", "append", body, onProgress);
  return res.seqs;
}

export async function getLog(
  after: number,
  limit = 1000,
): Promise<{ rows: WireRow[]; head: { seq: number; h: string } }> {
  const res = await fetch(`/api/log?after=${after}&limit=${limit}`, { cache: "no-store" });
  if (!res.ok) throw await readError(res);
  return (await res.json()) as { rows: WireRow[]; head: { seq: number; h: string } };
}

export async function getWraps(
  id: Uint8Array,
  uid: Uint8Array | null,
): Promise<{ seq: number; uid: string; record: string; sig: string }[]> {
  const q = uid ? `?uid=${P.b64u(uid)}` : "";
  const res = await fetch(`/api/wraps/${P.b64u(id)}${q}`, { cache: "no-store" });
  if (res.status === 404) return [];
  if (!res.ok) throw await readError(res);
  return (
    (await res.json()) as { wraps: { seq: number; uid: string; record: string; sig: string }[] }
  ).wraps;
}

export interface UserJson {
  uid: string;
  handle: string;
  bundle: string;
  sig: string;
  seq: number;
}

/** Directory lookup (convenience index; the log is authoritative). null when the handle is free. */
export async function getUser(handle: string): Promise<UserJson | null> {
  const res = await fetch(`/api/users/${encodeURIComponent(handle)}`, { cache: "no-store" });
  if (res.status === 404) return null;
  if (!res.ok) throw await readError(res);
  return (await res.json()) as UserJson;
}

export async function putBlob(id: string, blob: Uint8Array, onProgress?: Progress): Promise<void> {
  const header = await powHeader("blob", P.fromB64u(id), blob.length, onProgress);
  onProgress?.("uploading image…");
  const res = await fetch(`/api/blob/${id}`, {
    method: "PUT",
    headers: { "content-type": "application/octet-stream", "x-segv-pow": header },
    body: blob as BodyInit,
  });
  if (!res.ok) throw await readError(res);
}

export async function getBlob(id: string): Promise<Uint8Array> {
  const res = await fetch(`/api/blob/${id}`);
  if (!res.ok) throw await readError(res);
  return new Uint8Array(await res.arrayBuffer());
}

/** Live feed of new rows. Reconnects with exponential backoff until `close()` is called. */
export function openFeed(handlers: {
  onRows: (rows: WireRow[]) => void;
  onState: (connected: boolean) => void;
}): { close(): void } {
  let ws: WebSocket | null = null;
  let closed = false;
  let delay = 1000;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let ping: ReturnType<typeof setInterval> | null = null;

  const connect = () => {
    if (closed) return;
    const url = new URL("/api/ws", location.href);
    url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(url);
    ws.onopen = () => {
      delay = 1000;
      handlers.onState(true);
      ping = setInterval(() => ws?.readyState === WebSocket.OPEN && ws.send("ping"), 30_000);
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data !== "string" || ev.data === "pong") return;
      try {
        const msg = JSON.parse(ev.data) as { type?: string; rows?: WireRow[] };
        if (msg.type === "rows" && Array.isArray(msg.rows)) handlers.onRows(msg.rows);
      } catch {
        /* ignore malformed frames */
      }
    };
    ws.onclose = () => {
      if (ping) clearInterval(ping);
      ping = null;
      handlers.onState(false);
      if (closed) return;
      timer = setTimeout(connect, delay);
      delay = Math.min(delay * 2, 30_000);
    };
    ws.onerror = () => ws?.close();
  };
  connect();
  return {
    close() {
      closed = true;
      if (timer) clearTimeout(timer);
      if (ping) clearInterval(ping);
      ws?.close();
    },
  };
}
