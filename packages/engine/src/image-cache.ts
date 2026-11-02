// The session's decrypted images (§8.1), as object URLs: an image stays while the UI shows it, and the few it showed
// last stay too, for when they come back into view; any other is revoked, which frees its bytes. A session that runs
// for days would otherwise keep every image it ever showed.

export interface ImageCacheLimits {
  /** images kept that nothing shows */
  idle: number;
  /** their bytes */
  idleBytes: number;
}

export const IMAGE_CACHE_LIMITS: ImageCacheLimits = { idle: 32, idleBytes: 32 * 1024 * 1024 };

interface Entry {
  url: Promise<string>;
  /** the decrypted bytes, once the URL is made */
  size: number;
  settled: boolean;
  /** how many holders show it */
  holds: number;
}

export class ImageCache {
  /** by key, the least recently used first */
  private readonly entries = new Map<string, Entry>();

  constructor(
    private readonly limits: ImageCacheLimits = IMAGE_CACHE_LIMITS,
    private readonly revoke: (url: string) => void = (u) => URL.revokeObjectURL(u),
  ) {}

  /**
   * The image's URL, which `make` creates when the cache has none, held until `release(key)`. A failed `make` leaves
   * nothing cached, and nothing to release.
   */
  hold(key: string, make: () => Promise<{ url: string; size: number }>): Promise<string> {
    let e = this.entries.get(key);
    if (e) {
      this.entries.delete(key);
    } else {
      const made = make();
      const entry: Entry = {
        url: made.then((m) => m.url),
        size: 0,
        settled: false,
        holds: 0,
      };
      e = entry;
      made.then(
        (m) => {
          entry.size = m.size;
          entry.settled = true;
          if (this.entries.get(key) === entry) this.evict();
          else this.revoke(m.url);
        },
        () => {
          if (this.entries.get(key) === entry) this.entries.delete(key);
        },
      );
    }
    e.holds++;
    this.entries.set(key, e);
    return e.url;
  }

  /** An image whose URL is made already (one this device sent), held by nothing. */
  put(key: string, url: string, size: number): void {
    const old = this.entries.get(key);
    if (old) {
      this.revoke(url);
      return;
    }
    this.entries.set(key, { url: Promise.resolve(url), size, settled: true, holds: 0 });
    this.evict();
  }

  /** A holder no longer shows the image. */
  release(key: string): void {
    const e = this.entries.get(key);
    if (!e || e.holds === 0) return;
    e.holds--;
    if (e.holds === 0) this.evict();
  }

  /** Revokes every image (the session ends). */
  clear(): void {
    for (const e of this.entries.values()) if (e.settled) void e.url.then(this.revoke);
    this.entries.clear();
  }

  /** The number of images held or kept. */
  get size(): number {
    return this.entries.size;
  }

  /** Revokes the least recently used images that nothing shows, beyond the limits. */
  private evict(): void {
    let idle = 0;
    let bytes = 0;
    for (const e of this.entries.values())
      if (e.holds === 0 && e.settled) {
        idle++;
        bytes += e.size;
      }
    for (const [key, e] of this.entries) {
      if (idle <= this.limits.idle && bytes <= this.limits.idleBytes) break;
      if (e.holds > 0 || !e.settled) continue;
      this.entries.delete(key);
      idle--;
      bytes -= e.size;
      void e.url.then(this.revoke);
    }
  }
}
