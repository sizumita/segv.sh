/** Pure helpers, exercised inside workerd (where the native base64 path is active). */
import { describe, expect, it } from "vitest";
import * as P from "@segv/protocol/proto";
import { clientKey, clientTag } from "../src/abuse";
import { dec64, enc64 } from "../src/b64";
import { logErr } from "../src/http";
import { appHosts } from "../src/hosts";

const req = (ip?: string) => new Request("https://x/", { headers: ip === undefined ? {} : { "cf-connecting-ip": ip } });

describe("b64", () => {
  it("matches proto.b64u / proto.fromB64u for every length", () => {
    for (let n = 0; n < 100; n++) {
      const b = P.random(n);
      const s = P.b64u(b);
      expect(enc64(b)).toBe(s);
      expect(dec64(s)).toEqual(b);
    }
    const big = P.random(20_000);
    expect(enc64(big)).toBe(P.b64u(big));
  });

  it("rejects everything proto rejects", () => {
    for (const s of ["A", "AB==", "AB=", "A B", "AB\n", "+/", "AF", "AAB", "Zm9vé", " Zm9v"]) {
      expect(() => P.fromB64u(s), s).toThrow();
      expect(() => dec64(s), s).toThrow();
    }
    expect(() => dec64(42)).toThrow();
  });
});

describe("clientKey", () => {
  it("keys IPv4 by address and IPv6 by /64", () => {
    expect(clientKey(req("203.0.113.7"))).toBe("4:203.0.113.7");
    expect(clientKey(req("2001:db8:a:b:1:2:3:4"))).toBe("6:2001:db8:a:b::/64");
    expect(clientKey(req("2001:DB8:A:B::99"))).toBe("6:2001:db8:a:b::/64");
    expect(clientKey(req("2001:db8::1"))).toBe("6:2001:db8:0:0::/64");
    expect(clientKey(req("::1"))).toBe("6:0:0:0:0::/64");
    expect(clientKey(req("fe80::1%eth0"))).toBe("6:fe80:0:0:0::/64");
    expect(clientKey(req("2001:0db8:000a:000b::"))).toBe("6:2001:db8:a:b::/64");
    expect(clientKey(req("64:ff9b::192.0.2.1"))).toBe("6:64:ff9b:0:0::/64");
  });

  it("keys IPv4-mapped IPv6 by the IPv4 address", () => {
    expect(clientKey(req("::ffff:198.51.100.9"))).toBe("4:198.51.100.9");
    expect(clientKey(req("::ffff:c633:6409"))).toBe("4:198.51.100.9");
  });

  it("buckets missing / invalid addresses", () => {
    expect(clientKey(req())).toBe("x:unknown");
    expect(clientKey(req("not an ip"))).toBe("x:unknown");
    expect(clientKey(req("1.2.3.256"))).toBe("x:unknown");
    for (const bad of ["1:2:3:4:5:6:7:8:9", "1::2::3", "12345::", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8::", "::1.2.3"]) {
      expect(clientKey(req(bad)), bad).toBe("x:invalid");
    }
  });
});

describe("logErr", () => {
  it("redacts ids and addresses, keeps the message readable", () => {
    const id = P.b64u(P.random(32));
    const msg = logErr(new Error(`put: The SHA-256 checksum you specified did not match (${P.hex(P.random(32))}) for b/${id} from 203.0.113.7 / 2001:db8::1`));
    expect(msg).not.toContain(id);
    expect(msg).not.toContain("203.0.113.7");
    expect(msg).not.toContain("2001:db8::1");
    expect(msg).toContain("Error: put: The SHA-256 checksum you specified did not match");
    expect(logErr(new Error("D1_ERROR: SQLITE_CONSTRAINT_PRIMARYKEY"))).toBe("Error: D1_ERROR: SQLITE_CONSTRAINT_PRIMARYKEY");
    expect(logErr("x".repeat(1000)).length).toBeLessThanOrEqual(300);
  });
});

describe("clientTag / appHosts", () => {
  it("tags are opaque, stable per client key and key-dependent", () => {
    const k1 = P.random(32);
    const r = (ip: string) => req(ip);
    expect(clientTag(k1, r("203.0.113.7"))).toMatch(/^[0-9a-f]{32}$/);
    expect(clientTag(k1, r("203.0.113.7"))).toBe(clientTag(k1, r("203.0.113.7")));
    expect(clientTag(k1, r("2001:db8:a:b::1"))).toBe(clientTag(k1, r("2001:db8:a:b::2"))); // same /64
    expect(clientTag(k1, r("203.0.113.7"))).not.toBe(clientTag(k1, r("203.0.113.8")));
    expect(clientTag(k1, r("203.0.113.7"))).not.toBe(clientTag(P.random(32), r("203.0.113.7")));
  });

  it("parses APP_HOSTS", () => {
    expect(appHosts({ APP_HOSTS: " Segv.sh , localhost,," } as unknown as Env)).toEqual(["segv.sh", "localhost"]);
    expect(appHosts({ APP_HOSTS: "" } as unknown as Env)).toEqual([]);
    expect(appHosts({} as unknown as Env)).toEqual([]);
  });
});
