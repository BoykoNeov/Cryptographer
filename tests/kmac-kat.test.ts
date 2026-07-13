/**
 * KMAC128 / KMAC256 / KMACXOF128 / KMACXOF256 known-answer-test gate
 * (NIST SP 800-185 §4), 2026-07-13.
 *
 * `node:crypto` has **no KMAC**, so the oracle is the independent reference in
 * `M:\claud_projects\temp\cshake-kmac-ref\ref.py` — a from-scratch Keccak sponge
 * that agrees byte-for-byte with pycryptodome AND the NIST SP 800-185 published
 * KMAC / KMACXOF samples (three-source agreement). Vectors below were emitted
 * from that reference.
 *
 * KMAC is the app's **first keyed hash**: the spec reads the key from
 * `aux["key"]` via `aux-load-bytes@1`. This test drives the spec through the
 * runtime with the key seeded into `initialAux` **exactly as the app's run
 * handler does** (`new Map([["key", keyBytes]])`), so it exercises the real
 * key-plumbing path, not a hand-wired aux.
 *
 * Coverage:
 *   1. The NIST published KMAC128/256 + KMACXOF128/256 samples (exact hex).
 *   2. **Prefix-INSTABILITY** — KMAC (unlike SHAKE/cSHAKE) binds the output
 *      length into the input, so @16 is NOT a prefix of @32. Each length is a
 *      separate vector.
 *   3. KMAC vs KMACXOF differ (right_encode(L) vs right_encode(0)).
 *   4. Squeeze-block-count structural pins.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { type KmacVariant, buildKmacSpec } from "@/ciphers/kmac";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const seq = (len: number): Uint8Array => new Uint8Array(Array.from({ length: len }, (_, i) => i));

// The NIST SP 800-185 sample key: bytes 0x40..0x5F (32 bytes).
const NIST_KEY = new Uint8Array(Array.from({ length: 32 }, (_, i) => 0x40 + i));

/** Drive a KMAC spec through the runtime with the key seeded into aux exactly
 *  as the app's run handler does. */
const kmacHex = (
  variant: KmacVariant,
  message: Uint8Array,
  S: Uint8Array,
  outputLength: number,
  key: Uint8Array = NIST_KEY,
): string => {
  const spec = buildKmacSpec(variant, S, outputLength);
  const initialAux = new Map<string, AuxValue>([["key", key]]); // the app path
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: message },
    initialAux,
  });
  if (trace.finalState.shape !== "bytes") {
    throw new Error(`expected bytes finalState, got ${trace.finalState.shape}`);
  }
  return bytesToHex(trace.finalState.bytes);
};

const squeezePermCount = (spec: CipherSpec): number =>
  spec.steps.filter((n) => n.kind === "group" && n.id.startsWith("squeeze.perm.")).length;

// ─── Reference vectors (emitted from the validated python reference) ────────

type Vec = { variant: KmacVariant; S: string; dataLen: number; outLen: number; out: string };

const VECTORS: Vec[] = [
  // KMAC128 / KMAC256 — NIST samples #1-6
  {
    variant: "kmac128",
    S: "",
    dataLen: 4,
    outLen: 32,
    out: "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
  },
  {
    variant: "kmac128",
    S: "My Tagged Application",
    dataLen: 4,
    outLen: 32,
    out: "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
  },
  {
    variant: "kmac128",
    S: "My Tagged Application",
    dataLen: 200,
    outLen: 32,
    out: "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230",
  },
  {
    variant: "kmac256",
    S: "My Tagged Application",
    dataLen: 4,
    outLen: 64,
    out: "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
  },
  {
    variant: "kmac256",
    S: "",
    dataLen: 200,
    outLen: 64,
    out: "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
  },
  {
    variant: "kmac256",
    S: "My Tagged Application",
    dataLen: 200,
    outLen: 64,
    out: "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965",
  },
  // KMACXOF128 / KMACXOF256 — NIST samples #4-9
  {
    variant: "kmacxof128",
    S: "",
    dataLen: 4,
    outLen: 32,
    out: "cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35",
  },
  {
    variant: "kmacxof128",
    S: "My Tagged Application",
    dataLen: 4,
    outLen: 32,
    out: "31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c",
  },
  {
    variant: "kmacxof128",
    S: "My Tagged Application",
    dataLen: 200,
    outLen: 32,
    out: "47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f",
  },
  {
    variant: "kmacxof256",
    S: "",
    dataLen: 4,
    outLen: 64,
    out: "1c7f9bf1c335c97dfa48fba50027059230f1ba42ae749ad5342f965dd4d73d0cde89b50b264e199cc6929edfd012b7a13ad7b8fd8f7ddd3f2758068fe2a347f0",
  },
  {
    variant: "kmacxof256",
    S: "My Tagged Application",
    dataLen: 4,
    outLen: 64,
    out: "1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa96faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b",
  },
  {
    variant: "kmacxof256",
    S: "My Tagged Application",
    dataLen: 200,
    outLen: 64,
    out: "d5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce67ba01c62e8ab8578d2d499bd1bb276768781190020a306a97de281dcc30305d",
  },
];

describe("KMAC — NIST SP 800-185 published known-answer vectors", () => {
  for (const v of VECTORS) {
    it(`${v.variant} S="${v.S}" data[${v.dataLen}] @ ${v.outLen}`, () => {
      expect(kmacHex(v.variant, seq(v.dataLen), enc(v.S), v.outLen)).toBe(v.out);
    });
  }
});

// ─── Prefix-instability (KMAC binds L into the input) ───────────────────────

describe("KMAC — output length is committed (NOT prefix-stable)", () => {
  it("kmac128 @16 is not a prefix of @32 (each length is independent)", () => {
    const at16 = kmacHex("kmac128", seq(4), enc(""), 16);
    const at32 = kmacHex("kmac128", seq(4), enc(""), 32);
    expect(at16).toBe("a23543cf6ade5db704d2c30f154bc63d");
    expect(at32.startsWith(at16)).toBe(false);
  });
});

// ─── KMAC vs KMACXOF ────────────────────────────────────────────────────────

describe("KMAC vs KMACXOF", () => {
  it("differ only by right_encode(L) vs right_encode(0) → different output", () => {
    const kmac = kmacHex("kmac128", seq(4), enc(""), 32);
    const xof = kmacHex("kmacxof128", seq(4), enc(""), 32);
    expect(kmac).not.toBe(xof);
  });
});

// ─── Key sensitivity ────────────────────────────────────────────────────────

describe("KMAC — the key authenticates", () => {
  it("a one-byte key change produces a different tag", () => {
    const k1 = NIST_KEY;
    const k2 = Uint8Array.from(k1);
    k2[0] = (k2[0] ?? 0) ^ 0x01; // flip one key bit (noUncheckedIndexedAccess)
    expect(kmacHex("kmac128", seq(4), enc(""), 32, k1)).not.toBe(
      kmacHex("kmac128", seq(4), enc(""), 32, k2),
    );
  });
});

// ─── Squeeze-block-count structural pins ────────────────────────────────────

describe("KMAC — unrolled squeeze grows with output length", () => {
  it("kmac128: ≤168 → 0 extra perms, 169 → 1", () => {
    expect(squeezePermCount(buildKmacSpec("kmac128", enc(""), 168))).toBe(0);
    expect(squeezePermCount(buildKmacSpec("kmac128", enc(""), 169))).toBe(1);
  });
});
