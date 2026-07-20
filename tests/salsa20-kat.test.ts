/**
 * Salsa20/20 (Bernstein, 2005) known-answer tests — the app's second stream
 * cipher, and the first cipher with NO live oracle.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ORACLE PROBLEM, AND WHAT WE ACTUALLY HAVE.
 *
 * Every other cipher in this project can be checked against something running
 * in the same process: `node:crypto` has `aes-*`, `des-ede3` and `chacha20`.
 * **It has no `salsa20`.** So there is no `createCipheriv` call below, and
 * every expected value is a literal pinned into this file.
 *
 * That makes the provenance of those literals the whole ballgame — a KAT that
 * runs the app against the app is circular and passes on an entirely wrong
 * cipher. Two independent sources agree on every vector here:
 *
 *   1. **pycryptodome 3.23's `Crypto.Cipher.Salsa20`**, run offline. A mature
 *      third-party implementation, not this codebase.
 *   2. **The reference implementation in this file** (`refBlock` below),
 *      written directly from Bernstein's specification as plain word
 *      arithmetic. It shares no code, no data layout and no execution model
 *      with the port-graph spec under test — it does not use the registry, the
 *      runtime, or a single `Uint8Array` port. A bug in the spec's wiring
 *      cannot reach it.
 *
 * Source 2 is what makes this non-circular in the way that matters. The app is
 * a graph of byte-shuffling steps; `refBlock` is sixteen numbers in an array.
 * If they agree on 128 bytes of keystream, the graph is wired correctly.
 *
 * **Corroboration against published values.** The key and nonce in vector B
 * are the eSTREAM/ECRYPT verified test vectors, Set 6, vector 0 — a widely
 * republished pair. Its published keystream was checked against pycryptodome
 * and agrees. (Only a partial recollection of the published keystream tail was
 * available when these tests were written, so the full 64-byte literal below
 * comes from the two sources above rather than from a transcribed publication;
 * the first 22 bytes were confirmed against the published value directly.
 * Per the project's "external oracle before tests" rule, a half-remembered
 * published vector is worth less than two agreeing implementations, so it is
 * recorded here as corroboration rather than as the anchor.)
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHY ROUND-TRIP IS RANKED LAST.
 *
 * Salsa20's message meets only an XOR, and XOR is its own inverse, so the
 * encrypt and decrypt specs are structurally IDENTICAL. "Encrypt then decrypt
 * returns the plaintext" is therefore a tautology: it holds by construction
 * even if the quarter round is entirely wrong, the rotation constants are
 * permuted, the state layout is ChaCha20's, and the counter never advances.
 * Same trap OFB and ChaCha20 documented.
 *
 * Ordered by how much each test actually discriminates:
 *
 *   1. The reference implementation vs. the app, on keystream. The primary
 *      anchor — pins the quarter round, the rotation constants, the DIAGONAL
 *      state assembly, the little-endian serialization and the counter start
 *      all at once.
 *   2. Pinned pycryptodome vectors across three key/nonce pairs.
 *   3. The diagonal state assembly, read directly out of the trace — the one
 *      test that localizes a layout bug instead of just detecting it.
 *   4. Counter advance across blocks, including the 64-bit carry.
 *   5. Partial final block / arbitrary message lengths.
 *   6. Round-trip — last, and proving nothing on its own.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  SALSA20_BLOCK_BYTES,
  SALSA20_IV_BYTES,
  salsa20DecryptSpec,
  salsa20EncryptSpec,
} from "@/ciphers/salsa20";
import { framePrimaryOutBytes } from "@/core/frame-state";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const fromHex = (s: string): Uint8Array =>
  new Uint8Array((s.replace(/\s+/g, "").match(/../g) ?? []).map((h) => Number.parseInt(h, 16)));

const toHex = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

/**
 * Pack the app's 16-byte IV blob: a 64-bit little-endian counter followed by
 * the 8-byte nonce. Hand-rolled rather than imported, so a change to the
 * builder's layout has to be reflected in a test that fails.
 *
 * Note the 8/8 split — ChaCha20's is 4/12. Both ciphers have a 16-byte IV, and
 * that coincidence is exactly what makes `reconcileIvWidth`'s equal-width
 * short-circuit dangerous when switching between them (see
 * `tests/app-salsa20-stream.test.tsx`).
 */
const packIv = (counter: bigint, nonceHex: string): Uint8Array => {
  const iv = new Uint8Array(SALSA20_IV_BYTES);
  new DataView(iv.buffer).setBigUint64(0, counter, true /* little-endian */);
  iv.set(fromHex(nonceHex), 8);
  return iv;
};

const run = (spec: CipherSpec, input: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: input },
    initialAux: new Map<string, AuxValue>([
      ["key", key],
      ["iv", iv],
    ]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");
  return trace.finalState.bytes;
};

/**
 * The keystream for a given (key, iv), read out of the cipher by encrypting
 * zeros: `0 ⊕ keystream === keystream`.
 */
const keystream = (key: Uint8Array, iv: Uint8Array, length: number): Uint8Array =>
  run(salsa20EncryptSpec, new Uint8Array(length), key, iv);

// ─── The independent reference implementation ─────────────────────────────
//
// Written from Bernstein's specification as plain 32-bit word arithmetic.
// This shares nothing with the spec under test — no registry, no runtime, no
// ports, no byte buffers between operations. It is the second opinion that
// makes the pinned vectors below non-circular.

/** Rotate a 32-bit word left by `n`. */
const rotl = (v: number, n: number): number => ((v << n) | (v >>> (32 - n))) >>> 0;

/** Read `n` little-endian 32-bit words from `b` at `offset`. */
const leWords = (b: Uint8Array, offset: number, n: number): number[] => {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return Array.from({ length: n }, (_, i) => dv.getUint32(offset + 4 * i, true));
};

/** Bernstein's `quarterround`, applied in place at the four given indices. */
const refQuarterRound = (x: number[], i0: number, i1: number, i2: number, i3: number): void => {
  const at = (i: number): number => x[i] as number;
  x[i1] = (at(i1) ^ rotl((at(i0) + at(i3)) >>> 0, 7)) >>> 0;
  x[i2] = (at(i2) ^ rotl((at(i1) + at(i0)) >>> 0, 9)) >>> 0;
  x[i3] = (at(i3) ^ rotl((at(i2) + at(i1)) >>> 0, 13)) >>> 0;
  x[i0] = (at(i0) ^ rotl((at(i3) + at(i2)) >>> 0, 18)) >>> 0;
};

/** `columnround` then `rowround`, starting each quarter round on the diagonal. */
const COLUMN: readonly (readonly [number, number, number, number])[] = [
  [0, 4, 8, 12],
  [5, 9, 13, 1],
  [10, 14, 2, 6],
  [15, 3, 7, 11],
];
const ROW: readonly (readonly [number, number, number, number])[] = [
  [0, 1, 2, 3],
  [5, 6, 7, 4],
  [10, 11, 8, 9],
  [15, 12, 13, 14],
];

/** The four `"expand 32-byte k"` words, as Bernstein's little-endian readings. */
const REF_CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/**
 * One 64-byte Salsa20 block for (key, nonce, counter) — the diagonal state
 * assembly, twenty rounds, the feed-forward, and little-endian serialization.
 */
const refBlock = (key: Uint8Array, nonce: Uint8Array, counter: bigint): Uint8Array => {
  const k = leWords(key, 0, 8);
  const n = leWords(nonce, 0, 2);
  const [c0, c1, c2, c3] = REF_CONSTANTS as [number, number, number, number];

  // The diagonal layout: constants at 0, 5, 10, 15; key split across 1–4 and
  // 11–14; nonce at 6–7; counter at 8–9, low word first.
  const initial: number[] = [
    c0,
    k[0] as number,
    k[1] as number,
    k[2] as number,
    k[3] as number,
    c1,
    n[0] as number,
    n[1] as number,
    Number(counter & 0xffffffffn),
    Number((counter >> 32n) & 0xffffffffn),
    c2,
    k[4] as number,
    k[5] as number,
    k[6] as number,
    k[7] as number,
    c3,
  ];

  const x = [...initial];
  for (let i = 0; i < 10; i++) {
    for (const [a, b, c, d] of [...COLUMN, ...ROW]) refQuarterRound(x, a, b, c, d);
  }

  const out = new Uint8Array(SALSA20_BLOCK_BYTES);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) {
    dv.setUint32(4 * i, (((x[i] as number) + (initial[i] as number)) >>> 0) >>> 0, true);
  }
  return out;
};

/** `length` bytes of reference keystream from `counter` onward. */
const refKeystream = (
  key: Uint8Array,
  nonce: Uint8Array,
  counter: bigint,
  length: number,
): Uint8Array => {
  const out = new Uint8Array(length);
  for (let i = 0; i * SALSA20_BLOCK_BYTES < length; i++) {
    out.set(
      refBlock(key, nonce, counter + BigInt(i)).subarray(
        0,
        Math.min(SALSA20_BLOCK_BYTES, length - i * SALSA20_BLOCK_BYTES),
      ),
      i * SALSA20_BLOCK_BYTES,
    );
  }
  return out;
};

// ─── Fixtures ─────────────────────────────────────────────────────────────

/** Vector A — sequential key, simple nonce. */
const KEY_A = new Uint8Array(32).map((_, i) => i);
const NONCE_A = "4041424344454647";

/** Vector B — eSTREAM/ECRYPT verified vectors, Set 6, vector 0. */
const KEY_B = fromHex("0053a6f94c9ff24598eb3e91e4378add3083d6297ccf2275c81b6ec11467ba0d");
const NONCE_B = "0d74db42a91077de";

/** Vector C — the all-zero edge case. */
const KEY_C = new Uint8Array(32);
const NONCE_C = "0000000000000000";

// ─── 1. The reference implementation vs. the app ──────────────────────────

describe("Salsa20 — the app's keystream matches an independent reference implementation", () => {
  // This is the primary anchor. `refBlock` is plain word arithmetic written
  // from Bernstein's spec; the app is a port graph of byte-shuffling steps.
  // Agreement across 128 bytes pins the quarter round, the four rotation
  // constants, the column/row index tuples, the diagonal state assembly, the
  // little-endian crossings and the counter start simultaneously.
  const cases: ReadonlyArray<readonly [string, Uint8Array, string]> = [
    ["sequential key", KEY_A, NONCE_A],
    ["eSTREAM Set 6 vector 0", KEY_B, NONCE_B],
    ["all-zero key and nonce", KEY_C, NONCE_C],
  ];

  for (const [label, key, nonceHex] of cases) {
    it(`agrees over two blocks — ${label}`, () => {
      const iv = packIv(0n, nonceHex);
      const actual = keystream(key, iv, 2 * SALSA20_BLOCK_BYTES);
      const expected = refKeystream(key, fromHex(nonceHex), 0n, 2 * SALSA20_BLOCK_BYTES);
      expect(toHex(actual)).toBe(toHex(expected));
    });
  }
});

// ─── 2. Pinned third-party vectors ────────────────────────────────────────

describe("Salsa20 — pinned pycryptodome vectors (no live oracle exists)", () => {
  // Generated offline from `Crypto.Cipher.Salsa20`, pycryptodome 3.23, with the
  // counter starting at 0 (the only start that library offers). These literals
  // are the third-party half of the two-source agreement described in the
  // header — if the app and `refBlock` ever drift together, these still fail.
  it("vector A — sequential key, first two blocks of keystream", () => {
    expect(toHex(keystream(KEY_A, packIv(0n, NONCE_A), 2 * SALSA20_BLOCK_BYTES))).toBe(
      "d2518e89c545cbabdebd227bdfca66275a95fed248504b6108980f7088e55b5a8" +
        "b511b5054009d7fa8ddc02326e8cc30a32b70c0bef1879f65987956a7d3a9a3" +
        "25ffdeee7c3a5e3886d92c5209bf059eafa0101bd25a933788e987ceabc2d7e9" +
        "df4809b8de0822c3f286c3e082341ee9dfbc8234db2de161b09e435575f8572f",
    );
  });

  it("vector B — eSTREAM Set 6 vector 0, first block of keystream", () => {
    expect(toHex(keystream(KEY_B, packIv(0n, NONCE_B), SALSA20_BLOCK_BYTES))).toBe(
      "f5fad53f79f9df58c4aea0d0ed9a9601f278112ca7180d565b420a48019670ea" +
        "f24ce493a86263f677b46ace1924773d2bb25571e1aa8593758fc382b1280b71",
    );
  });

  it("vector C — all-zero key and nonce, first block of keystream", () => {
    expect(toHex(keystream(KEY_C, packIv(0n, NONCE_C), SALSA20_BLOCK_BYTES))).toBe(
      "9a97f65b9b4c721b960a672145fca8d4e32e67f9111ea979ce9c4826806aeee6" +
        "3de9c0da2bd7f91ebcb2639bf989c6251b29bf38d39a9bdce7c55f4b2ac12a39",
    );
  });

  it("encrypts a short, non-block-multiple message", () => {
    const pt = new TextEncoder().encode("hello");
    expect(toHex(run(salsa20EncryptSpec, pt, KEY_A, packIv(0n, NONCE_A)))).toBe("ba34e2e5aa");
  });
});

// ─── 3. The diagonal state assembly, localized ────────────────────────────

describe("Salsa20 — the state is assembled on the diagonal, not in four regions", () => {
  // The keystream tests above would FAIL on a ChaCha20-style region layout, but
  // they would not say why. This one reads the assembled state straight out of
  // the trace, so a layout regression names itself instead of presenting as
  // "the keystream is wrong".
  it("places constants at words 0, 5, 10 and 15 with the key split around them", () => {
    const trace = runSpec(salsa20EncryptSpec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(SALSA20_BLOCK_BYTES) },
      initialAux: new Map<string, AuxValue>([
        ["key", KEY_A],
        ["iv", packIv(0n, NONCE_A)],
      ]),
    });

    // The first block's state-init frame. Iterate frames are suffixed `:b{i}`.
    const frame = trace.frames.find((f) => f.stepId.startsWith("state-init"));
    expect(frame, "expected a state-init frame in the trace").toBeDefined();
    const state = framePrimaryOutBytes(frame as NonNullable<typeof frame>);
    expect(state).not.toBeNull();
    expect((state as Uint8Array).length).toBe(SALSA20_BLOCK_BYTES);

    // Words travel big-endian inside the spec, so each word reads directly.
    const dv = new DataView(
      (state as Uint8Array).buffer,
      (state as Uint8Array).byteOffset,
      (state as Uint8Array).byteLength,
    );
    const word = (i: number): number => dv.getUint32(4 * i, false /* big-endian */);

    // The diagonal carries the constants.
    expect([word(0), word(5), word(10), word(15)]).toEqual(REF_CONSTANTS);

    // The key occupies 1–4 and 11–14 — split, not contiguous. Under the
    // big-endian wire convention each word is the LE reading of the key bytes.
    const k = leWords(KEY_A, 0, 8);
    expect([word(1), word(2), word(3), word(4)]).toEqual(k.slice(0, 4));
    expect([word(11), word(12), word(13), word(14)]).toEqual(k.slice(4, 8));

    // Nonce at 6–7; counter at 8–9, low word first (both zero on block 0).
    expect([word(6), word(7)]).toEqual(leWords(fromHex(NONCE_A), 0, 2));
    expect([word(8), word(9)]).toEqual([0, 0]);
  });
});

// ─── 4. Counter advance, including the 64-bit carry ───────────────────────

describe("Salsa20 — the 64-bit counter advances by exactly one per block", () => {
  // A single-block KAT structurally cannot see a counter that fails to advance.
  it("block n's keystream equals the block function at (initial + n)", () => {
    const iv = packIv(0n, NONCE_A);
    const ks = keystream(KEY_A, iv, 3 * SALSA20_BLOCK_BYTES);
    for (let n = 0; n < 3; n++) {
      const block = ks.subarray(n * SALSA20_BLOCK_BYTES, (n + 1) * SALSA20_BLOCK_BYTES);
      expect(toHex(block), `block ${n}`).toBe(toHex(refBlock(KEY_A, fromHex(NONCE_A), BigInt(n))));
    }
  });

  it("honours a non-zero starting counter", () => {
    // Seeking: block 0 from counter 7 must equal block 7 from counter 0.
    const fromSeven = keystream(KEY_A, packIv(7n, NONCE_A), SALSA20_BLOCK_BYTES);
    expect(toHex(fromSeven)).toBe(toHex(refBlock(KEY_A, fromHex(NONCE_A), 7n)));
  });

  it("carries from the low counter word into the high one at 2³²", () => {
    // THE 64-bit test. Starting at 2³² − 1, the second block's counter is 2³²,
    // which is zero in the low word and one in the high word. An implementation
    // that incremented the two counter words independently — or that reversed
    // the counter as two 4-byte words rather than one 8-byte number — produces
    // the right first block and the wrong second one.
    const start = (1n << 32n) - 1n;
    const ks = keystream(KEY_A, packIv(start, NONCE_A), 2 * SALSA20_BLOCK_BYTES);
    expect(toHex(ks.subarray(0, SALSA20_BLOCK_BYTES)), "block at 2³²−1").toBe(
      toHex(refBlock(KEY_A, fromHex(NONCE_A), start)),
    );
    expect(toHex(ks.subarray(SALSA20_BLOCK_BYTES)), "block at 2³² (after the carry)").toBe(
      toHex(refBlock(KEY_A, fromHex(NONCE_A), start + 1n)),
    );
  });
});

// ─── 5. Arbitrary message lengths ─────────────────────────────────────────

describe("Salsa20 — any length ≥ 1, ciphertext exactly as long as the plaintext", () => {
  // No padding is ever engaged: `paddingLimits` answers {min: 1} for the stream
  // mode and `buildCanonicalPair` splices in no pad step.
  const lengths = [1, 7, 63, 64, 65, 127, 128, 129, 200];

  for (const n of lengths) {
    it(`${n} bytes — output length matches and bytes match the reference`, () => {
      const pt = new Uint8Array(n).map((_, i) => (i * 7 + 3) & 0xff);
      const iv = packIv(0n, NONCE_A);
      const ct = run(salsa20EncryptSpec, pt, KEY_A, iv);

      expect(ct.length, "ciphertext length").toBe(n);

      const ks = refKeystream(KEY_A, fromHex(NONCE_A), 0n, n);
      const expected = pt.map((b, i) => b ^ (ks[i] as number));
      expect(toHex(ct)).toBe(toHex(expected));
    });
  }

  it("matches a pinned pycryptodome ciphertext for a 200-byte message", () => {
    // 200 bytes spans four counter values with a 8-byte final block, so this
    // one literal covers the multi-block path and the ragged tail together.
    const pt = new Uint8Array(200).map((_, i) => (i * 7 + 3) & 0xff);
    expect(toHex(run(salsa20EncryptSpec, pt, KEY_A, packIv(0n, NONCE_A)))).toBe(
      "d15b9f91da63e69fe5ff6b2b8894034b29ef7f5ac7c6d6c5a32ab6b04f2b8e866" +
        "8bbeaa8ab06906bb3ffe91311d6897cf07111a8d187fa1bee0ae0f6007d1c1fe" +
        "6350f36a3dcb3cc7ddb25421ea120b29c9a51539d0cce53e39bfe4e2c4c42757" +
        "ce2b80061ceef1729642a1075ca1be5cca6a31cf41bdc25fbcc1a3512962253" +
        "6d5cb7fa43e956b22bf2c3be14335ec4c325ad31726f7cd948f60e9f263f5855" +
        "e92f6e93beb8d0a4e2b0146d6dac72d5edf325aad623fc18c1ca41886308931a" +
        "10f76d24dfc3f34f",
    );
  });
});

// ─── 6. Round-trip — ranked last, and proving nothing on its own ──────────

describe("Salsa20 — round-trip (a tautology, kept only for completeness)", () => {
  // The encrypt and decrypt specs are structurally identical, so this holds by
  // construction even on a completely wrong cipher. It is here to catch a
  // registration mistake — a decrypt spec accidentally wired to a different
  // key or IV source — and for nothing else. Everything above is the real test.
  it("decrypt(encrypt(m)) === m", () => {
    const pt = new TextEncoder().encode("The tautology is the point: this cannot fail usefully.");
    const iv = packIv(3n, NONCE_B);
    const ct = run(salsa20EncryptSpec, pt, KEY_B, iv);
    expect(toHex(run(salsa20DecryptSpec, ct, KEY_B, iv))).toBe(toHex(pt));
  });
});
