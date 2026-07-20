/**
 * CTR partial-block (ragged tail) known-answer tests — the assertions that
 * make "CTR needs no padding" a fact about this build rather than a claim in
 * its narration.
 *
 * ## What is newly representable
 *
 * Before the partial-block work (2026-07-20) a CTR message had to reach a
 * block boundary: the port-mode iterate rejected a non-multiple `seedInput`
 * and `xor@1` requires equal-length operands. So `L % B !== 0` was impossible,
 * and `L < B` — a whole message shorter than one cipher block — was not
 * representable at all. Both are covered here, and the second is the headline:
 * it is the case where the ciphertext is shorter than a single block, which no
 * block mode can produce.
 *
 * ## Oracles
 *
 * 1. **External, for AES** — `node:crypto`'s `aes-128-ctr` handles the ragged
 *    tail natively and is the gold reference. It pins not just "some bytes
 *    came out" but that the SURVIVING bytes are the correct prefix of the
 *    keystream — a trim that kept the wrong end, or trimmed the message
 *    instead of the keystream, would still produce L bytes and still
 *    round-trip, and would fail only here.
 *
 * 2. **Round-trip identity, for every core** — swept across `L = 1 … 3B+1` for
 *    all ten cores. This is the block-size-generic sweep, and it is where a
 *    stray `>= B` or hardcoded `16` assumption surfaces: Speck32/64's 4-byte
 *    block means `L = 1..13` spans four distinct raggedness classes, and the
 *    Speck lesson (its block is smaller than every "round" width) is exactly
 *    the kind of floor this catches. Round-trip is a sound check for CTR
 *    specifically because decrypt runs the same FORWARD path — it is not the
 *    usual "both sides share the bug" weak check for an inverse cipher, though
 *    the AES oracle above is still the stronger assertion.
 *
 * A length-only regression is asserted too (`ciphertext.length === L`), because
 * a silently re-padded output would satisfy neither oracle's shape but might
 * survive a careless read of a hex string.
 *
 * References: NIST SP 800-38A §6.5 (CTR mode — the final partial block).
 */

import { createCipheriv } from "node:crypto";
import { aesCore } from "@/ciphers/aes-core";
import type { BlockCipherCore } from "@/ciphers/block-cipher-core";
import { blowfishCore } from "@/ciphers/blowfish-core";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desCore } from "@/ciphers/des-core";
import { buildCtrSpec } from "@/ciphers/modes/ctr";
import { serpentCore } from "@/ciphers/serpent-core";
import { speck32_64Core } from "@/ciphers/speck-32-64-core";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import type { Cipher } from "@/ui/stores/cipher";
import { describe, expect, it } from "vitest";

// ─── Cores + material (mirrors ctr-all-cores-kat.test.ts) ────────────────────

const CORES: ReadonlyArray<{ cipher: Cipher; core: BlockCipherCore }> = [
  { cipher: "aes-128", core: aesCore("aes-128") },
  { cipher: "aes-192", core: aesCore("aes-192") },
  { cipher: "aes-256", core: aesCore("aes-256") },
  { cipher: "speck-32-64-be", core: speck32_64Core("be-paper") },
  { cipher: "speck-32-64-le", core: speck32_64Core("le-nsa") },
  { cipher: "blowfish", core: blowfishCore() },
  { cipher: "des", core: desCore() },
  { cipher: "serpent-128", core: serpentCore(16) },
  { cipher: "serpent-192", core: serpentCore(24) },
  { cipher: "serpent-256", core: serpentCore(32) },
];

const fillByte = (i: number): number => (i * 37 + 11) & 0xff;
const fillHex = (n: number): string =>
  Array.from({ length: n }, (_, i) => fillByte(i).toString(16).padStart(2, "0")).join("");

const keyFor = (core: BlockCipherCore): string => fillHex(core.keyByteLength);

/** T₀ ending in 0xFE so a multi-block sweep crosses a carry ripple. */
const ivFor = (core: BlockCipherCore): string => `${fillHex(core.blockByteLength).slice(0, -2)}fe`;

/** A distinctive `n`-byte message — no zero bytes, so a dropped byte shows. */
const messageOfLength = (n: number): string =>
  Array.from({ length: n }, (_, i) =>
    (((i * 53 + 7) & 0xff) | 1).toString(16).padStart(2, "0"),
  ).join("");

const runMode = (spec: CipherSpec, inputHex: string, keyHex: string, ivHex: string): string => {
  const aux = new Map<string, AuxValue>([
    ["key", bytesFromHex(keyHex)],
    ["iv", bytesFromHex(ivHex)],
  ]);
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: aux,
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return hexFromBytes(trace.finalState.bytes);
};

// ─── The external oracle: AES-128 vs node:crypto ─────────────────────────────

describe("CTR ragged tail — AES-128 vs node:crypto (external oracle)", () => {
  const core = aesCore("aes-128");
  const key = keyFor(core);
  const iv = ivFor(core);
  const B = core.blockByteLength; // 16

  /** node's own aes-128-ctr over the same material. */
  const nodeCtr = (messageHex: string): string => {
    const c = createCipheriv("aes-128-ctr", bytesFromHex(key), bytesFromHex(iv));
    return Buffer.concat([c.update(Buffer.from(messageHex, "hex")), c.final()]).toString("hex");
  };

  // The headline: a message SHORTER than one block. Previously unrepresentable
  // — the iterate threw before the cipher ever ran.
  for (const L of [1, 5, B - 1]) {
    it(`L=${L} (< one ${B}-byte block) matches node, and the ciphertext is ${L} bytes`, () => {
      const pt = messageOfLength(L);
      const ct = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
      expect(ct).toBe(nodeCtr(pt));
      expect(ct.length / 2).toBe(L);
    });
  }

  // Multi-block messages that end mid-block: the trim runs on the LAST block
  // only, so these also assert the earlier blocks were left whole.
  for (const L of [B + 1, B + 7, 2 * B + 3, 3 * B - 1]) {
    it(`L=${L} (${L % B} bytes past a block boundary) matches node`, () => {
      const pt = messageOfLength(L);
      const ct = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
      expect(ct).toBe(nodeCtr(pt));
      expect(ct.length / 2).toBe(L);
    });
  }

  // Regression: whole-block messages must be byte-identical to before. The
  // trim is a passthrough here, and `ceil` degenerates to exact division.
  for (const L of [B, 2 * B, 4 * B]) {
    it(`L=${L} (whole blocks) is unchanged — the trim is a no-op`, () => {
      const pt = messageOfLength(L);
      const ct = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
      expect(ct).toBe(nodeCtr(pt));
      expect(ct.length / 2).toBe(L);
    });
  }

  it("decrypt of a ragged ciphertext recovers the ragged plaintext", () => {
    const pt = messageOfLength(B + 5);
    const ct = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
    expect(runMode(buildCtrSpec(core, "decrypt"), ct, key, iv)).toBe(pt);
  });

  it("the trimmed tail is the PREFIX of the keystream, not some other slice", () => {
    // A trim that kept the wrong end would still produce L bytes and still
    // round-trip. This pins it directly: the ciphertext of an L-byte message
    // must equal the first L bytes of the ciphertext of a full-block message
    // with the same leading bytes, since CTR's keystream doesn't depend on
    // the message at all.
    const L = 5;
    const short = messageOfLength(L);
    const padded = short + "00".repeat(B - L);
    const ctShort = runMode(buildCtrSpec(core, "encrypt"), short, key, iv);
    const ctFull = runMode(buildCtrSpec(core, "encrypt"), padded, key, iv);
    expect(ctShort).toBe(ctFull.slice(0, L * 2));
  });
});

// ─── The block-size-generic sweep: every core, L = 1 … 3B+1 ──────────────────

describe("CTR ragged tail — round-trip identity across every core and length", () => {
  for (const { cipher, core } of CORES) {
    const B = core.blockByteLength;
    const key = keyFor(core);
    const iv = ivFor(core);

    it(`${cipher} (B=${B}) round-trips every length 1…${3 * B + 1} with exact length preservation`, () => {
      for (let L = 1; L <= 3 * B + 1; L++) {
        const pt = messageOfLength(L);
        const ct = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
        // Length preservation is the property padding would destroy.
        expect(ct.length / 2, `${cipher} L=${L}: ciphertext length`).toBe(L);
        // And the bytes come back.
        expect(runMode(buildCtrSpec(core, "decrypt"), ct, key, iv), `${cipher} L=${L}`).toBe(pt);
        // A stream cipher must actually transform: identity would round-trip.
        expect(ct, `${cipher} L=${L}: ciphertext equals plaintext`).not.toBe(pt);
      }
    });
  }
});
