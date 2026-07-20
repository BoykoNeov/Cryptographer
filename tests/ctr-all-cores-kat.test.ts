/**
 * CTR known-answer tests across **every** `BlockCipherCore` — the broadest
 * single assertion the mode machine has.
 *
 * ## Why CTR is the sharpest test of the core contract
 *
 * ECB and CBC both feed the cipher body the message block (CBC XORs it with
 * the chain first, but the bytes still originate at `port(iterate,"in")`). CTR
 * does not: it feeds the body the **counter**, taken from the iterate's `chain`
 * port, and the message block never enters the cipher at all. Any core that
 * merely *happened* to work because its seed arrived from the usual direction
 * fails here. That is what "a good test for all the cores" means concretely —
 * every core's forward body is re-seeded from a port it has never been seeded
 * from before, ten cores over four distinct block widths (4, 8, 16 bytes).
 *
 * CTR also runs the FORWARD body on decrypt, so the decrypt direction is a
 * second independent exercise of the same path rather than a mirror.
 *
 * ## Two oracles, deliberately
 *
 * 1. **External, for AES** — `node:crypto`'s `aes-{128,192,256}-ctr` is a real
 *    independent implementation. It pins the counter convention (big-endian,
 *    incrementing the whole block) that nothing internal could confirm: a
 *    little-endian counter would round-trip perfectly and still be wrong.
 *
 * 2. **Constructed-from-ECB, for every core** — the keystream is rebuilt here
 *    by encrypting T₀, T₀+1, … through the core's *own already-KAT-verified
 *    ECB spec*, then XORed with the message by hand. This is not circular: ECB
 *    is verified against published vectors in the per-cipher KAT files, and the
 *    counter arithmetic + XOR are re-implemented independently below. It
 *    catches exactly what a round-trip cannot — a keystream that is
 *    self-consistent but not CTR.
 *
 * Round-trip is asserted too, but as the *weakest* of the three: encrypt and
 * decrypt sharing a bug would satisfy it.
 *
 * References: NIST SP 800-38A §6.5 + Appendix B.1 (CTR).
 */

import { createCipheriv } from "node:crypto";
import { aesCore } from "@/ciphers/aes-core";
import type { BlockCipherCore } from "@/ciphers/block-cipher-core";
import { blowfishCore } from "@/ciphers/blowfish-core";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desCore } from "@/ciphers/des-core";
import { buildCtrSpec } from "@/ciphers/modes/ctr";
import { buildEcbSpec } from "@/ciphers/modes/ecb";
import { serpentCore } from "@/ciphers/serpent-core";
import { speck32_64Core } from "@/ciphers/speck-32-64-core";
import { runSpec } from "@/core/runtime";
import { applyPaddingScheme } from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { hasBlockCipherCore } from "@/ui/stores/block-cipher-cores";
import type { Cipher } from "@/ui/stores/cipher";
import { isCipherModeSupported } from "@/ui/stores/cipher-mode";
import { paddingLimits } from "@/ui/stores/padding";
import { describe, expect, it } from "vitest";

// ─── The cores under test ─────────────────────────────────────────────────────

/**
 * Mirrors `BLOCK_CIPHER_CORES` in `stores/block-cipher-cores.ts` (which isn't
 * exported). The "covers every cored cipher" test below fails if the two drift,
 * so a new core cannot land without gaining CTR coverage here.
 */
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

const ALL_CIPHERS: readonly Cipher[] = [
  "aes-128",
  "aes-192",
  "aes-256",
  "speck-32-64-be",
  "speck-32-64-le",
  "blowfish",
  "des",
  "serpent-128",
  "serpent-192",
  "serpent-256",
  "twofish",
];

// ─── Deterministic per-core test material ─────────────────────────────────────

/** A fixed, nonzero, non-patterned byte at index i — no accidental symmetry. */
const fillByte = (i: number): number => (i * 37 + 11) & 0xff;
const fillHex = (n: number): string =>
  Array.from({ length: n }, (_, i) => fillByte(i).toString(16).padStart(2, "0")).join("");

/** Key of the core's width. */
const keyFor = (core: BlockCipherCore): string => fillHex(core.keyByteLength);

/**
 * Initial counter T₀, one block wide. Deliberately ends in 0xFE so that
 * incrementing across a 4-block message crosses a byte-carry boundary
 * (…FE → …FF → …00 with a ripple) — a keystream built with a broken carry
 * diverges at block 2 rather than passing by luck.
 */
const ivFor = (core: BlockCipherCore): string => `${fillHex(core.blockByteLength).slice(0, -2)}fe`;

/** Four blocks; blocks 0 and 2 identical, so a stuck counter is visible. */
const plaintextFor = (core: BlockCipherCore): string => {
  const b = core.blockByteLength;
  const blk0 = fillHex(b);
  const blk1 = fillHex(b).split("").reverse().join("");
  const blk3 = "a".repeat(b * 2);
  return `${blk0}${blk1}${blk0}${blk3}`;
};

// ─── Running the app's real specs ─────────────────────────────────────────────

const runMode = (spec: CipherSpec, inputHex: string, keyHex: string, ivHex?: string): string => {
  const aux = new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]);
  if (ivHex !== undefined) aux.set("iv", bytesFromHex(ivHex));
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: aux,
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return hexFromBytes(trace.finalState.bytes);
};

// ─── The constructed oracle: keystream from the core's verified ECB spec ──────

/** Big-endian +1 over a whole block — re-implemented here, NOT imported. */
const bumpCounter = (block: Uint8Array): Uint8Array => {
  const out = new Uint8Array(block);
  for (let i = out.length - 1; i >= 0; i--) {
    const v = ((out[i] as number) + 1) & 0xff;
    out[i] = v;
    if (v !== 0) break;
  }
  return out;
};

/**
 * Expected CTR output, built from first principles: encrypt T₀, T₀+1, … through
 * the core's ECB spec to get the keystream, then XOR with the message.
 *
 * Uses ECB (not the CTR spec) so this is genuinely independent of the code
 * under test — ECB's correctness is pinned by the per-cipher KAT files.
 */
const ctrOracle = (core: BlockCipherCore, messageHex: string, keyHex: string, ivHex: string) => {
  const b = core.blockByteLength;
  const message = bytesFromHex(messageHex);
  const blockCount = message.length / b;

  // The counter sequence T₀, T₀+1, …, concatenated into one buffer.
  let counter = bytesFromHex(ivHex);
  const counters = new Uint8Array(blockCount * b);
  for (let i = 0; i < blockCount; i++) {
    counters.set(counter, i * b);
    counter = bumpCounter(counter);
  }

  // One ECB pass encrypts every counter block independently — which is exactly
  // what CTR's keystream is.
  const keystream = bytesFromHex(
    runMode(buildEcbSpec(core, "encrypt"), hexFromBytes(counters), keyHex),
  );

  const out = new Uint8Array(message.length);
  for (let i = 0; i < message.length; i++) {
    out[i] = (message[i] as number) ^ (keystream[i] as number);
  }
  return hexFromBytes(out);
};

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("CTR across every BlockCipherCore", () => {
  it("covers every cipher that has a core (guards against a new core skipping CTR)", () => {
    const cored = ALL_CIPHERS.filter((c) => hasBlockCipherCore(c));
    expect(CORES.map((e) => e.cipher).sort()).toEqual([...cored].sort());
  });

  it("every cored cipher advertises CTR in the mode table", () => {
    for (const { cipher } of CORES) {
      expect(isCipherModeSupported(cipher, "ctr")).toBe(true);
    }
    // Twofish has no core, so it must NOT advertise CTR.
    expect(isCipherModeSupported("twofish", "ctr")).toBe(false);
  });

  // ── The external oracle: AES vs node:crypto ────────────────────────────────
  describe("AES — byte-equal to node:crypto's aes-*-ctr (external oracle)", () => {
    for (const variant of ["aes-128", "aes-192", "aes-256"] as const) {
      const core = aesCore(variant);
      const key = keyFor(core);
      const iv = ivFor(core);
      const pt = plaintextFor(core);

      it(`${variant} encrypt matches node's ${variant}-ctr`, () => {
        // This is the assertion that pins the counter CONVENTION. A
        // little-endian or partial-width counter would still round-trip
        // perfectly inside the app and fail only here.
        const c = createCipheriv(`${variant}-ctr`, bytesFromHex(key), bytesFromHex(iv));
        const expected = Buffer.concat([c.update(Buffer.from(pt, "hex")), c.final()]).toString(
          "hex",
        );
        expect(runMode(buildCtrSpec(core, "encrypt"), pt, key, iv)).toBe(expected);
      });

      it(`${variant} decrypt matches node too (CTR decrypt encrypts)`, () => {
        const ct = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
        // node's CTR "decrypt" is the same transform; use createCipheriv again
        // to make the point that nothing inverse is happening.
        const c = createCipheriv(`${variant}-ctr`, bytesFromHex(key), bytesFromHex(iv));
        const expected = Buffer.concat([c.update(Buffer.from(ct, "hex")), c.final()]).toString(
          "hex",
        );
        expect(runMode(buildCtrSpec(core, "decrypt"), ct, key, iv)).toBe(expected);
      });
    }
  });

  // ── The constructed oracle + structural properties, per core ───────────────
  for (const { cipher, core } of CORES) {
    describe(`${cipher} (${core.blockByteLength}-byte block)`, () => {
      const key = keyFor(core);
      const iv = ivFor(core);
      const pt = plaintextFor(core);

      it("encrypts to keystream ⊕ message, where the keystream is its own ECB over T₀, T₀+1, …", () => {
        // The strongest internal assertion: it would catch a counter that
        // doesn't advance, advances wrongly, or is XORed in the wrong order —
        // none of which a round-trip notices.
        expect(runMode(buildCtrSpec(core, "encrypt"), pt, key, iv)).toBe(
          ctrOracle(core, pt, key, iv),
        );
      });

      it("decrypt runs the SAME transform as encrypt (XOR is its own inverse)", () => {
        // Not a mirror: both specs run the forward body. Feeding the plaintext
        // to the decrypt spec must produce the ciphertext.
        const viaEncrypt = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
        const viaDecrypt = runMode(buildCtrSpec(core, "decrypt"), pt, key, iv);
        expect(viaDecrypt).toBe(viaEncrypt);
      });

      it("round-trips plaintext → ciphertext → plaintext", () => {
        const ct = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
        expect(runMode(buildCtrSpec(core, "decrypt"), ct, key, iv)).toBe(pt);
        expect(ct).not.toBe(pt);
      });

      it("does NOT leak the repeated plaintext block that ECB leaks", () => {
        // Blocks 0 and 2 of the plaintext are identical. Under ECB they would
        // encrypt identically; under CTR the counter differs, so they must not.
        const b = core.blockByteLength * 2; // hex chars per block
        const ct = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
        expect(ct.slice(0, b)).not.toBe(ct.slice(2 * b, 3 * b));
      });

      it("a different initial counter changes the entire ciphertext", () => {
        const ctA = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
        const zeroIv = "00".repeat(core.blockByteLength);
        const ctB = runMode(buildCtrSpec(core, "encrypt"), pt, key, zeroIv);
        expect(ctB).not.toBe(ctA);
        expect(ctB).toBe(ctrOracle(core, pt, key, zeroIv));
      });

      it("the counter carry crosses a byte boundary correctly across blocks", () => {
        // T₀ ends in 0xFE, so blocks 1→2 cross …FF → …00 with a ripple into
        // the next byte up. A broken carry produces a keystream that is still
        // self-consistent (so the round-trip passes) but diverges from the
        // ECB-built oracle from block 2 onward — this isolates that.
        const ct = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
        const expected = ctrOracle(core, pt, key, iv);
        const b = core.blockByteLength * 2;
        expect(ct.slice(2 * b, 3 * b)).toBe(expected.slice(2 * b, 3 * b));
        expect(ct.slice(3 * b, 4 * b)).toBe(expected.slice(3 * b, 4 * b));
      });

      it("takes the padding overlay, so a short message reaches a block boundary", () => {
        // v1 CTR is block-aligned, so the padding overlay must actually apply
        // to it — `needsAlignment` in App.tsx SKIPS the alignment check when a
        // padding scheme is set, on the assumption that a pad gets spliced in.
        // If that assumption were wrong (e.g. the overlay gated on
        // `cipherMode ∈ {ecb,cbc}`), a short input would reach the iterate raw
        // and throw "not a multiple of blockByteLength". It is gated on core
        // PRESENCE instead, which is why CTR gets it for free — asserted here
        // rather than inferred from the call site.
        const b = core.blockByteLength;
        // One byte short of a whole block ⇒ PKCS#7 must append exactly one 0x01.
        const short = "7e".repeat(b - 1);
        const enc = applyPaddingScheme(buildCtrSpec(core, "encrypt"), "encrypt", "pkcs7", b);
        const ct = runMode(enc, short, key, iv);
        expect(ct.length / 2).toBe(b);

        // And it round-trips: decrypt(unpad) recovers the original short input.
        const dec = applyPaddingScheme(buildCtrSpec(core, "decrypt"), "decrypt", "pkcs7", b);
        expect(runMode(dec, ct, key, iv)).toBe(short);
      });

      it("paddingLimits bounds CTR like the other multi-block modes (v1: whole blocks)", () => {
        // Pinned because CTR's bounds are a deliberate v1 compromise, not the
        // mode's real behaviour: real CTR needs no padding at all. If the
        // partial-block follow-up lands, THIS is the assertion that should
        // change, which is exactly why it names the block width explicitly.
        const b = core.blockByteLength;
        expect(paddingLimits("decrypt", "none", cipher, "ctr")).toEqual(
          paddingLimits("decrypt", "none", cipher, "cbc"),
        );
        expect(paddingLimits("decrypt", "none", cipher, "ctr").min).toBe(b);
      });

      it("the cipher body is seeded from the COUNTER, never from the message block", () => {
        // The structural claim this whole file rests on: change only the
        // message and the keystream must be unchanged, so the two ciphertexts
        // differ from each other by exactly the plaintext difference.
        const altPt = "00".repeat(pt.length / 2);
        const ctA = runMode(buildCtrSpec(core, "encrypt"), pt, key, iv);
        const ctB = runMode(buildCtrSpec(core, "encrypt"), altPt, key, iv);
        const a = bytesFromHex(ctA);
        const bb = bytesFromHex(ctB);
        const p = bytesFromHex(pt);
        for (let i = 0; i < a.length; i++) {
          // ctA ⊕ ctB === ptA ⊕ ptB === ptA (since ptB is all zeros).
          expect((a[i] as number) ^ (bb[i] as number)).toBe(p[i] as number);
        }
      });
    });
  }
});
