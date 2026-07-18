/**
 * Speck32/64 ECB + CBC known-answer tests — the proof that the cipher-agnostic
 * mode machine drives Speck's 4-byte-block ARX body per block, under BOTH byte
 * conventions.
 *
 * ## What this file adds over the existing coverage
 *
 * Speck's single-block cores are already KAT-verified (`speck-vectors.test.ts`,
 * against Beaulieu et al. 2013 Table 4.1), and the mode machine is already
 * generic-verified (AES + Blowfish + a fake 8-byte core in
 * `block-size-generic-modes.test.ts`). What was NOT covered until now is the
 * composition at a **sub-8-byte block**: the generic `modes/ecb.ts` /
 * `modes/cbc.ts` builders running the REAL Speck body once per 4-byte block,
 * with the key schedule hoisted outside the loop and the chain value crossing
 * iterations over a 4-byte-wide IV.
 *
 * ## Why the 4-byte block earns its keep here (advisor 2026-07-18)
 *
 * An exact-multiple ECB/CBC round-trip alone would only re-run paths already
 * proven at 8 and 16 bytes — it tests nothing genuinely new about width 4. The
 * novel surfaces, where a hidden `>= 8` floor would hide, are: the CBC IV at 4
 * bytes, and the padding overlay filling a non-multiple message to a 4-byte
 * boundary (reachable in single-block mode too, per the core-presence policy).
 * So this file asserts both directly, not just an aligned round-trip.
 *
 * ## The oracle
 *
 * `node:crypto` cannot oracle Speck (it isn't an OpenSSL cipher). But no
 * external per-mode oracle is needed: a mode of operation is BY DEFINITION the
 * block cipher repeated under a rule (NIST SP 800-38A §6.1-6.2), so the
 * already-trusted single-block Speck spec IS the oracle for one block, and the
 * ECB/CBC rules compose over it here — the same argument
 * `serpent-modes-kat.test.ts` makes. To guard against the composed oracle and
 * the mode spec sharing a wrong assumption, ECB block 0 is anchored to the
 * PUBLISHED Beaulieu constant (`a86842f2` BE / `f24268a8` LE): under ECB that
 * block is encrypted independently, so a published single-block vector IS a
 * published ECB-block vector.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildCbcSpec } from "@/ciphers/modes/cbc";
import { buildEcbSpec } from "@/ciphers/modes/ecb";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64Core } from "@/ciphers/speck-32-64-core";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
import { deriveAuxGraph, validateGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { applyPaddingScheme } from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import type { SpeckByteOrder } from "@/steps/speck-word-codec";
import type { Cipher } from "@/ui/stores/cipher";
import { paddingLimits } from "@/ui/stores/padding";
import { describe, expect, it } from "vitest";

/** Speck32/64's block is 4 bytes — one 32-bit block, two 16-bit words. */
const B = 4;

/**
 * The two byte conventions as a fixture. Each carries its own single-block spec
 * pair (the composed oracle), its Beaulieu canonical key, and the published
 * anchor pair (plaintext block → ciphertext block, Table 4.1 under each
 * serialization).
 */
const VARIANTS: ReadonlyArray<{
  byteOrder: SpeckByteOrder;
  label: string;
  key: string;
  encSpec: CipherSpec;
  decSpec: CipherSpec;
  anchorPt: string;
  anchorCt: string;
}> = [
  {
    byteOrder: "be-paper",
    label: "BE, paper",
    key: "1918111009080100",
    encSpec: speck32_64BeSpec,
    decSpec: speck32_64BeDecryptSpec,
    anchorPt: "6574694c",
    anchorCt: "a86842f2",
  },
  {
    byteOrder: "le-nsa",
    label: "LE, NSA",
    key: "0001080910111819",
    encSpec: speck32_64LeSpec,
    decSpec: speck32_64LeDecryptSpec,
    anchorPt: "4c697465",
    anchorCt: "f24268a8",
  },
];

// A 4-byte IV — the narrowest chain value the app has ever chained. Arbitrary,
// distinct bytes.
const IV = "0a0b0c0d";

const xorBytes = (a: Uint8Array, b: Uint8Array): Uint8Array =>
  Uint8Array.from(a, (v, i) => v ^ (b[i] ?? 0));

const blocksOf = (bytes: Uint8Array): Uint8Array[] => {
  const out: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += B) out.push(bytes.subarray(i, i + B));
  return out;
};

const joinBlocks = (blocks: readonly Uint8Array[]): string =>
  hexFromBytes(Uint8Array.from(blocks.flatMap((b) => [...b])));

describe.each(VARIANTS)(
  "Speck32/64 ($label) modes — a 4-byte block driven by the generic mode machine",
  ({ byteOrder, key, encSpec, decSpec, anchorPt, anchorCt }) => {
    const core = speck32_64Core(byteOrder);

    /**
     * Four 4-byte blocks. Blocks 0 and 2 are IDENTICAL on purpose (ECB leaks
     * them, CBC hides them). Block 0 is the published anchor plaintext.
     */
    const PT_4_BLOCKS = `${anchorPt}deadbeef${anchorPt}00000000`;

    // ─── The composed oracle: the trusted single-block spec, once per block ─────

    /** One block through the single-block Speck spec. `encrypt=false` decrypts. */
    const oracleBlock = (block: Uint8Array, encrypt: boolean): Uint8Array => {
      const trace = runSpec(encrypt ? encSpec : decSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(block),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(key)]]),
      });
      if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
      return trace.finalState.bytes;
    };

    /** ECB (SP 800-38A §6.1): every block independently, no chaining. */
    const oracleEcb = (inputHex: string, encrypt: boolean): string =>
      joinBlocks(blocksOf(bytesFromHex(inputHex)).map((blk) => oracleBlock(blk, encrypt)));

    /** CBC (SP 800-38A §6.2): C_i = E(P_i ⊕ C_{i-1}); P_i = D(C_i) ⊕ C_{i-1}; C_-1 = IV. */
    const oracleCbc = (ivHex: string, inputHex: string, encrypt: boolean): string => {
      let chain = bytesFromHex(ivHex);
      const out: Uint8Array[] = [];
      for (const blk of blocksOf(bytesFromHex(inputHex))) {
        if (encrypt) {
          const c = oracleBlock(xorBytes(blk, chain), true);
          out.push(c);
          chain = c;
        } else {
          out.push(xorBytes(oracleBlock(blk, false), chain));
          chain = Uint8Array.from(blk);
        }
      }
      return joinBlocks(out);
    };

    // ─── Running the real mode specs ───────────────────────────────────────────

    const runMode = (spec: CipherSpec, inputHex: string, ivHex: string | null): string => {
      const aux = new Map<string, AuxValue>([["key", bytesFromHex(key)]]);
      if (ivHex) aux.set("iv", bytesFromHex(ivHex));
      const trace = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(inputHex)),
        initialAux: aux,
      });
      if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
      return hexFromBytes(trace.finalState.bytes);
    };

    describe("ECB — the ARX body driven per 4-byte block", () => {
      it("the core reports Speck32/64's real geometry (4-byte block, 8-byte key)", () => {
        expect(core.blockByteLength).toBe(4);
        expect(core.keyByteLength).toBe(8);
      });

      it("encrypts every block independently, matching the composed oracle", () => {
        const got = runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, null);
        expect(got).toBe(oracleEcb(PT_4_BLOCKS, true));
        // 4 blocks × 4 bytes = 16 bytes.
        expect(got.length / 2).toBe(16);
      });

      it("decrypt inverts encrypt", () => {
        const ct = runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, null);
        expect(runMode(buildEcbSpec(core, "decrypt"), ct, null)).toBe(PT_4_BLOCKS);
      });

      it("leaks identical plaintext blocks as identical ciphertext blocks", () => {
        // The Tux-image lesson, and the structural contrast with CBC below.
        const ct = blocksOf(
          bytesFromHex(runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, null)),
        );
        expect(hexFromBytes(ct[0] as Uint8Array)).toBe(hexFromBytes(ct[2] as Uint8Array));
      });

      it("its anchor block lands on the PUBLISHED Beaulieu Speck32/64 vector", () => {
        // ECB encrypts each block independently, so the published single-block
        // vector IS a published ECB-block vector. Block 0 is the Table 4.1
        // plaintext under the Table 4.1 key. Ties the file to an EXTERNAL oracle,
        // not only the composed one — the two cannot share a wrong assumption and
        // still hit this constant.
        const ct = blocksOf(
          bytesFromHex(runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, null)),
        );
        expect(hexFromBytes(ct[0] as Uint8Array)).toBe(anchorCt);
      });
    });

    describe("CBC — chaining over a 4-byte block and IV", () => {
      it("matches the composed oracle across 4 blocks (chain feeds forward)", () => {
        const got = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, IV);
        expect(got).toBe(oracleCbc(IV, PT_4_BLOCKS, true));
      });

      it("decrypt inverts encrypt, and matches the oracle directly", () => {
        const ct = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, IV);
        expect(runMode(buildCbcSpec(core, "decrypt"), ct, IV)).toBe(PT_4_BLOCKS);
        expect(runMode(buildCbcSpec(core, "decrypt"), ct, IV)).toBe(oracleCbc(IV, ct, false));
      });

      it("hides the repeated plaintext block that ECB leaks", () => {
        const ct = blocksOf(bytesFromHex(runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, IV)));
        expect(hexFromBytes(ct[0] as Uint8Array)).not.toBe(hexFromBytes(ct[2] as Uint8Array));
      });

      it("reads a 4-byte IV, and a different IV changes the ciphertext", () => {
        // The genuinely novel width-4 surface: the chain value is 4 bytes wide.
        // A hidden `>= 8` floor in `fetch-iv` would surface here.
        const ctA = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, IV);
        const ctB = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, "00000000");
        expect(ctB).not.toBe(ctA);
        expect(ctB).toBe(oracleCbc("00000000", PT_4_BLOCKS, true));
      });
    });

    describe("padding overlay fills to a 4-byte boundary (the sub-8 novelty)", () => {
      // 2 bytes — under one 4-byte block, so PKCS#7 appends two 0x02s. The path an
      // exact-multiple round-trip never touches, and where a stray 8/16 would hide.
      const TWO = Uint8Array.from([0xde, 0xad]);

      /** PKCS#7 (RFC 5652 §6.3), spelled out so the test doesn't reuse the code under test. */
      const pkcs7Pad = (bytes: Uint8Array): Uint8Array => {
        const n = B - (bytes.length % B);
        return Uint8Array.from([...bytes, ...Array.from({ length: n }, () => n)]);
      };

      it("single-block PKCS#7 pads 2 bytes up to ONE 4-byte block, matching the oracle", () => {
        const padded = applyPaddingScheme(encSpec, "encrypt", "pkcs7", core.blockByteLength);
        const ct = runMode(padded, hexFromBytes(TWO), null);
        // If the pad padded to 8 or 16, the length alone would diverge; if it were
        // floating, the body would read 2 raw bytes and the bytes would differ.
        expect(ct).toBe(hexFromBytes(oracleBlock(pkcs7Pad(TWO), true)));
        expect(ct.length / 2).toBe(4);
      });

      it("round-trips a short input: encrypt(pad) then decrypt(unpad) returns the original", () => {
        const enc = applyPaddingScheme(encSpec, "encrypt", "pkcs7", core.blockByteLength);
        const dec = applyPaddingScheme(decSpec, "decrypt", "pkcs7", core.blockByteLength);
        expect(runMode(dec, runMode(enc, hexFromBytes(TWO), null), null)).toBe(hexFromBytes(TWO));
      });

      it("multi-block ECB pads 6 bytes up to 8 (two 4-byte blocks), not 16", () => {
        // The clearest "4, not 8/16" length assertion: 6 bytes pads to 8 at a
        // 4-byte block. Would be 8→16 at an 8-byte one, 16 at a 16-byte one.
        const six = Uint8Array.from({ length: 6 }, (_, i) => i + 1);
        const spec = applyPaddingScheme(
          buildEcbSpec(core, "encrypt"),
          "encrypt",
          "pkcs7",
          core.blockByteLength,
        );
        const ct = runMode(spec, hexFromBytes(six), null);
        expect(ct.length / 2).toBe(8);
        expect(ct).toBe(oracleEcb(hexFromBytes(pkcs7Pad(six)), true));
      });

      it("paddingLimits derives Speck's bounds from its 4-byte core", () => {
        // Pre-core this returned a fixed {4,4} from the coreless switch; now the
        // single-block PKCS#7 encrypt bound is 0..3 (blockSize-1).
        expect(paddingLimits("encrypt", "pkcs7", core.id as Cipher, "single-block")).toEqual({
          min: 0,
          max: 3,
        });
      });
    });

    describe("mode traces stay well-formed", () => {
      it.each([
        ["ecb", () => buildEcbSpec(core, "encrypt"), null],
        ["cbc", () => buildCbcSpec(core, "encrypt"), IV],
      ] as const)("%s: per-iteration frames carry :b{i} stepId suffixes", (_name, build, ivHex) => {
        const trace = runSpec(build(), buildDefaultRegistry(), {
          initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
          initialAux: (() => {
            const aux = new Map<string, AuxValue>([["key", bytesFromHex(key)]]);
            if (ivHex) aux.set("iv", bytesFromHex(ivHex));
            return aux;
          })(),
        });
        for (let i = 0; i < 4; i++) {
          expect(trace.frames.some((f) => f.stepId.endsWith(`:b${i}`))).toBe(true);
        }
        expect(trace.frames.some((f) => f.stepId.endsWith(":b4"))).toBe(false);
        expect(trace.frames.some((f) => f.blockIndex === 3)).toBe(true);
      });

      it.each([
        ["ecb", () => buildEcbSpec(core, "encrypt"), null],
        ["cbc", () => buildCbcSpec(core, "encrypt"), IV],
      ] as const)("%s: the derived aux graph has no warnings", (_name, build, ivHex) => {
        const spec = build();
        const aux = new Map<string, AuxValue>([["key", bytesFromHex(key)]]);
        if (ivHex) aux.set("iv", bytesFromHex(ivHex));
        const trace = runSpec(spec, buildDefaultRegistry(), {
          initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
          initialAux: aux,
        });
        // Orphaned reads / unused writes / cycles would mean the key schedule's aux
        // publish isn't reaching the body across the iterate's scope boundary.
        expect(validateGraph(deriveAuxGraph(trace, spec), trace)).toEqual([]);
      });
    });
  },
);
