/**
 * Serpent ECB + CBC known-answer tests — the proof that the cipher-agnostic
 * mode machine drives Serpent's AES-shaped body per block.
 *
 * ## What this file adds over the existing coverage
 *
 * Serpent's single-block core is already KAT-verified (`serpent-vectors.test.ts`,
 * against the Anderson/Biham/Knudsen Python reference), and the mode machine is
 * already generic-verified (AES + Blowfish + a fake 8-byte core in
 * `block-size-generic-modes.test.ts`). What was NOT covered until now is the
 * composition: the generic `modes/ecb.ts` / `modes/cbc.ts` builders running the
 * REAL Serpent body once per block, with the key schedule hoisted outside the
 * loop and the chain value crossing iterations.
 *
 * ## The oracle
 *
 * `node:crypto` cannot oracle Serpent (it isn't an OpenSSL cipher at all). But
 * no external per-mode oracle is needed: a mode of operation is BY DEFINITION
 * the block cipher repeated under a rule (NIST SP 800-38A §6.1-6.2), so the
 * already-trusted single-block Serpent spec IS the oracle for one block, and the
 * ECB/CBC rules compose over it here. This is the same argument
 * `blowfish-modes-kat.test.ts` makes, and it does not violate the "external
 * oracle before tests" rule — that rule governs *new ciphers*, and Serpent's
 * primitive is already externally verified.
 *
 * To guard against the composed oracle and the mode spec sharing a wrong
 * assumption, the all-zero fixture block under the `80…0` key is anchored to the
 * PUBLISHED reference constant (`264e5481…`, the headline vector in
 * `serpent-vectors.test.ts`): under ECB that block is encrypted independently,
 * so a published single-block vector IS a published ECB-block vector.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildCbcSpec } from "@/ciphers/modes/cbc";
import { buildEcbSpec } from "@/ciphers/modes/ecb";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpentCore } from "@/ciphers/serpent-core";
import { deriveAuxGraph, validateGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// The published Serpent-128 reference key: byte 0 = 0x80, rest zero. Chosen so
// the all-zero fixture block encrypts to the headline reference vector below.
const KEY = "80000000000000000000000000000000";
// Serpent's block is 16 bytes, so the IV must be 16 (identical width to AES —
// the exact opposite of Blowfish's 8-byte IV). Arbitrary, distinct bytes.
const IV = "0f0e0d0c0b0a09080706050403020100";

const B = 16;

/**
 * Four 16-byte blocks. Blocks 0 and 2 are IDENTICAL on purpose (ECB leaks them,
 * CBC hides them). Block 3 is all-zero — the external-anchor block.
 */
const PT_4_BLOCKS =
  "11111111111111111111111111111111" +
  "000102030405060708090a0b0c0d0e0f" +
  "11111111111111111111111111111111" +
  "00000000000000000000000000000000";

/** The published Serpent-128 vector: key=80…0, pt=0 (serpent-vectors.test.ts). */
const ANCHOR_BLOCK_0 = "264e5481eff42a4606abda06c0bfda3d";

// ─── The composed oracle: the trusted single-block spec, once per block ───────

/** One block through the single-block Serpent spec. `encrypt=false` decrypts. */
const oracleBlock = (block: Uint8Array, encrypt: boolean): Uint8Array => {
  const spec = encrypt ? serpent128Spec : serpent128DecryptSpec;
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(block),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return trace.finalState.bytes;
};

const xorBytes = (a: Uint8Array, b: Uint8Array): Uint8Array =>
  Uint8Array.from(a, (v, i) => v ^ (b[i] ?? 0));

const blocksOf = (bytes: Uint8Array): Uint8Array[] => {
  const out: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += B) out.push(bytes.subarray(i, i + B));
  return out;
};

const joinBlocks = (blocks: readonly Uint8Array[]): string =>
  hexFromBytes(Uint8Array.from(blocks.flatMap((b) => [...b])));

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

// ─── Running the real mode specs ──────────────────────────────────────────────

const core = serpentCore(16);

const runMode = (spec: CipherSpec, inputHex: string, withIv: boolean): string => {
  const aux = new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]);
  if (withIv) aux.set("iv", bytesFromHex(IV));
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: aux,
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return hexFromBytes(trace.finalState.bytes);
};

describe("Serpent ECB — the AES-shaped body driven per block by the generic mode machine", () => {
  it("the core reports Serpent-128's real geometry", () => {
    // 16-byte block (like AES), 16-byte key (Serpent-128).
    expect(core.blockByteLength).toBe(16);
    expect(core.keyByteLength).toBe(16);
  });

  it("encrypts every block independently, matching the composed oracle", () => {
    const got = runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, false);
    expect(got).toBe(oracleEcb(PT_4_BLOCKS, true));
    // 4 blocks × 16 bytes = 64 bytes.
    expect(got.length / 2).toBe(64);
  });

  it("decrypt inverts encrypt", () => {
    const ct = runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, false);
    expect(runMode(buildEcbSpec(core, "decrypt"), ct, false)).toBe(PT_4_BLOCKS);
  });

  it("leaks identical plaintext blocks as identical ciphertext blocks", () => {
    // The Tux-image lesson, and the structural contrast with CBC below. Blocks
    // 0 and 2 of the fixture are equal.
    const ct = blocksOf(bytesFromHex(runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, false)));
    expect(hexFromBytes(ct[0] as Uint8Array)).toBe(hexFromBytes(ct[2] as Uint8Array));
  });

  it("its all-zero block lands on the PUBLISHED Serpent-128 vector", () => {
    // ECB encrypts each block independently, so the published single-block
    // vector IS a published ECB-block vector. Block 3 (all-zero) under key 80…0
    // is the headline reference constant. This ties the file to an EXTERNAL
    // oracle, not only the composed one — the two cannot share a wrong
    // assumption and still hit this constant.
    const ct = blocksOf(bytesFromHex(runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, false)));
    expect(hexFromBytes(ct[3] as Uint8Array)).toBe(ANCHOR_BLOCK_0);
  });
});

describe("Serpent CBC — chaining over a 16-byte block", () => {
  it("matches the composed oracle across 4 blocks (chain feeds forward)", () => {
    const got = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, true);
    expect(got).toBe(oracleCbc(IV, PT_4_BLOCKS, true));
  });

  it("decrypt inverts encrypt, and matches the oracle directly", () => {
    const ct = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, true);
    expect(runMode(buildCbcSpec(core, "decrypt"), ct, true)).toBe(PT_4_BLOCKS);
    expect(runMode(buildCbcSpec(core, "decrypt"), ct, true)).toBe(oracleCbc(IV, ct, false));
  });

  it("hides the repeated plaintext block that ECB leaks", () => {
    // Same fixture, same repeated blocks 0 and 2 — but the chain makes their
    // ciphertexts differ. This is CBC's whole point, and it proves the chain
    // value genuinely crosses iterations.
    const ct = blocksOf(bytesFromHex(runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, true)));
    expect(hexFromBytes(ct[0] as Uint8Array)).not.toBe(hexFromBytes(ct[2] as Uint8Array));
  });

  it("reads a 16-byte IV, and a different IV changes the ciphertext", () => {
    const ctA = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, true);
    const trace = runSpec(buildCbcSpec(core, "encrypt"), buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
      initialAux: new Map<string, AuxValue>([
        ["key", bytesFromHex(KEY)],
        ["iv", bytesFromHex("00000000000000000000000000000000")],
      ]),
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes");
    expect(hexFromBytes(trace.finalState.bytes)).not.toBe(ctA);
  });
});

describe("Serpent-192 / -256 modes exercise the other key widths", () => {
  // serpentCore(16) above drives every headline assertion, but 192/256 are
  // registered too — and "all three share one body, only the key-schedule input
  // width differs" is exactly the "correct by construction" claim a KAT exists
  // to check (the AES-192/256-modes-KAT precedent: silent-wrong-ciphertext if the
  // wider key schedule mis-drives the mode). The published single-block vectors
  // (key=80…0, pt=0) double as ECB-block-0 anchors, since ECB encrypts each block
  // independently. All keys are the single-bit reference key at the right width.
  const VARIANTS = [
    {
      keyByteLength: 24 as const,
      key: `80${"00".repeat(23)}`,
      anchor: "9e274ead9b737bb21efcfca548602689",
    },
    {
      keyByteLength: 32 as const,
      key: `80${"00".repeat(31)}`,
      anchor: "a223aa1288463c0e2be38ebd825616c0",
    },
  ];

  const runVariant = (
    spec: CipherSpec,
    key: string,
    inputHex: string,
    ivHex: string | null,
  ): string => {
    const aux = new Map<string, AuxValue>([["key", bytesFromHex(key)]]);
    if (ivHex) aux.set("iv", bytesFromHex(ivHex));
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(inputHex)),
      initialAux: aux,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
    return hexFromBytes(trace.finalState.bytes);
  };

  it.each(VARIANTS)(
    "Serpent-$keyByteLength: ECB block 0 (all-zero, key 80…0) lands on the published vector",
    ({ keyByteLength, key, anchor }) => {
      const c = serpentCore(keyByteLength);
      // Single all-zero block through ECB = the published single-block vector.
      const ct = runVariant(buildEcbSpec(c, "encrypt"), key, "0".repeat(32), null);
      expect(
        blocksOf(bytesFromHex(ct))[0] && hexFromBytes(blocksOf(bytesFromHex(ct))[0] as Uint8Array),
      ).toBe(anchor);
    },
  );

  it.each(VARIANTS)(
    "Serpent-$keyByteLength: ECB and CBC both round-trip a 4-block message",
    ({ keyByteLength, key }) => {
      const c = serpentCore(keyByteLength);
      const ecbCt = runVariant(buildEcbSpec(c, "encrypt"), key, PT_4_BLOCKS, null);
      expect(runVariant(buildEcbSpec(c, "decrypt"), key, ecbCt, null)).toBe(PT_4_BLOCKS);
      const cbcCt = runVariant(buildCbcSpec(c, "encrypt"), key, PT_4_BLOCKS, IV);
      expect(runVariant(buildCbcSpec(c, "decrypt"), key, cbcCt, IV)).toBe(PT_4_BLOCKS);
    },
  );
});

describe("Serpent mode traces stay well-formed", () => {
  it.each([
    ["ecb", () => buildEcbSpec(core, "encrypt"), false],
    ["cbc", () => buildCbcSpec(core, "encrypt"), true],
  ] as const)("%s: per-iteration frames carry :b{i} stepId suffixes", (_name, build, withIv) => {
    const spec = build();
    const aux = new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]);
    if (withIv) aux.set("iv", bytesFromHex(IV));
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
      initialAux: aux,
    });
    // The suffix is what keeps the flat trace uniquely keyed per block, which is
    // what lets `setTrace` preserve the scrubber's focus by stepId across re-runs.
    for (let i = 0; i < 4; i++) {
      expect(trace.frames.some((f) => f.stepId.endsWith(`:b${i}`))).toBe(true);
    }
    expect(trace.frames.some((f) => f.stepId.endsWith(":b4"))).toBe(false);
    expect(trace.frames.some((f) => f.blockIndex === 3)).toBe(true);
  });

  it.each([
    ["ecb", () => buildEcbSpec(core, "encrypt"), false],
    ["cbc", () => buildCbcSpec(core, "encrypt"), true],
  ] as const)("%s: the derived aux graph has no warnings", (_name, build, withIv) => {
    const spec = build();
    const aux = new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]);
    if (withIv) aux.set("iv", bytesFromHex(IV));
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
      initialAux: aux,
    });
    // Orphaned reads / unused writes / cycles would mean the key schedule's aux
    // publish isn't reaching the body across the iterate's scope boundary.
    expect(validateGraph(deriveAuxGraph(trace, spec), trace)).toEqual([]);
  });
});
