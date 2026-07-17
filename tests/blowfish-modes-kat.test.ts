/**
 * Blowfish ECB + CBC known-answer tests — the proof that the cipher-agnostic
 * mode machine works on a block that ISN'T 16 bytes.
 *
 * ## Why this file is the load-bearing gate for Phase C
 *
 * Phases A + B of `docs/plans/foamy-prancing-wren.md` made the mode builders,
 * the padding overlay, and the IV plumbing block-size-generic — but every core
 * that existed was AES, whose block IS 16. A stray hardcoded `16` anywhere in
 * that arithmetic would have passed the entire suite, and AES-192/256 didn't
 * help (also 16-byte). `tests/block-size-generic-modes.test.ts` closed part of
 * the gap with a fake 8-byte core, but a fake core's body is a passthrough leaf
 * — it proves the plumbing carries the width, not that a real cipher runs. This
 * file is the real cipher behind the same arithmetic.
 *
 * ## The oracle
 *
 * `node:crypto` is NOT usable here: verified on Node v24.14.1 that `bf-ecb` /
 * `bf-cbc` fail with the OpenSSL 3 legacy-provider error
 * `0308010C:digital envelope routines::unsupported`, while `aes-128-cbc` is
 * fine (so the check is sound, not a harness artifact).
 *
 * So the oracle is composed here from `blowfish-constants.ts`'s pure helpers —
 * the same math already pinned against the Eric-Young / pycryptodome vectors in
 * `blowfish-vectors.test.ts`. This does NOT violate the "external oracle before
 * tests" rule: that rule governs *new ciphers*, and Blowfish's single-block core
 * is already externally verified. ECB/CBC over an already-trusted primitive is
 * legitimately verified by composing the mode's rule over that primitive — which
 * is exactly what a mode of operation IS (NIST SP 800-38A §6.1-6.2).
 *
 * Decrypt reuses `blowfishEncryptWords` with the P-array REVERSED: Blowfish
 * inverts by running the same network with P consumed backwards, which is the
 * same fact the spec builder encodes as `pIdx = 18 - j`.
 */

import {
  blowfishEncryptWords,
  blowfishKeySchedule,
  bytesBEToU32,
  u32ToBytesBE,
} from "@/ciphers/blowfish-constants";
import { blowfishCore } from "@/ciphers/blowfish-core";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildCbcSpec } from "@/ciphers/modes/cbc";
import { buildEcbSpec } from "@/ciphers/modes/ecb";
import { deriveAuxGraph, validateGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY = "0123456789abcdef";
// Blowfish's block is 8 bytes, so the IV must be 8 — NOT the 16 the AES CBC KAT
// next door uses. This is the width the whole phase exists to get right.
const IV = "fedcba9876543210";

const B = 8;

/**
 * Four 8-byte blocks. Blocks 0 and 2 are IDENTICAL on purpose: that is what
 * makes ECB's structural leak visible and proves CBC's chain actually chains.
 */
const PT_4_BLOCKS =
  "1111111111111111" + "0123456789abcdef" + "1111111111111111" + "0000000000000000";

// ─── The composed oracle ──────────────────────────────────────────────────────

/** One block through the raw Feistel network. `encrypt=false` reverses P. */
const oracleBlock = (keyHex: string, block: Uint8Array, encrypt: boolean): Uint8Array => {
  const { P, S } = blowfishKeySchedule(bytesFromHex(keyHex));
  // Blowfish decrypts by running the identical network with P reversed.
  const p = encrypt ? P : [...P].reverse();
  const [xl, xr] = blowfishEncryptWords(bytesBEToU32(block, 0), bytesBEToU32(block, 4), p, S);
  const out = new Uint8Array(B);
  out.set(u32ToBytesBE(xl), 0);
  out.set(u32ToBytesBE(xr), 4);
  return out;
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
const oracleEcb = (keyHex: string, inputHex: string, encrypt: boolean): string =>
  joinBlocks(blocksOf(bytesFromHex(inputHex)).map((blk) => oracleBlock(keyHex, blk, encrypt)));

/** CBC (SP 800-38A §6.2): C_i = E(P_i ⊕ C_{i-1}); P_i = D(C_i) ⊕ C_{i-1}; C_-1 = IV. */
const oracleCbc = (keyHex: string, ivHex: string, inputHex: string, encrypt: boolean): string => {
  let chain = bytesFromHex(ivHex);
  const out: Uint8Array[] = [];
  for (const blk of blocksOf(bytesFromHex(inputHex))) {
    if (encrypt) {
      const c = oracleBlock(keyHex, xorBytes(blk, chain), true);
      out.push(c);
      chain = c;
    } else {
      out.push(xorBytes(oracleBlock(keyHex, blk, false), chain));
      chain = Uint8Array.from(blk);
    }
  }
  return joinBlocks(out);
};

// ─── Running the real specs ───────────────────────────────────────────────────

const core = blowfishCore();

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

describe("Blowfish ECB — the first non-16-byte block through the generic mode machine", () => {
  it("the core reports Blowfish's real geometry, not AES's", () => {
    // If this is 16, every other assertion in this file is testing AES-shaped
    // arithmetic that happens to be driven by Blowfish's builders.
    expect(core.blockByteLength).toBe(8);
    expect(core.keyByteLength).toBe(8);
  });

  it("encrypts every block independently, matching the composed oracle", () => {
    const got = runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, false);
    expect(got).toBe(oracleEcb(KEY, PT_4_BLOCKS, true));
    // 4 blocks × 8 bytes = 32 bytes. At a wrongly-assumed 16-byte block this
    // input would be 2 blocks and the length alone would diverge.
    expect(got.length / 2).toBe(32);
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

  it("its blocks land on the PUBLISHED Eric-Young vectors", () => {
    // The strongest check available here, and it costs nothing: ECB is BY
    // DEFINITION each block encrypted independently, so a published single-block
    // vector IS a published ECB vector for that block. The fixture's blocks 0/2
    // (`1111…`) and 3 (`0000…`) under this key are two of the canonical
    // Eric-Young vectors already pinned in `blowfish-vectors.test.ts`.
    //
    // That ties this file's output to an EXTERNAL oracle rather than only to the
    // composed one above — which matters, because a composed oracle and the spec
    // could in principle share a wrong assumption about the underlying cipher.
    // They cannot both be wrong and still hit these two constants.
    const ct = blocksOf(bytesFromHex(runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, false)));
    expect(hexFromBytes(ct[0] as Uint8Array)).toBe("61f9c3802281b096");
    expect(hexFromBytes(ct[3] as Uint8Array)).toBe("245946885754369a");
  });
});

describe("Blowfish CBC — chaining over an 8-byte block", () => {
  it("matches the composed oracle across 4 blocks (chain feeds forward)", () => {
    const got = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, true);
    expect(got).toBe(oracleCbc(KEY, IV, PT_4_BLOCKS, true));
  });

  it("decrypt inverts encrypt, and matches the oracle directly", () => {
    const ct = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, true);
    expect(runMode(buildCbcSpec(core, "decrypt"), ct, true)).toBe(PT_4_BLOCKS);
    expect(runMode(buildCbcSpec(core, "decrypt"), ct, true)).toBe(oracleCbc(KEY, IV, ct, false));
  });

  it("hides the repeated plaintext block that ECB leaks", () => {
    // Same fixture, same repeated blocks 0 and 2 — but the chain makes their
    // ciphertexts differ. This is CBC's whole point, and it also proves the
    // chain value genuinely crosses iterations at 8-byte width.
    const ct = blocksOf(bytesFromHex(runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, true)));
    expect(hexFromBytes(ct[0] as Uint8Array)).not.toBe(hexFromBytes(ct[2] as Uint8Array));
  });

  it("reads an 8-byte IV, and a different IV changes every block", () => {
    const ctA = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, true);
    // Re-run with a different IV via a direct aux swap.
    const trace = runSpec(buildCbcSpec(core, "encrypt"), buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
      initialAux: new Map<string, AuxValue>([
        ["key", bytesFromHex(KEY)],
        ["iv", bytesFromHex("0000000000000000")],
      ]),
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes");
    expect(hexFromBytes(trace.finalState.bytes)).not.toBe(ctA);
  });
});

describe("Blowfish mode traces stay well-formed", () => {
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
    // Every per-block frame is stamped with its iteration index.
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
