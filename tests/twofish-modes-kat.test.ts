/**
 * Twofish ECB + CBC known-answer tests — the proof that the cipher-agnostic mode
 * machine drives Twofish's 4-rail body per block, and the last cipher family to
 * need one.
 *
 * ## What this file adds over the existing coverage
 *
 * Twofish's single-block core is already KAT-verified at three levels
 * (`twofish-vectors.test.ts`, against the Ferguson reference C library: the
 * key-dependent S-boxes, all 40 subkeys, and the ciphertext). The mode machine is
 * already generic-verified across five other cores. What was NOT covered until
 * now is the composition: the generic `modes/ecb.ts` / `modes/cbc.ts` builders
 * running the REAL Twofish body once per block, with the key setup hoisted
 * outside the loop.
 *
 * ## Why a 16-byte block still earns a KAT here
 *
 * It buys no block-size confidence — 16 is AES's width, the best-covered case,
 * and Blowfish's 8 / Speck's 4 already pushed the generic arithmetic below it.
 * What is genuinely new is *what gets nested*: Twofish has the most structurally
 * unusual body in the app (a 4-rail round, not the 2-way Feistel form), and its
 * subkeys reach each round exclusively through **aux**. That aux routing is the
 * load-bearing precondition for schedule-outside / body-inside — a subkey
 * arriving over a port edge into the key-setup group would throw the moment the
 * body is wrapped in an iterate, because port flow cannot cross a group scope.
 * These tests are what prove it does not.
 *
 * ## The oracle
 *
 * `node:crypto` cannot oracle Twofish (it isn't an OpenSSL cipher). But no
 * external per-mode oracle is needed: a mode of operation is BY DEFINITION the
 * block cipher repeated under a rule (NIST SP 800-38A §6.1-6.2), so the
 * already-trusted single-block Twofish spec IS the oracle for one block, and the
 * ECB/CBC rules compose over it here — the same argument
 * `serpent-modes-kat.test.ts` and `speck-modes-kat.test.ts` make.
 *
 * To guard against the composed oracle and the mode spec sharing a wrong
 * assumption, the all-zero fixture block under the all-zero key is anchored to
 * the PUBLISHED constant (`9f589f5c…c35a`, the canonical Twofish-128 vector):
 * under ECB that block is encrypted independently, so a published single-block
 * vector IS a published ECB-block vector.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildCbcSpec } from "@/ciphers/modes/cbc";
import { buildEcbSpec } from "@/ciphers/modes/ecb";
import { twofishSpec } from "@/ciphers/twofish";
import { twofishCore } from "@/ciphers/twofish-core";
import { twofishDecryptSpec } from "@/ciphers/twofish-decrypt";
import { deriveAuxGraph, validateGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import { analyzeTwofishRound } from "@/core/twofish-shape";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

/** The all-zero 128-bit key — the one the published canonical vector uses. */
const KEY = "00".repeat(16);
/** Twofish's block is 16 bytes, so the IV is 16 wide. Arbitrary, distinct bytes. */
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

/** The canonical published Twofish-128 vector: key = 0…0, pt = 0…0. */
const ANCHOR_ZERO_BLOCK = "9f589f5cf6122c32b6bfec2f2ae8c35a";

// ─── The composed oracle: the trusted single-block spec, once per block ───────

/** One block through the single-block Twofish spec. `encrypt=false` decrypts. */
const oracleBlock = (block: Uint8Array, encrypt: boolean): Uint8Array => {
  const spec = encrypt ? twofishSpec : twofishDecryptSpec;
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

const core = twofishCore;

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

describe("Twofish ECB — the 4-rail body driven per block by the generic mode machine", () => {
  it("the core reports Twofish's real geometry", () => {
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
    // The Tux-image lesson, and the structural contrast with CBC below.
    const ct = blocksOf(bytesFromHex(runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, false)));
    expect(hexFromBytes(ct[0] as Uint8Array)).toBe(hexFromBytes(ct[2] as Uint8Array));
  });

  it("its all-zero block lands on the PUBLISHED Twofish-128 vector", () => {
    // ECB encrypts each block independently, so the published single-block
    // vector IS a published ECB-block vector. This ties the file to an EXTERNAL
    // oracle, not only the composed one — the two cannot share a wrong
    // assumption and still hit this constant.
    const ct = blocksOf(bytesFromHex(runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, false)));
    expect(hexFromBytes(ct[3] as Uint8Array)).toBe(ANCHOR_ZERO_BLOCK);
  });
});

describe("Twofish CBC — chaining over a 16-byte block", () => {
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
    // Proof the chain value genuinely crosses iterations.
    const ct = blocksOf(bytesFromHex(runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, true)));
    expect(hexFromBytes(ct[0] as Uint8Array)).not.toBe(hexFromBytes(ct[2] as Uint8Array));
  });

  it("a different IV changes the ciphertext", () => {
    const ctA = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, true);
    const trace = runSpec(buildCbcSpec(core, "encrypt"), buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
      initialAux: new Map<string, AuxValue>([
        ["key", bytesFromHex(KEY)],
        ["iv", bytesFromHex("00".repeat(16))],
      ]),
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes");
    expect(hexFromBytes(trace.finalState.bytes)).not.toBe(ctA);
  });
});

describe("the key setup survives being hoisted out of the per-block loop", () => {
  it("runs ONCE for a 4-block message, not once per block", () => {
    // The whole point of `buildKeySchedule` being separate from the bodies. If
    // the schedule had been nested in the iterate it would emit `:b{i}`-suffixed
    // frames; hoisted, its frames carry no block suffix and appear once.
    const trace = runSpec(buildEcbSpec(core, "encrypt"), buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]),
    });
    const hExpand = trace.frames.filter((f) => f.stepId.includes("h-expand"));
    expect(hExpand).toHaveLength(1);
    expect(hExpand[0]?.stepId).not.toContain(":b");
  });

  it("the generated ECB spec has no graph warnings", () => {
    // An orphaned read here would be the signature of a subkey that failed to
    // cross the iterate boundary — the exact hazard aux routing avoids.
    const spec = buildEcbSpec(core, "encrypt");
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]),
    });
    expect(validateGraph(deriveAuxGraph(trace, spec), trace)).toEqual([]);
  });
});

describe("the canonical 4-rail round shape survives nesting inside the iterate", () => {
  it("every round in the ECB body is still recognized by analyzeTwofishRound", () => {
    // The graph view's canonical Twofish cell is recognized by SHAPE, with no
    // spec tag. Wrapping the body in a mode's iterate puts each round group one
    // scope deeper, so this asserts the recognizer still fires there — the
    // layout is derived from the same analysis.
    const rounds: StepNode[] = [];
    const walk = (nodes: readonly StepNode[]): void => {
      for (const n of nodes) {
        if (n.kind === "group") {
          if (n.id.startsWith("round.")) rounds.push(n);
          walk(n.children);
        } else if (n.kind === "iterate") {
          walk(n.children);
        }
      }
    };
    walk(buildEcbSpec(core, "encrypt").steps);

    expect(rounds).toHaveLength(16);
    for (const round of rounds) {
      if (round.kind !== "group") throw new Error("expected a group");
      expect(analyzeTwofishRound(round)).not.toBeNull();
    }
  });
});
