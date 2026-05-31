/**
 * NIST SP 800-38A Appendix F.2 — AES-128 in CBC mode, known-answer tests.
 *
 * - F.2.1: CBC-AES128.Encrypt
 * - F.2.2: CBC-AES128.Decrypt
 *
 * Same 4-block (64-byte) plaintext as F.1 / F.5 — shared across all SP
 * 800-38A appendix-F examples so the modes can be compared side-by-side.
 * The IV is the standard test vector `000102030405060708090a0b0c0d0e0f`.
 *
 * What this file pins, beyond the obvious "encrypt then decrypt
 * round-trips":
 *
 *   1. The published §F.2.1 ciphertext is byte-identical (≥3 blocks, so the
 *      cross-iteration chain feedback is exercised feedback-of-feedback).
 *   2. The spec output is byte-equal to `node:crypto`'s aes-128-cbc (enc+dec),
 *      an independent oracle alongside the published vector.
 *   3. The chaining works: identical plaintext halves produce DIFFERENT
 *      ciphertext halves (the structural difference vs ECB).
 *   4. The CBC trace's per-iteration frames carry `:b{i}` stepId suffixes
 *      so the trace store's `setTrace` can preserve focus by stepId
 *      across re-runs — same invariant the ECB KAT tests pin.
 *
 * Byte-native (scaffolding-suppression Slice B1.4b): the CBC spec is now a
 * port-graph (port-mode `iterate` with `chainInput`/`chainFeedback` carrying
 * the previous-ciphertext value on a port instead of an aux slot), so every
 * run sets `portedDispatchEnabled: true`.
 */

import { createCipheriv, createDecipheriv } from "node:crypto";
import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128CbcDecryptSpec } from "@/ciphers/aes-128-cbc-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { deriveAuxGraph, validateGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY = "2b7e151628aed2a6abf7158809cf4f3c";
const IV = "000102030405060708090a0b0c0d0e0f";

// SP 800-38A §F (shared across F.1/F.2/F.5).
const PLAINTEXT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

// SP 800-38A §F.2.1 (CBC-AES128.Encrypt) expected ciphertext.
const CBC_CIPHERTEXT_4_BLOCKS =
  "7649abac8119b246cee98e9b12e9197d" +
  "5086cb9b507219ee95db113a917678b2" +
  "73bed6b8e3c1743b7116e69e22229516" +
  "3ff1caa1681fac09120eca307586e1a7";

const buildAux = (): Map<string, AuxValue> =>
  new Map<string, AuxValue>([
    ["key", bytesFromHex(KEY)],
    ["iv", bytesFromHex(IV)],
  ]);

// Run a byte-native CBC spec with ported dispatch (required — the spec is a
// port-graph). Returns the final ciphertext/plaintext bytes as hex.
const runCbc = (spec: CipherSpec, inputHex: string, aux: Map<string, AuxValue>): string => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: aux,
  });
  expect(trace.finalState.shape).toBe("bytes");
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return hexFromBytes(trace.finalState.bytes);
};

describe("AES-128 CBC (NIST SP 800-38A §F.2)", () => {
  it("F.2.1: encrypts the 4-block plaintext to the published ciphertext", () => {
    expect(runCbc(aes128CbcSpec, PLAINTEXT_4_BLOCKS, buildAux())).toBe(CBC_CIPHERTEXT_4_BLOCKS);
  });

  it("F.2.2: decrypts the 4-block ciphertext to the original plaintext", () => {
    expect(runCbc(aes128CbcDecryptSpec, CBC_CIPHERTEXT_4_BLOCKS, buildAux())).toBe(
      PLAINTEXT_4_BLOCKS,
    );
  });

  it("matches node:crypto aes-128-cbc on an arbitrary 3-block message (enc + dec)", () => {
    // Independent oracle. ≥3 blocks so the chain feedback is exercised
    // feedback-of-feedback (block 2's chain = block 1's, which depended on
    // block 0's) — a wrong carry would show as a wrong block 2 onward.
    const plaintextHex =
      "00112233445566778899aabbccddeeff" +
      "0f1e2d3c4b5a69788796a5b4c3d2e1f0" +
      "fedcba98765432100123456789abcdef";
    const keyHex = "0123456789abcdef0123456789abcdef";
    const ivHex = "f0e1d2c3b4a5968778695a4b3c2d1e0f";

    // node:crypto reference (no padding — the message is an exact multiple).
    const cipher = createCipheriv(
      "aes-128-cbc",
      Buffer.from(keyHex, "hex"),
      Buffer.from(ivHex, "hex"),
    );
    cipher.setAutoPadding(false);
    const nodeCipherHex = Buffer.concat([
      cipher.update(Buffer.from(plaintextHex, "hex")),
      cipher.final(),
    ]).toString("hex");

    const aux = new Map<string, AuxValue>([
      ["key", bytesFromHex(keyHex)],
      ["iv", bytesFromHex(ivHex)],
    ]);

    // Our encrypt must equal node:crypto's ciphertext.
    expect(runCbc(aes128CbcSpec, plaintextHex, aux)).toBe(nodeCipherHex);

    // node:crypto decrypt of OUR ciphertext must equal the original plaintext.
    const decipher = createDecipheriv(
      "aes-128-cbc",
      Buffer.from(keyHex, "hex"),
      Buffer.from(ivHex, "hex"),
    );
    decipher.setAutoPadding(false);
    const nodePlainHex = Buffer.concat([
      decipher.update(Buffer.from(nodeCipherHex, "hex")),
      decipher.final(),
    ]).toString("hex");
    expect(nodePlainHex).toBe(plaintextHex);

    // And our decrypt of node:crypto's ciphertext must equal the plaintext.
    const aux2 = new Map<string, AuxValue>([
      ["key", bytesFromHex(keyHex)],
      ["iv", bytesFromHex(ivHex)],
    ]);
    expect(runCbc(aes128CbcDecryptSpec, nodeCipherHex, aux2)).toBe(plaintextHex);
  });

  it("identical plaintext halves produce DIFFERENT ciphertext halves (the chaining difference vs ECB)", () => {
    // 32 bytes of plaintext, both halves identical. Under ECB this would
    // produce identical ciphertext halves — the famous leak. Under CBC,
    // the second half's XOR with the previous ciphertext block makes the
    // two halves diverge.
    const ciphertextHex = runCbc(
      aes128CbcSpec,
      "00112233445566778899aabbccddeeff".repeat(2),
      buildAux(),
    );
    const half1 = ciphertextHex.slice(0, 32);
    const half2 = ciphertextHex.slice(32, 64);
    expect(half1).not.toBe(half2);
  });

  it("changing the IV produces different ciphertext for the same plaintext+key", () => {
    const auxA = new Map<string, AuxValue>([
      ["key", bytesFromHex(KEY)],
      ["iv", new Uint8Array(16)],
    ]);
    const auxB = new Map<string, AuxValue>([
      ["key", bytesFromHex(KEY)],
      ["iv", bytesFromHex(IV)],
    ]);
    expect(runCbc(aes128CbcSpec, PLAINTEXT_4_BLOCKS, auxA)).not.toBe(
      runCbc(aes128CbcSpec, PLAINTEXT_4_BLOCKS, auxB),
    );
  });

  it("emits :b{i} stepId suffixes for every iterating frame (preserves the trace-store invariant)", () => {
    const trace = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(PLAINTEXT_4_BLOCKS)),
      initialAux: buildAux(),
    });

    // Spot-check: the chaining XOR (cbc-xor) shows up at every block index.
    for (let i = 0; i < 4; i++) {
      const xorFrame = trace.frames.find((f) => f.stepId === `cbc-xor:b${i}` && f.blockIndex === i);
      expect(xorFrame).toBeDefined();
    }

    // The pre-loop fetch-iv step does NOT get a suffix (it lives outside the
    // iterate node — it reads aux["iv"] once and bootstraps the chain).
    const ivFrame = trace.frames.find((f) => f.stepId === "fetch-iv");
    expect(ivFrame).toBeDefined();
  });

  it("multi-block trace produces NO cycle warnings (iterate-feedback regression)", () => {
    // The `:b{i}` collapse merges per-iteration port reads/writes onto one
    // canonical stepId. For byte-native CBC the chain rides the iterate's
    // `chain` port: encrypt's round.N output in block i feeds cbc-xor's chain
    // read in block i+1, a backwards edge in canonical-id space. Combined with
    // the forward port-flow spine through the AES body, a naive cycle detector
    // would flag the iterate body. This pins that validateGraph suppresses the
    // false alarm (no aux mutation involved anymore — the old state-to-aux /
    // aux-copy dance is gone).
    const trace = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(PLAINTEXT_4_BLOCKS)),
      initialAux: buildAux(),
    });
    const graph = deriveAuxGraph(trace, aes128CbcSpec);
    const warnings = validateGraph(graph, trace);
    expect(warnings.filter((w) => w.kind === "cycle")).toEqual([]);

    // Same for decrypt — chainFeedback reads the raw input block, which is
    // ALSO a backwards edge once collapsed.
    const decTrace = runSpec(aes128CbcDecryptSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(CBC_CIPHERTEXT_4_BLOCKS)),
      initialAux: buildAux(),
    });
    const decGraph = deriveAuxGraph(decTrace, aes128CbcDecryptSpec);
    const decWarnings = validateGraph(decGraph, decTrace);
    expect(decWarnings.filter((w) => w.kind === "cycle")).toEqual([]);
  });

  it("round-trips an arbitrary 48-byte plaintext (3 blocks) through encrypt → decrypt", () => {
    const plaintextHex =
      "deadbeefcafebabe0011223344556677" +
      "8899aabbccddeeff0123456789abcdef" +
      "fedcba9876543210aabbccddeeff0011";
    const keyHex = "0123456789abcdef0123456789abcdef";
    const ivHex = "f0e1d2c3b4a5968778695a4b3c2d1e0f";

    const aux = new Map<string, AuxValue>([
      ["key", bytesFromHex(keyHex)],
      ["iv", bytesFromHex(ivHex)],
    ]);
    const cipherHex = runCbc(aes128CbcSpec, plaintextHex, aux);

    // Decrypt needs a fresh aux map (mirrors the App's per-Run construction).
    const decAux = new Map<string, AuxValue>([
      ["key", bytesFromHex(keyHex)],
      ["iv", bytesFromHex(ivHex)],
    ]);
    expect(runCbc(aes128CbcDecryptSpec, cipherHex, decAux)).toBe(plaintextHex);
  });
});
