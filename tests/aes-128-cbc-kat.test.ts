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
 *   1. The published §F.2.1 ciphertext is byte-identical.
 *   2. The chaining works: identical plaintext halves produce DIFFERENT
 *      ciphertext halves (the structural difference vs ECB).
 *   3. The CBC trace's per-iteration frames carry `:b{i}` stepId suffixes
 *      so the trace store's `setTrace` can preserve focus by stepId
 *      across re-runs — same invariant the ECB KAT tests pin.
 */

import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128CbcDecryptSpec } from "@/ciphers/aes-128-cbc-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
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

describe("AES-128 CBC (NIST SP 800-38A §F.2)", () => {
  it("F.2.1: encrypts the 4-block plaintext to the published ciphertext", () => {
    const initial = makeBytesState(bytesFromHex(PLAINTEXT_4_BLOCKS));
    const trace = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
      initialState: initial,
      initialAux: buildAux(),
    });

    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(CBC_CIPHERTEXT_4_BLOCKS);
  });

  it("F.2.2: decrypts the 4-block ciphertext to the original plaintext", () => {
    const initial = makeBytesState(bytesFromHex(CBC_CIPHERTEXT_4_BLOCKS));
    const trace = runSpec(aes128CbcDecryptSpec, buildDefaultRegistry(), {
      initialState: initial,
      initialAux: buildAux(),
    });

    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(PLAINTEXT_4_BLOCKS);
  });

  it("identical plaintext halves produce DIFFERENT ciphertext halves (the chaining difference vs ECB)", () => {
    // 32 bytes of plaintext, both halves identical. Under ECB this would
    // produce identical ciphertext halves — the famous leak. Under CBC,
    // the second half's XOR with the previous ciphertext block makes the
    // two halves diverge.
    const plaintext = bytesFromHex("00112233445566778899aabbccddeeff".repeat(2));
    const trace = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(plaintext),
      initialAux: buildAux(),
    });
    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") return;
    const ciphertextHex = hexFromBytes(trace.finalState.bytes);
    const half1 = ciphertextHex.slice(0, 32);
    const half2 = ciphertextHex.slice(32, 64);
    expect(half1).not.toBe(half2);
  });

  it("changing the IV produces different ciphertext for the same plaintext+key", () => {
    const plaintext = makeBytesState(bytesFromHex(PLAINTEXT_4_BLOCKS));

    const auxA = new Map<string, AuxValue>([
      ["key", bytesFromHex(KEY)],
      ["iv", new Uint8Array(16)],
    ]);
    const auxB = new Map<string, AuxValue>([
      ["key", bytesFromHex(KEY)],
      ["iv", bytesFromHex(IV)],
    ]);

    const traceA = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux: auxA,
    });
    const traceB = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux: auxB,
    });

    if (traceA.finalState.shape !== "bytes" || traceB.finalState.shape !== "bytes") return;
    expect(hexFromBytes(traceA.finalState.bytes)).not.toBe(hexFromBytes(traceB.finalState.bytes));
  });

  it("emits :b{i} stepId suffixes for every iterating frame (preserves the trace-store invariant)", () => {
    const trace = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(PLAINTEXT_4_BLOCKS)),
      initialAux: buildAux(),
    });

    // Spot-check: a per-iter step (cbc-xor) shows up at every block index.
    for (let i = 0; i < 4; i++) {
      const xorFrame = trace.frames.find((f) => f.stepId === `cbc-xor:b${i}` && f.blockIndex === i);
      expect(xorFrame).toBeDefined();
    }

    // The pre-loop iv-load step does NOT get a suffix (it lives outside
    // the iterate node).
    const ivFrame = trace.frames.find((f) => f.stepId === "iv-load");
    expect(ivFrame).toBeDefined();
  });

  it("round-trips an arbitrary 48-byte plaintext (3 blocks) through encrypt → decrypt", () => {
    const plaintext = bytesFromHex(
      "deadbeefcafebabe0011223344556677" +
        "8899aabbccddeefffeeddccbbaa99887" +
        "766554433221100ffeedccbbaa998877",
    );
    const key = bytesFromHex("0123456789abcdef0123456789abcdef");
    const iv = bytesFromHex("f0e1d2c3b4a5968778695a4b3c2d1e0f");

    const aux = new Map<string, AuxValue>([
      ["key", key],
      ["iv", iv],
    ]);

    const encTrace = runSpec(aes128CbcSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(plaintext),
      initialAux: aux,
    });
    expect(encTrace.finalState.shape).toBe("bytes");
    if (encTrace.finalState.shape !== "bytes") return;

    // Decrypt needs a FRESH aux map — encrypt's pass left aux["chain"]
    // pointing at the last ciphertext block, but decrypt's iv-load
    // overwrites chain from aux["iv"] anyway, so this isn't strictly
    // required. Building a fresh map mirrors the real App's per-Run
    // initialAux construction.
    const decAux = new Map<string, AuxValue>([
      ["key", key],
      ["iv", iv],
    ]);
    const decTrace = runSpec(aes128CbcDecryptSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(encTrace.finalState.bytes),
      initialAux: decAux,
    });
    expect(decTrace.finalState.shape).toBe("bytes");
    if (decTrace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(decTrace.finalState.bytes)).toBe(hexFromBytes(plaintext));
  });
});
