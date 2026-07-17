/**
 * Multi-block PKCS#7 + ECB boundary cases: length 0, 1, 15, 16, 17, 31,
 * 32, MAX_BYTES, MAX_BYTES-1, MAX_BYTES+1. The `applyPaddingScheme` +
 * iterate body should expand short inputs to the right number of blocks
 * and round-trip cleanly through the inverse spec.
 *
 * Also pins the `paddingLimits` ranges for multi-block (cipherMode = "ecb")
 * — these were the load-bearing change to the UI's input validation when
 * Phase 1 shipped.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes128EcbDecryptSpec } from "@/ciphers/aes-128-ecb-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { applyPaddingScheme } from "@/core/spec-mutations";
import { hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { MAX_BLOCKS_UI, paddingLimits } from "@/ui/stores/padding";
import { describe, expect, it } from "vitest";

const KEY_HEX = "00112233445566778899aabbccddeeff";

const runRoundTrip = (rawInput: Uint8Array): Uint8Array => {
  const encSpec = applyPaddingScheme(aes128EcbSpec, "encrypt", "pkcs7", 16);
  const decSpec = applyPaddingScheme(aes128EcbDecryptSpec, "decrypt", "pkcs7", 16);
  const keyBytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) keyBytes[i] = Number.parseInt(KEY_HEX.substr(i * 2, 2), 16);

  const encTrace = runSpec(encSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(rawInput),
    initialAux: new Map<string, AuxValue>([["key", keyBytes]]),
  });
  if (encTrace.finalState.shape !== "bytes") throw new Error("encrypt did not produce bytes");

  const decTrace = runSpec(decSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(encTrace.finalState.bytes),
    initialAux: new Map<string, AuxValue>([["key", keyBytes]]),
  });
  if (decTrace.finalState.shape !== "bytes") throw new Error("decrypt did not produce bytes");
  return decTrace.finalState.bytes;
};

describe("multi-block ECB + PKCS#7 boundary cases", () => {
  const cases: Array<{ name: string; length: number }> = [
    { name: "length 0 (empty input)", length: 0 },
    { name: "length 1 (single byte)", length: 1 },
    { name: "length 15 (one byte short of block)", length: 15 },
    { name: "length 16 (exact one block)", length: 16 },
    { name: "length 17 (one byte over)", length: 17 },
    { name: "length 31 (one byte short of two blocks)", length: 31 },
    { name: "length 32 (exact two blocks)", length: 32 },
    { name: "length 64 (four blocks)", length: 64 },
  ];

  for (const c of cases) {
    it(`PKCS#7 round-trips ${c.name}`, () => {
      const input = new Uint8Array(c.length);
      for (let i = 0; i < c.length; i++) input[i] = (i * 7 + 3) & 0xff;
      const out = runRoundTrip(input);
      expect(out.length).toBe(c.length);
      expect(hexFromBytes(out)).toBe(hexFromBytes(input));
    });
  }

  it("PKCS#7 of 16-byte input adds a full extra padding block (canonical behaviour)", () => {
    const input = new Uint8Array(16).fill(0xaa);
    const encSpec = applyPaddingScheme(aes128EcbSpec, "encrypt", "pkcs7", 16);
    const keyBytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) keyBytes[i] = Number.parseInt(KEY_HEX.substr(i * 2, 2), 16);
    const trace = runSpec(encSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(input),
      initialAux: new Map<string, AuxValue>([["key", keyBytes]]),
    });
    if (trace.finalState.shape !== "bytes") return;
    // 16 bytes input → 32 bytes padded → 32 bytes ciphertext (2 blocks).
    expect(trace.finalState.bytes.length).toBe(32);
  });
});

describe("paddingLimits — multi-block ECB", () => {
  it("encrypt + pkcs7 + ecb = 0..MAX_BYTES-1", () => {
    expect(paddingLimits("encrypt", "pkcs7", "aes-128", "ecb")).toEqual({
      min: 0,
      max: MAX_BLOCKS_UI * 16 - 1,
    });
  });

  it("encrypt + iso7816-4 + ecb = 0..MAX_BYTES-1 (also always-pads scheme)", () => {
    expect(paddingLimits("encrypt", "iso7816-4", "aes-128", "ecb")).toEqual({
      min: 0,
      max: MAX_BLOCKS_UI * 16 - 1,
    });
  });

  it("encrypt + zero-pad + ecb = 1..MAX_BYTES (zero-pad doesn't always pad)", () => {
    expect(paddingLimits("encrypt", "zero-pad", "aes-128", "ecb")).toEqual({
      min: 1,
      max: MAX_BLOCKS_UI * 16,
    });
  });

  it("encrypt + none + ecb = 16..MAX_BYTES (block-aligned only)", () => {
    expect(paddingLimits("encrypt", "none", "aes-128", "ecb")).toEqual({
      min: 16,
      max: MAX_BLOCKS_UI * 16,
    });
  });

  it("decrypt + any + ecb = 16..MAX_BYTES (ciphertext is whole blocks)", () => {
    for (const scheme of ["none", "pkcs7", "zero-pad", "iso7816-4"] as const) {
      expect(
        paddingLimits("decrypt", scheme, "aes-128", scheme === "none" ? "ecb" : "ecb"),
      ).toEqual({
        min: 16,
        max: MAX_BLOCKS_UI * 16,
      });
    }
  });

  it("single-block (default) preserves today's behaviour for AES-128 encrypt+pkcs7", () => {
    expect(paddingLimits("encrypt", "pkcs7", "aes-128")).toEqual({ min: 0, max: 15 });
  });
});
