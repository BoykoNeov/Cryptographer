/**
 * Tests for `byte-substitute@1` — port-native S-box substitution primitive
 * (scaffolding-suppression plan Phase B Slice B1.1, 2026-05-29).
 *
 * The byte-native replacement for the matrix-shaped
 * `generic.byte-substitution@1`. Coverage:
 *   1. Executor KATs against the real AES S-box (known values) + identity
 *      table passthrough + fresh-buffer guarantee.
 *   2. PortContract is static raw on both sides (the A4-clean shape).
 *   3. Param + wiring validation.
 *   4. Dispatch-path guards (off-flag / on-flag-unwired).
 */

import { AES_INV_SBOX, AES_SBOX } from "@/ciphers/aes-constants";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec, Json, StepContext } from "@/core/types";
import { byteSubstitute, byteSubstitutePortContract } from "@/steps/byte-substitute";
import { describe, expect, it } from "vitest";

const callSub = (input: readonly number[], sbox: readonly number[]): number[] => {
  const inputs = new Map([["input", new Uint8Array(input)]]);
  const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
  const outputs = byteSubstitute(inputs, { sbox: [...sbox] } as unknown as Json, ctx);
  const out = outputs.get("output");
  if (!out) throw new Error("byte-substitute: no output port");
  return Array.from(out);
};

const identity = Array.from({ length: 256 }, (_, i) => i);
const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

describe("byte-substitute@1 — executor (direct invocation)", () => {
  it("maps each byte through the AES S-box (known values)", () => {
    // FIPS-197 S-box: sbox[0x00]=0x63, sbox[0x53]=0xed, sbox[0xff]=0x16.
    expect(callSub([0x00, 0x53, 0xff], AES_SBOX)).toEqual([0x63, 0xed, 0x16]);
  });

  it("inverse S-box undoes the forward S-box (round trip on all 256 values)", () => {
    const forward = callSub(identity, AES_SBOX);
    const back = callSub(forward, AES_INV_SBOX);
    expect(back).toEqual(identity);
  });

  it("identity table is a passthrough", () => {
    expect(callSub([0x12, 0x34, 0x56, 0x78], identity)).toEqual([0x12, 0x34, 0x56, 0x78]);
  });

  it("preserves input length (position-local, 16-byte AES block)", () => {
    const block = Array.from({ length: 16 }, (_, i) => (i * 17) & 0xff);
    expect(callSub(block, AES_SBOX)).toHaveLength(16);
  });

  it("returns a fresh buffer (downstream mutation must not leak back)", () => {
    const inputBytes = new Uint8Array([0xaa, 0xbb]);
    const inputs = new Map([["input", inputBytes]]);
    const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
    const out = byteSubstitute(inputs, { sbox: identity } as unknown as Json, ctx).get(
      "output",
    ) as Uint8Array;
    out[0] = 0xff;
    expect(inputBytes[0]).toBe(0xaa);
  });

  describe("validation", () => {
    const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
    it("throws when sbox is missing", () => {
      expect(() =>
        byteSubstitute(new Map([["input", new Uint8Array([0])]]), {} as Json, ctx),
      ).toThrow(/sbox must be an array of 256/);
    });
    it("throws when sbox is the wrong length", () => {
      expect(() =>
        byteSubstitute(
          new Map([["input", new Uint8Array([0])]]),
          { sbox: [1, 2, 3] } as unknown as Json,
          ctx,
        ),
      ).toThrow(/256/);
    });
    it("throws when the input port is not wired", () => {
      expect(() => byteSubstitute(new Map(), { sbox: identity } as unknown as Json, ctx)).toThrow(
        /input port "input" is not wired/,
      );
    });
  });
});

describe("byte-substitute@1 — PortContract is A4-clean (static raw)", () => {
  it("input + output are static maps with layout raw, polymorphic byteLength", () => {
    if (typeof byteSubstitutePortContract.inputs === "function") {
      throw new Error("byte-substitute inputs should be static");
    }
    if (typeof byteSubstitutePortContract.outputs === "function") {
      throw new Error("byte-substitute outputs should be static");
    }
    expect([...byteSubstitutePortContract.inputs.keys()]).toEqual(["input"]);
    expect([...byteSubstitutePortContract.outputs.keys()]).toEqual(["output"]);
    expect(byteSubstitutePortContract.inputs.get("input")?.layout).toBe("raw");
    expect(byteSubstitutePortContract.outputs.get("output")?.layout).toBe("raw");
    expect(byteSubstitutePortContract.inputs.get("input")?.byteLength).toBeUndefined();
  });
});

describe("byte-substitute@1 — runtime dispatch guards", () => {
  const buildSpec = (): CipherSpec => ({
    id: "test-byte-substitute@1",
    name: "test byte-substitute",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [{ kind: "step", id: "s", type: "byte-substitute@1", params: { sbox: identity } }],
  });

  it("on-flag dispatch with no portInputs throws 'input port input is not wired'", () => {
    expect(() =>
      runSpec(buildSpec(), buildDefaultRegistry(), {
        initialState: emptyBytes(),
      }),
    ).toThrow(/input port 'input' is not wired/);
  });
});
