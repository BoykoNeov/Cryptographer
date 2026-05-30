/**
 * Unit test for the `xor-with-aux@1` port-native primitive (scaffolding-
 * suppression Finding F3, 2026-05-30). The single-step AddRoundKey: XOR the
 * `input` port with the `operand` port (which the runtime projects from
 * `aux[params.auxName]` via `meta.auxReadPorts`).
 *
 * End-to-end crypto coverage lives in the AES KATs (`aes-vectors`,
 * `aes-{192,256}-vectors`, `aes-decrypt`, ECB/CBC) — the FIPS-197 §B
 * intermediate `193de3be…` after the initial AddRoundKey pins the XOR math
 * against the published vector. This file pins the primitive's contract in
 * isolation: the XOR result, the meta aux-read binding, and the error paths.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { xorWithAux, xorWithAuxMeta, xorWithAuxPortContract } from "@/steps/xor-with-aux";
import { describe, expect, it } from "vitest";

const ctx = { stepId: "x", path: [] as string[], aux: new Map<string, AuxValue>() };

describe("xor-with-aux@1 — executor", () => {
  it("XORs the input port with the operand (aux) port byte-for-byte", () => {
    const out = xorWithAux(
      new Map([
        ["input", new Uint8Array([0x00, 0x11, 0x22, 0xff])],
        ["operand", new Uint8Array([0xff, 0x0f, 0x22, 0x0f])],
      ]),
      { auxName: "roundKey.0" },
      ctx,
    );
    expect(out.get("output")).toEqual(new Uint8Array([0xff, 0x1e, 0x00, 0xf0]));
  });

  it("is self-inverse: XORing the same operand twice recovers the input", () => {
    const input = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const operand = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const once = xorWithAux(
      new Map([
        ["input", input],
        ["operand", operand],
      ]),
      { auxName: "k" },
      ctx,
    );
    const twice = xorWithAux(
      new Map([
        ["input", once.get("output") as Uint8Array],
        ["operand", operand],
      ]),
      { auxName: "k" },
      ctx,
    );
    expect(twice.get("output")).toEqual(input);
  });

  it("throws when the input port is unwired", () => {
    expect(() =>
      xorWithAux(new Map([["operand", new Uint8Array([0x01])]]), { auxName: "k" }, ctx),
    ).toThrow(/input port 'input' is not wired/);
  });

  it("throws when the operand (aux) port is unavailable", () => {
    expect(() =>
      xorWithAux(new Map([["input", new Uint8Array([0x01])]]), { auxName: "k" }, ctx),
    ).toThrow(/operand port not available/);
  });

  it("throws on a length mismatch between input and operand", () => {
    expect(() =>
      xorWithAux(
        new Map([
          ["input", new Uint8Array([0x01, 0x02])],
          ["operand", new Uint8Array([0x01])],
        ]),
        { auxName: "k" },
        ctx,
      ),
    ).toThrow(/length mismatch/);
  });

  it("throws when params.auxName is not a string", () => {
    expect(() =>
      xorWithAux(
        new Map([
          ["input", new Uint8Array([0x01])],
          ["operand", new Uint8Array([0x01])],
        ]),
        { auxName: 5 as unknown as string },
        ctx,
      ),
    ).toThrow(/auxName must be a string/);
  });
});

describe("xor-with-aux@1 — projection metadata + port contract", () => {
  it("binds the `operand` input port to aux[params.auxName]", () => {
    expect(xorWithAuxMeta.auxReadPorts?.({ auxName: "roundKey.7" })).toEqual(
      new Map([["operand", "roundKey.7"]]),
    );
  });

  it("emits the binding even for an empty auxName (orphan-read glyph survives)", () => {
    // Mirrors aux-load-bytes@1 — the unconditional binding is what records
    // auxReadMissing so the editor flags a half-wired leaf.
    expect(xorWithAuxMeta.auxReadPorts?.({})).toEqual(new Map([["operand", ""]]));
  });

  it("declares raw, polymorphic (no byteLength) ports so it is variant-agnostic", () => {
    const inputs = xorWithAuxPortContract.inputs as Map<
      string,
      { layout: string; byteLength?: number }
    >;
    expect(inputs.get("input")).toEqual({ layout: "raw" });
    expect(inputs.get("operand")).toEqual({ layout: "raw" });
    const outputs = xorWithAuxPortContract.outputs as Map<string, { layout: string }>;
    expect(outputs.get("output")).toEqual({ layout: "raw" });
  });
});

describe("xor-with-aux@1 — integration (records auxRead → graph fan-out preserved)", () => {
  it("AES-128 initial AddRoundKey records auxRead[roundKey.0] and exposes the XOR on portOutputs", () => {
    // The byte-native AES-128 `initial.add-round-key` IS a `xor-with-aux@1`
    // leaf. It must (a) record roundKey.0 in frame.auxRead — what preserves
    // the key-expansion → AddRoundKey graph fan-out — and (b) expose its XOR
    // result on frame.portOutputs (the F3 runtime fix: hybrid ported steps
    // carry port I/O). FIPS-197 §B intermediate is `193de3be…`.
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("3243f6a8885a308d313198a2e0370734")),
      initialAux: new Map<string, AuxValue>([
        ["key", bytesFromHex("2b7e151628aed2a6abf7158809cf4f3c")],
      ]),
      portedDispatchEnabled: true,
    });
    const ark = trace.frames.find((f) => f.stepId === "initial.add-round-key");
    expect(ark).toBeDefined();
    expect(ark?.auxRead.has("roundKey.0")).toBe(true);
    const out = ark?.portOutputs?.get("output");
    expect(out).toBeInstanceOf(Uint8Array);
    if (!out) return;
    expect(Buffer.from(out).toString("hex")).toBe("193de3bea0f4e22b9ac68d2ae9f84808");
  });
});
