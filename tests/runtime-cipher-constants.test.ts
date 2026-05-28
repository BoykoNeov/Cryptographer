/**
 * Runtime materialization of `spec.cipherConstants` (scaffolding-suppression
 * A1).
 *
 * The runtime seeds each `spec.cipherConstants[name]` into `aux[name]` once,
 * before walking the step tree — so a leaf reads a published constant via
 * `aux-load-bytes@1` exactly like any other aux value, with no per-spec
 * "constant loader" leaf. These micro-tests pin that contract independent of
 * SHA-256 (whose KAT + finalAux assertions also exercise it end-to-end).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// Minimal spec: one identity bridge leaf, no reads of the constant. The
// constant must still be materialized into aux purely from the spec field.
const specWithConstants = (cipherConstants: Record<string, Uint8Array>): CipherSpec => ({
  id: "test-const@1",
  name: "const-test",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [{ kind: "step", id: "passthrough", type: "state-to-bytes@1", params: {} }],
  cipherConstants,
});

const run = (spec: CipherSpec) =>
  runSpec(spec, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: new Uint8Array([1, 2, 3]) },
    portedDispatchEnabled: true,
  });

describe("runtime — cipherConstants materialization (A1)", () => {
  it("seeds each constant into aux before any step runs", () => {
    const K = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const H = new Uint8Array([0x01, 0x02]);
    const trace = run(specWithConstants({ K, H }));
    expect(trace.finalAux.get("K")).toBeInstanceOf(Uint8Array);
    expect(Array.from(trace.finalAux.get("K") as Uint8Array)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(Array.from(trace.finalAux.get("H") as Uint8Array)).toEqual([0x01, 0x02]);
  });

  it("clones the constant so a downstream aux mutation can't write back into the spec", () => {
    const K = new Uint8Array([0xaa, 0xbb]);
    const spec = specWithConstants({ K });
    run(spec);
    // The spec's own buffer is untouched regardless of what the run did.
    expect(Array.from(spec.cipherConstants?.K as Uint8Array)).toEqual([0xaa, 0xbb]);
    // And the materialized aux entry is a distinct object (not the same ref).
    const trace = run(spec);
    expect(trace.finalAux.get("K")).not.toBe(spec.cipherConstants?.K);
  });

  it("is a no-op for specs without cipherConstants", () => {
    const spec: CipherSpec = {
      id: "no-const@1",
      name: "no-const",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [{ kind: "step", id: "passthrough", type: "state-to-bytes@1", params: {} }],
    };
    const trace = run(spec);
    expect(trace.finalAux.size).toBe(0);
  });
});
