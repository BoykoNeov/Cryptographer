/**
 * RSA Phase 2 — "Key Generation" group + cross-scope aux export
 * (`docs/plans/shimmying-booping-moth.md`).
 *
 * Phase 1 built RSA flat so `n`/`φ`/`d` fanned out port-to-port to the ladder.
 * Phase 2 wraps the key-gen leaves in a collapsible group, which re-introduces
 * the group-scope wall: a rung OUTSIDE the group can no longer reference a port
 * INSIDE it. The `rsa.publish-key-params@1` tail bridges the wall by mirroring
 * n/e/d into `aux["rsa.n" | "rsa.e" | "rsa.d"]`, and the ladder reads them back
 * via top-level `aux-load-bytes@1` loaders.
 *
 * This test proves the bridge end-to-end: the published values reach the
 * loaders byte-identically (the same `n=3233`, `e=17`, `d=2753` the flat spec
 * computed), and the executor + meta contract behave. The exhaustive KAT
 * round-trip in `rsa-vectors.test.ts` is the math gate; this is the topology
 * gate (the wrap didn't change the numbers, and the publish tail wires right).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { RSA_AUX_PREFIX, buildRsaSpec } from "@/ciphers/rsa";
import { bigIntToBytes, bytesToBigInt } from "@/core/big-int-codec";
import { runSpec } from "@/core/runtime";
import type { Trace } from "@/core/types";
import { publishKeyParams, publishKeyParamsMeta } from "@/steps/publish-key-params";
import { describe, expect, it } from "vitest";

const W = 2;
const registry = buildDefaultRegistry();

/** Run an RSA spec on a numeric message; return the trace. */
const runRsa = (direction: "encrypt" | "decrypt", message: number): Trace =>
  runSpec(buildRsaSpec(direction, W), registry, {
    initialState: { shape: "bytes", bytes: bigIntToBytes(BigInt(message), W) },
  });

/** Read a frame's output port as a BigInt. */
const frameOut = (trace: Trace, stepId: string, port = "output"): bigint => {
  const frame = trace.frames.find((f) => f.stepId === stepId);
  if (!frame) throw new Error(`no frame for stepId "${stepId}"`);
  const out = frame.portOutputs?.get(port);
  if (out === undefined) throw new Error(`frame "${stepId}" has no "${port}" output port`);
  return bytesToBigInt(out);
};

describe("RSA Phase 2 — Key-Generation group structure", () => {
  it("wraps the key-gen leaves in a default-EXPANDED group whose tail is the publish step", () => {
    const spec = buildRsaSpec("encrypt", W);
    const first = spec.steps[0];
    if (first?.kind !== "group")
      throw new Error("expected steps[0] to be the key-generation group");
    expect(first.id).toBe("key-generation");
    expect(first.label).toBe("Key Generation");
    // Default-EXPANDED: key generation is RSA's headline feature, so the group
    // must NOT default-collapse (that would hide what Phase 1 showed).
    expect(first.defaultCollapsed).toBeUndefined();
    // The publish tail is the group's last child.
    const last = first.children[first.children.length - 1];
    if (last?.kind !== "step") throw new Error("expected the publish tail to be a step leaf");
    expect(last.type).toBe("rsa.publish-key-params@1");
  });

  it("keeps the exponentiation ladder flat (the group is the only container)", () => {
    const spec = buildRsaSpec("encrypt", W);
    const groups = spec.steps.filter((s) => s.kind === "group");
    expect(groups.length).toBe(1);
    // The ladder rungs are top-level leaves, not wrapped.
    expect(spec.steps.some((s) => s.kind === "step" && s.id === "square-0")).toBe(true);
  });
});

describe("RSA Phase 2 — cross-scope aux export is byte-identical", () => {
  it("the publish tail emits n=3233, e=17, d=2753 on its output ports", () => {
    const trace = runRsa("encrypt", 65);
    expect(frameOut(trace, "publish-key", "n")).toBe(3233n);
    expect(frameOut(trace, "publish-key", "e")).toBe(17n);
    expect(frameOut(trace, "publish-key", "d")).toBe(2753n);
  });

  it("the published modulus crosses the wall: load-n reads back n=3233", () => {
    const trace = runRsa("encrypt", 65);
    expect(frameOut(trace, "load-n")).toBe(3233n);
  });

  it("encrypt loads the PUBLIC exponent e=17 across the wall (rsa.e)", () => {
    const trace = runRsa("encrypt", 65);
    expect(frameOut(trace, "load-exp")).toBe(17n);
  });

  it("decrypt loads the PRIVATE exponent d=2753 across the wall (rsa.d)", () => {
    const trace = runRsa("decrypt", 2790);
    expect(frameOut(trace, "load-exp")).toBe(2753n);
  });

  it("the publish frame writes the three named aux keys (rsa.n / rsa.e / rsa.d)", () => {
    const trace = runRsa("encrypt", 65);
    const frame = trace.frames.find((f) => f.stepId === "publish-key");
    if (!frame) throw new Error("no publish-key frame");
    for (const name of ["n", "e", "d"]) {
      expect(frame.auxWritten.has(`${RSA_AUX_PREFIX}.${name}`)).toBe(true);
    }
  });
});

describe("rsa.publish-key-params@1 executor + meta contract", () => {
  const params = { outputPrefix: RSA_AUX_PREFIX };
  // The executor ignores ctx (aux-only via meta); a minimal valid StepContext.
  const ctx = { stepId: "publish-key", path: [], aux: new Map() };

  it("is an identity passthrough on its three named ports", () => {
    const inputs = new Map<string, Uint8Array>([
      ["n", bigIntToBytes(3233n, W)],
      ["e", bigIntToBytes(17n, W)],
      ["d", bigIntToBytes(2753n, W)],
    ]);
    const out = publishKeyParams(inputs, params, ctx);
    expect(bytesToBigInt(out.get("n") as Uint8Array)).toBe(3233n);
    expect(bytesToBigInt(out.get("e") as Uint8Array)).toBe(17n);
    expect(bytesToBigInt(out.get("d") as Uint8Array)).toBe(2753n);
  });

  it("throws a friendly error when a key-parameter port is unwired", () => {
    const inputs = new Map<string, Uint8Array>([
      ["n", bigIntToBytes(3233n, W)],
      ["e", bigIntToBytes(17n, W)],
      // d missing
    ]);
    expect(() => publishKeyParams(inputs, params, ctx)).toThrow(/input port "d"/);
  });

  it("maps each output port to its prefixed aux key via meta.auxWritePorts", () => {
    const bindings = publishKeyParamsMeta.auxWritePorts?.(params);
    expect(bindings?.get("n")).toBe("rsa.n");
    expect(bindings?.get("e")).toBe("rsa.e");
    expect(bindings?.get("d")).toBe("rsa.d");
  });
});
