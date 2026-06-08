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
import { deriveAuxGraph, validateGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import type { StepNode, Trace } from "@/core/types";
import { publishKeyParams, publishKeyParamsMeta } from "@/steps/publish-key-params";
import { describe, expect, it } from "vitest";

const W = 2;
const registry = buildDefaultRegistry();

type StepLeaf = Extract<StepNode, { kind: "step" }>;

/** Flatten a spec's step tree to its leaves (RSA nests one group; recurse). */
const collectLeaves = (nodes: readonly StepNode[]): StepLeaf[] => {
  const out: StepLeaf[] = [];
  for (const n of nodes) {
    if (n.kind === "step") out.push(n);
    else if (n.kind === "group" || n.kind === "iterate") out.push(...collectLeaves(n.children));
  }
  return out;
};

/** Map of leaf id → its narrationOverride name (undefined if no override). */
const overrideNames = (spec: { steps: readonly StepNode[] }): Map<string, string | undefined> =>
  new Map(collectLeaves(spec.steps).map((leaf) => [leaf.id, leaf.narrationOverride?.name]));

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
  it("encrypt's publish tail emits the PUBLIC key {n=3233, e=17} on its output ports", () => {
    const trace = runRsa("encrypt", 65);
    expect(frameOut(trace, "publish-key", "n")).toBe(3233n);
    expect(frameOut(trace, "publish-key", "e")).toBe(17n);
  });

  it("decrypt's publish tail emits the PRIVATE key {n=3233, d=2753} on its output ports", () => {
    const trace = runRsa("decrypt", 2790);
    expect(frameOut(trace, "publish-key", "n")).toBe(3233n);
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

  it("each direction publishes EXACTLY its consumed key (no unused aux write)", () => {
    // Encrypt writes the public key {rsa.n, rsa.e} and NOT rsa.d — publishing
    // the unused private exponent would leave an unread aux value (unused-write
    // warning). Decrypt is the mirror.
    const enc = runRsa("encrypt", 65).frames.find((f) => f.stepId === "publish-key");
    if (!enc) throw new Error("no encrypt publish-key frame");
    expect(enc.auxWritten.has(`${RSA_AUX_PREFIX}.n`)).toBe(true);
    expect(enc.auxWritten.has(`${RSA_AUX_PREFIX}.e`)).toBe(true);
    expect(enc.auxWritten.has(`${RSA_AUX_PREFIX}.d`)).toBe(false);

    const dec = runRsa("decrypt", 2790).frames.find((f) => f.stepId === "publish-key");
    if (!dec) throw new Error("no decrypt publish-key frame");
    expect(dec.auxWritten.has(`${RSA_AUX_PREFIX}.n`)).toBe(true);
    expect(dec.auxWritten.has(`${RSA_AUX_PREFIX}.d`)).toBe(true);
    expect(dec.auxWritten.has(`${RSA_AUX_PREFIX}.e`)).toBe(false);
  });
});

describe("RSA Phase 2 — graph validates with no unused-write warnings", () => {
  // The durable encoding of what the manual browser pass caught: publishing all
  // three key parameters left rsa.d (encrypt) / rsa.e (decrypt) written-but-
  // unread, which `validateGraph` flags as `unused-write` — an orange warning
  // glyph on the DEFAULT spec. Publishing only the consumed key removes it.
  for (const direction of ["encrypt", "decrypt"] as const) {
    it(`${direction} produces zero unused-write warnings`, () => {
      const spec = buildRsaSpec(direction, W);
      const trace = runRsa(direction, direction === "encrypt" ? 65 : 2790);
      const warnings = validateGraph(deriveAuxGraph(trace, spec), trace);
      const unused = warnings.filter((w) => w.kind === "unused-write");
      expect(unused, `unexpected unused-write warnings: ${JSON.stringify(unused)}`).toEqual([]);
    });
  }
});

describe("rsa.publish-key-params@1 executor + meta contract", () => {
  // The executor ignores ctx (aux-only via meta); a minimal valid StepContext.
  const ctx = { stepId: "publish-key", path: [], aux: new Map() };

  it("is an identity passthrough on exactly the keys it is told to publish", () => {
    // Encrypt-shaped instance: publishes the public key {n, e}.
    const params = { outputPrefix: RSA_AUX_PREFIX, keys: ["n", "e"] };
    const inputs = new Map<string, Uint8Array>([
      ["n", bigIntToBytes(3233n, W)],
      ["e", bigIntToBytes(17n, W)],
    ]);
    const out = publishKeyParams(inputs, params, ctx);
    expect(bytesToBigInt(out.get("n") as Uint8Array)).toBe(3233n);
    expect(bytesToBigInt(out.get("e") as Uint8Array)).toBe(17n);
    expect(out.has("d")).toBe(false); // not in `keys` → not emitted
  });

  it("throws when params.keys is missing or empty (no default — it is direction-specific)", () => {
    const inputs = new Map<string, Uint8Array>([["n", bigIntToBytes(3233n, W)]]);
    expect(() => publishKeyParams(inputs, { outputPrefix: RSA_AUX_PREFIX }, ctx)).toThrow(
      /params\.keys/,
    );
  });

  it("throws a friendly error when a listed key-parameter port is unwired", () => {
    const params = { outputPrefix: RSA_AUX_PREFIX, keys: ["n", "d"] };
    const inputs = new Map<string, Uint8Array>([
      ["n", bigIntToBytes(3233n, W)],
      // d missing
    ]);
    expect(() => publishKeyParams(inputs, params, ctx)).toThrow(/input port "d"/);
  });

  it("maps each published key to its prefixed aux key via meta.auxWritePorts", () => {
    const bindings = publishKeyParamsMeta.auxWritePorts?.({
      outputPrefix: RSA_AUX_PREFIX,
      keys: ["n", "d"],
    });
    expect(bindings?.get("n")).toBe("rsa.n");
    expect(bindings?.get("d")).toBe("rsa.d");
    expect(bindings?.has("e")).toBe(false); // not published in this instance
  });
});

describe("RSA Phase 2 — per-leaf narrationOverride", () => {
  it("names every key-generation leaf with cipher-specific prose", () => {
    // The registry doc for `mul@1` is the generic "Multiply"; the narration
    // override is what makes THIS mul leaf read as "Modulus n = p·q" etc.
    const names = overrideNames(buildRsaSpec("encrypt", W));
    expect(names.get("load-p")).toBe("Load prime p");
    expect(names.get("load-q")).toBe("Load prime q");
    expect(names.get("load-e")).toBe("Load public exponent e");
    expect(names.get("one")).toBe("Constant 1");
    expect(names.get("n")).toBe("Modulus n = p·q");
    expect(names.get("p-minus-1")).toBe("p − 1");
    expect(names.get("q-minus-1")).toBe("q − 1");
    expect(names.get("phi")).toBe("Totient φ(n) = (p−1)(q−1)");
    expect(names.get("d")).toBe("Private exponent d = e⁻¹ mod φ(n)");
  });

  it("names ladder rungs with their rung number + tested exponent bit", () => {
    const names = overrideNames(buildRsaSpec("encrypt", W));
    const totalRungs = W * 8; // 16
    // square-0 is rung 1 of 16; mult-0 tests the MSB (bitIndex = 15).
    expect(names.get("square-0")).toBe(`Square (rung 1/${totalRungs})`);
    expect(names.get("mult-0")).toBe("Multiply if exponent bit 15 is set");
    // square-15 is the last rung; mult-15 tests the LSB (bitIndex = 0).
    expect(names.get("square-15")).toBe(`Square (rung 16/${totalRungs})`);
    expect(names.get("mult-15")).toBe("Multiply if exponent bit 0 is set");
  });

  it("leaves the publish tail to its registry doc (no override)", () => {
    // The aux-publish tail's own StepDocumentation is already cipher-specific
    // ("Publish key parameters (RSA)") — same posture as the key-schedule
    // publish tails, which carry no narrationOverride either.
    const names = overrideNames(buildRsaSpec("encrypt", W));
    expect(names.get("publish-key")).toBeUndefined();
  });
});
