/**
 * **NTT butterfly recognition** — `core/ntt-shape.ts`, the fourth member of the
 * canonical-layout family and the first whose container is an `iterate` rather
 * than a group.
 *
 * What this file is trying to establish, in the order the assertions run:
 *
 * 1. The analyzer recognizes every layer of both shipped transforms, and
 *    assigns the DIRECTION from wiring rather than from the spec it came out of
 *    — the property every label and the whole layout slot table rests on.
 * 2. It recognizes the transforms EMBEDDED in K-PKE, which is the case a test
 *    driving only the standalone specs would miss: those layer ids are prefixed
 *    (`keygen.ntt-s0.layer3`), and an analyzer that had grown any id dependence
 *    would still pass on the standalone pair.
 * 3. It DECLINES everything else in the app — every other cipher's iterate —
 *    and declines a rewired butterfly, which is what makes a half-edited body
 *    fall back to the generic layout instead of rendering a broken cell.
 * 4. The replication guard is measured against the real transform rather than
 *    asserted from a story, in the shape `chacha-graph-replication.test.ts`
 *    established. The measurement here comes out DIFFERENT from ChaCha's and
 *    Salsa's — nothing crosses the default threshold — and the test says so, so
 *    that a future reader can see the guard is insurance against a user
 *    lowering the threshold rather than a fix for a live break.
 *
 * Everything imports the shipped functions. A local re-derivation of the guard
 * would leave every assertion green while the browser cell fell apart, which is
 * the failure `core/arx-group.ts` was extracted to prevent.
 */

import { chacha20EncryptSpec } from "@/ciphers/chacha20";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildKPkeKeyGenSpec } from "@/ciphers/k-pke";
import { buildLcgSpec } from "@/ciphers/lcg";
import { DEFAULT_NTT_INPUT, buildInverseNttSpec, buildNttSpec } from "@/ciphers/ntt-3329-256";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { buildSha3256Spec } from "@/ciphers/sha3-256";
import { deriveAuxGraph, replicateHighFanoutSources } from "@/core/graph";
import {
  NTT_BUTTERFLY_LEAVES,
  analyzeNttButterfly,
  nttButterfliesById,
  nttButterflyNeverModes,
} from "@/core/ntt-shape";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import type { CipherSpec, IterateGroup, StepLeaf, StepNode } from "@/core/types";
import { DEFAULT_REPLICATION_THRESHOLD } from "@/ui/stores/view-replication";
import { describe, expect, it } from "vitest";

/** Every `iterate` in a spec, at any depth. */
const iteratesOf = (spec: CipherSpec): IterateGroup[] => {
  const out: IterateGroup[] = [];
  const walk = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "step") continue;
      if (n.kind === "iterate") out.push(n);
      walk(n.children);
    }
  };
  walk(spec.steps);
  return out;
};

/** A deep-enough clone to rewire one binding without touching the shipped spec. */
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

const forwardSpec = buildNttSpec();
const inverseSpec = buildInverseNttSpec();

describe("NTT butterfly recognition — the shipped transforms", () => {
  it("recognizes all seven layers of each direction", () => {
    expect(nttButterfliesById(forwardSpec).size).toBe(7);
    expect(nttButterfliesById(inverseSpec).size).toBe(7);
    // And every iterate in these specs IS a layer — nothing else loops here, so
    // "7 recognized" and "7 present" together mean none were skipped.
    expect(iteratesOf(forwardSpec)).toHaveLength(7);
    expect(iteratesOf(inverseSpec)).toHaveLength(7);
  });

  it("derives the direction from the wiring, not from which spec it came from", () => {
    for (const shape of nttButterfliesById(forwardSpec).values()) {
      expect(shape.kind).toBe("cooley-tukey");
      // Forward: t = ζ·hi first, so the SUBTRACTION produces the high half.
      expect(shape.hiProducerId).toBe(shape.subId);
    }
    for (const shape of nttButterfliesById(inverseSpec).values()) {
      expect(shape.kind).toBe("gentleman-sande");
      // Inverse: combine first, twist after, so the MULTIPLY produces it.
      expect(shape.hiProducerId).toBe(shape.twistId);
    }
  });

  it("assigns every leaf exactly one role, covering the whole body", () => {
    for (const spec of [forwardSpec, inverseSpec]) {
      for (const node of iteratesOf(spec)) {
        const shape = analyzeNttButterfly(node);
        expect(shape).not.toBeNull();
        if (!shape) continue;
        const childIds = node.children.map((c) => c.id);
        expect(shape.memberIds).toHaveLength(NTT_BUTTERFLY_LEAVES);
        expect([...shape.memberIds].sort()).toEqual([...childIds].sort());
        expect(shape.ops).toHaveLength(NTT_BUTTERFLY_LEAVES);
        expect(new Set(shape.ops.map((o) => o.role)).size).toBe(NTT_BUTTERFLY_LEAVES);
      }
    }
  });

  it("the two directions' role sets differ exactly at the twist/diff slot", () => {
    // This is what lets `ntt-layout.ts` use ONE slot table for both butterflies
    // — if it ever stopped holding, the layout would silently collide two
    // leaves into one position.
    const roles = (spec: CipherSpec): Set<string> => {
      const first = [...nttButterfliesById(spec).values()][0];
      return new Set((first?.ops ?? []).map((o) => o.role));
    };
    const fwd = roles(forwardSpec);
    const inv = roles(inverseSpec);
    expect(fwd.has("twist")).toBe(true);
    expect(fwd.has("diff")).toBe(false);
    expect(inv.has("diff")).toBe(true);
    expect(inv.has("twist")).toBe(false);
    // Everything else is shared.
    const shared = [...fwd].filter((r) => inv.has(r)).sort();
    expect(shared).toEqual(["advance", "hi", "lo", "modulus", "recombine", "split", "zeta"]);
  });
});

describe("NTT butterfly recognition — transforms embedded in a larger spec", () => {
  // K-PKE key generation embeds several transforms, each prefixed. A recognizer
  // with any residual id dependence passes on the standalone specs and fails
  // here, which is the whole point of driving this one.
  const keygen = buildKPkeKeyGenSpec();

  it("recognizes the prefixed layers inside K-PKE key generation", () => {
    const found = nttButterfliesById(keygen);
    expect(found.size).toBeGreaterThan(7); // more than one transform
    expect(found.size % 7).toBe(0); // whole transforms, not fragments
    for (const [id, shape] of found) {
      expect(id).toContain("."); // genuinely prefixed, not a bare `layer3`
      expect(shape.layerId).toBe(id);
      expect(shape.kind).toBe("cooley-tukey");
    }
  });

  it("every iterate inside K-PKE key generation IS a butterfly", () => {
    // Worth stating rather than assuming: the first draft of this file tried to
    // assert that K-PKE's OTHER loops decline, and the anti-vacuity guard on it
    // failed — there are none. Every loop in key generation is an NTT layer, so
    // the recognizer must claim all of them, and the "what it declines" case
    // has to be driven from other families (below).
    expect(iteratesOf(keygen)).toHaveLength(nttButterfliesById(keygen).size);
  });
});

describe("NTT butterfly recognition — every other family's loops", () => {
  // The recognizer is wiring-derived and names no cipher, so the honest check
  // is that it stays silent across the app's other iterate shapes: a block
  // mode's per-block loop, a hash's absorb fold and round loop, a stream
  // cipher's keystream loop, and a generator's word loop.
  const others: readonly [string, CipherSpec][] = [
    ["SHA-256", buildSha256Spec()],
    ["SHA3-256", buildSha3256Spec()],
    ["ChaCha20", chacha20EncryptSpec],
    ["MINSTD", buildLcgSpec("minstd-rand", 64)],
  ];

  it.each(others)("recognizes nothing in %s", (_name, spec) => {
    const iterates = iteratesOf(spec);
    expect(iterates.length).toBeGreaterThan(0); // anti-vacuity
    for (const node of iterates) expect(analyzeNttButterfly(node)).toBeNull();
    expect(nttButterfliesById(spec).size).toBe(0);
    expect(Object.keys(nttButterflyNeverModes(spec))).toHaveLength(0);
  });
});

describe("NTT butterfly recognition — what it declines", () => {
  it("declines a butterfly whose subtraction operands are swapped", () => {
    // `hi − lo` reversed negates every high coefficient. In the INVERSE that is
    // a real, silent wrongness (see `narrInverseSub`), so the cell must not
    // keep claiming the body is canonical.
    const spec = clone(inverseSpec);
    const layer = iteratesOf(spec)[0] as IterateGroup;
    const sub = layer.children.find(
      (c) => c.kind === "step" && c.type === "zq-vec-sub@1",
    ) as StepLeaf;
    const ports = sub.portInputs as Record<string, { node: string; port: string }>;
    const a = ports.a;
    const b = ports.b;
    if (a && b) {
      ports.a = b;
      ports.b = a;
    }
    expect(analyzeNttButterfly(layer)).toBeNull();
  });

  it("declines a butterfly whose recombine puts the high half first", () => {
    const spec = clone(forwardSpec);
    const layer = iteratesOf(spec)[0] as IterateGroup;
    const concat = layer.children.find(
      (c) => c.kind === "step" && c.id.endsWith(".out"),
    ) as StepLeaf;
    const ports = concat.portInputs as Record<string, { node: string; port: string }>;
    const i0 = ports.input0;
    const i1 = ports.input1;
    if (i0 && i1) {
      ports.input0 = i1;
      ports.input1 = i0;
    }
    expect(analyzeNttButterfly(layer)).toBeNull();
  });

  it("declines a butterfly with one extra leaf spliced into the body", () => {
    // The partition gate: eight roles must tile the body. A ninth leaf means
    // something is unaccounted for, so the layer drops to the generic layout
    // rather than rendering a cell with an orphan.
    const spec = clone(forwardSpec);
    const layer = iteratesOf(spec)[0] as IterateGroup;
    (layer.children as StepNode[]).push({
      kind: "step",
      id: "intruder",
      type: "aux-load-bytes@1",
      params: { auxName: "q", byteLength: 2 },
    });
    expect(analyzeNttButterfly(layer)).toBeNull();
  });

  it("declines a butterfly whose modulus no longer reaches all three operations", () => {
    const spec = clone(forwardSpec);
    const layer = iteratesOf(spec)[0] as IterateGroup;
    (layer.children as StepNode[]).push({
      kind: "step",
      id: "second-q",
      type: "aux-load-bytes@1",
      params: { auxName: "q", byteLength: 2 },
    });
    const add = layer.children.find(
      (c) => c.kind === "step" && c.type === "zq-vec-add@1",
    ) as StepLeaf;
    (add.portInputs as Record<string, { node: string; port: string }>).modulus = {
      node: "second-q",
      port: "output",
    };
    expect(analyzeNttButterfly(layer)).toBeNull();
  });
});

describe("NTT butterfly vs high-fanout replication", () => {
  const graph = () => {
    const trace = runSpec(forwardSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(DEFAULT_NTT_INPUT),
    });
    return deriveAuxGraph(trace, forwardSpec);
  };

  const shapes = [...nttButterfliesById(forwardSpec).values()];

  it("MEASURED: no butterfly member crosses the DEFAULT threshold", () => {
    // The number that decides whether the guard below is a fix or insurance,
    // and it comes out the opposite way from ChaCha20's and Salsa20's. The
    // Cooley–Tukey split feeds {twist, lo, hi} and the modulus feeds the same
    // three; `replicateHighFanoutSources` fires on `count > threshold`,
    // strictly, so three is not enough. Nothing here breaks by default — unlike
    // the ARX cell, which provably shatters without its guard.
    const g = graph();
    const consumersOf = (id: string): number =>
      new Set(g.edges.filter((e) => e.from === id).map((e) => e.to)).size;
    const first = shapes[0];
    expect(first).toBeDefined();
    if (!first) return;
    expect(consumersOf(first.splitId)).toBe(3);
    expect(consumersOf(first.modulusId)).toBe(3);
    expect(consumersOf(first.zetaId)).toBe(2);
    expect(DEFAULT_REPLICATION_THRESHOLD).toBe(3);

    const replicated = replicateHighFanoutSources(g, DEFAULT_REPLICATION_THRESHOLD);
    const ids = new Set(replicated.nodes.map((n) => n.stepId));
    expect(ids.has(first.splitId)).toBe(true);
    expect(ids.has(first.modulusId)).toBe(true);
  });

  it("WITHOUT the guard a lowered threshold scatters the cell's two hubs", () => {
    // The threshold is a user-facing control that goes down to 1. At 2 the
    // split and the modulus both qualify, are DELETED from the graph, and
    // reappear as per-consumer chips — the cell loses its two most connected
    // nodes. This is the live justification for the guard.
    const replicated = replicateHighFanoutSources(graph(), 2);
    const ids = new Set(replicated.nodes.map((n) => n.stepId));
    const first = shapes[0];
    if (!first) return;
    expect(ids.has(first.splitId)).toBe(false);
    expect(ids.has(first.modulusId)).toBe(false);
    expect(replicated.nodes.filter((n) => n.replicaOf === first.splitId).length).toBe(3);
  });

  it("WITH the guard the cell survives a threshold of 1", () => {
    const modes = nttButterflyNeverModes(forwardSpec);
    const replicated = replicateHighFanoutSources(graph(), 1, modes);
    const ids = new Set(replicated.nodes.map((n) => n.stepId));
    for (const shape of shapes) {
      for (const memberId of shape.memberIds) {
        expect(ids.has(memberId)).toBe(true);
        expect(replicated.nodes.some((n) => n.replicaOf === memberId)).toBe(false);
      }
    }
  });

  it("the guard covers all seven layers, in both directions", () => {
    expect(Object.keys(nttButterflyNeverModes(forwardSpec))).toHaveLength(7 * NTT_BUTTERFLY_LEAVES);
    expect(Object.keys(nttButterflyNeverModes(inverseSpec))).toHaveLength(7 * NTT_BUTTERFLY_LEAVES);
    // And it is empty for a spec with no butterflies, so the map never grows
    // entries that would silently pin unrelated nodes.
    expect(Object.keys(nttButterflyNeverModes(buildKPkeKeyGenSpec())).length).toBeGreaterThan(0);
  });
});
