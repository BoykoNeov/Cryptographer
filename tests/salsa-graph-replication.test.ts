/**
 * Salsa20 double-round SPLIT vs `replicateHighFanoutSources` — the sibling of
 * `chacha-graph-replication.test.ts`, and for the same hard-won reason.
 *
 * **Why this file exists.** When Twofish's canonical 4-rail cell shipped, ~60
 * unit tests were green and the cell was still broken in the browser: the round
 * split's fan-out exceeded the replication threshold, so the pipeline DELETED
 * it and scattered it into per-consumer chips. Nothing in the layout tests
 * could see it, because the layout module is never told what the replication
 * pass did. It was found by opening a browser (see
 * `feedback_visual_smoke_vs_property_tests`).
 *
 * Salsa20 inherits that hazard wholesale — and, as measured below, its split
 * feeds *more* distinct consumers than ChaCha's does, because Salsa reads a
 * word from the split on three of its four written lines rather than two. So
 * this file drives the REAL pipeline and pins both halves of the mechanism:
 *
 *   1. Without the guard, the split really would be replicated away. (Asserted
 *      against the actual transform, so it is a measurement and not a story.)
 *   2. With the guard, it survives intact and the cell holds together.
 *
 * **The guard under test is the REAL one, imported.** `GraphView`'s `"never"`
 * map is `arxRoundNeverModes(spec())` and nothing else, so this file calls that
 * exact function. It used to re-implement the composition locally — which meant
 * narrowing the shipped guard back to one cipher would have left every
 * assertion here green while the browser cell fell apart, the very failure this
 * file was written to prevent. The function lives in `core/arx-group.ts`
 * precisely so a node-environment test can reach it without importing a Solid
 * component tree.
 */

import { chacha20EncryptSpec } from "@/ciphers/chacha20";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { SALSA20_IV_BYTES, salsa20EncryptSpec } from "@/ciphers/salsa20";
import { arxRoundNeverModes } from "@/core/arx-group";
import { deriveAuxGraph, replicateHighFanoutSources } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { analyzeSalsaDoubleRound } from "@/core/salsa-shape";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, StepGroup, StepNode } from "@/core/types";
import { DEFAULT_REPLICATION_THRESHOLD } from "@/ui/stores/view-replication";
import { describe, expect, it } from "vitest";

const KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PT = "4c616469657320616e642047656e746c";
/** Counter 0 ‖ an 8-byte nonce — Salsa's IV is 8/8, not ChaCha's 4/12. */
const IV = new Uint8Array(SALSA20_IV_BYTES);
IV.set(bytesFromHex("0001020304050607"), 8);

const salsaGraph = () => {
  const trace = runSpec(salsa20EncryptSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(PT)),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex(KEY)],
      ["iv", IV],
    ]),
  });
  return deriveAuxGraph(trace, salsa20EncryptSpec);
};

/** Every recognized double round in the shipped spec. */
const doubleRoundShapes = () => {
  const out: NonNullable<ReturnType<typeof analyzeSalsaDoubleRound>>[] = [];
  const walk = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "group") {
        const s = analyzeSalsaDoubleRound(n as StepGroup);
        if (s) out.push(s);
        walk(n.children);
      } else if (n.kind === "iterate") walk(n.children);
    }
  };
  walk(salsa20EncryptSpec.steps);
  return out;
};

/**
 * The `"never"` map `GraphView` builds — literally the function the component
 * calls, applied to the shipped Salsa20 spec. Nothing is re-derived here, which
 * is the point: a change that narrows the guard breaks this file.
 */
const neverModes = (): Record<string, "never"> => arxRoundNeverModes(salsa20EncryptSpec);

describe("Salsa20 double-round split vs high-fanout replication", () => {
  const shapes = doubleRoundShapes();
  const splitIds = shapes.map((s) => s.splitId);

  it("MEASURED: the split feeds far more distinct consumers than the threshold", () => {
    // The number that decides everything, and it is worth spelling out because
    // it is NOT ChaCha's number. Each of the four COLUMN quarter rounds reads
    // the split through SIX heads:
    //
    //   z1 = y1 ^ ((y0 + y3) <<<  7)   ← the add takes y0 and y3; the xor takes y1
    //   z2 = y2 ^ ((z1 + y0) <<<  9)   ← the add takes y0 AGAIN; the xor takes y2
    //   z3 = y3 ^ ((z2 + z1) <<< 13)   ← the add takes neither; the xor takes y3
    //   z0 = y0 ^ ((z3 + z2) <<< 18)   ← the add takes neither; the xor takes y0
    //
    // Six consumers over seven edges, per round. Salsa reaches back to the raw
    // state on three of its four lines because only its XORs write back, so a
    // word stays "original" longer than in ChaCha's in-place form — which is
    // exactly why its split is the more extreme case of the two.
    const graph = salsaGraph();
    const edges = graph.edges.filter((e) => e.from === splitIds[0]);
    const consumers = new Set(edges.map((e) => e.to));
    expect(edges).toHaveLength(28);
    expect(consumers.size).toBe(24);
    expect(consumers.size).toBeGreaterThan(DEFAULT_REPLICATION_THRESHOLD);
  });

  it("WITHOUT the guard the split is replicated away — the Twofish failure, reproduced", () => {
    // Not a hypothetical: this is the transform the app actually runs. If this
    // assertion ever flips to "survives", the guard below has become dead code
    // and should be removed rather than left as cargo.
    const replicated = replicateHighFanoutSources(salsaGraph(), DEFAULT_REPLICATION_THRESHOLD);
    const ids = new Set(replicated.nodes.map((n) => n.stepId));
    expect(ids.has(splitIds[0] as string)).toBe(false);
    expect(replicated.nodes.filter((n) => n.replicaOf === splitIds[0]).length).toBe(24);
  });

  it("WITH the guard every split survives and spawns no replicas", () => {
    const replicated = replicateHighFanoutSources(
      salsaGraph(),
      DEFAULT_REPLICATION_THRESHOLD,
      neverModes(),
    );
    const ids = new Set(replicated.nodes.map((n) => n.stepId));
    for (const splitId of splitIds) {
      expect(ids.has(splitId)).toBe(true);
      expect(replicated.nodes.some((n) => n.replicaOf === splitId)).toBe(false);
    }
  });

  it("WITH the guard no round member anywhere is replicated", () => {
    // The cell is only intact if all 98 leaves of all 10 rounds stay put.
    const replicated = replicateHighFanoutSources(
      salsaGraph(),
      DEFAULT_REPLICATION_THRESHOLD,
      neverModes(),
    );
    const guarded = new Set(Object.keys(neverModes()));
    for (const node of replicated.nodes) {
      if (node.replicaOf !== undefined) {
        expect(guarded.has(node.replicaOf)).toBe(false);
      }
    }
  });

  it("the guard covers all ten double rounds, not just the first", () => {
    expect(shapes).toHaveLength(10);
    expect(Object.keys(neverModes())).toHaveLength(10 * 98);
  });

  it("the guard generalizes with the SHAPE FAMILY, not the cipher list", () => {
    // The assertion a locally-rebuilt map could never make, and the reason this
    // one is imported: ONE function, unchanged, covers both ARX ciphers.
    // Narrowing it to either analyzer alone empties one of these two maps.
    expect(Object.keys(arxRoundNeverModes(salsa20EncryptSpec))).toHaveLength(10 * 98);
    expect(Object.keys(arxRoundNeverModes(chacha20EncryptSpec))).toHaveLength(10 * 98);
  });
});
