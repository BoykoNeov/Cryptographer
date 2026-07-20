/**
 * ChaCha20 double-round SPLIT vs `replicateHighFanoutSources`.
 *
 * **Why this file exists.** When Twofish's canonical 4-rail cell shipped, ~60
 * unit tests were green and the cell was still broken in the browser: the round
 * split's fan-out exceeded the replication threshold, so the pipeline DELETED
 * it and scattered it into per-consumer chips. Nothing in the layout tests
 * could see it, because the layout module is never told what the replication
 * pass did. It was found by opening a browser (see
 * `feedback_visual_smoke_vs_property_tests`).
 *
 * ChaCha20's split is a far worse case — sixteen outputs — so rather than
 * repeat the discovery, this file drives the REAL pipeline and pins both halves
 * of the mechanism:
 *
 *   1. Without the guard, the split really would be replicated away. (Asserted
 *      against the actual transform, so it is a measurement and not a story.)
 *   2. With the guard, it survives intact and the cell holds together.
 *
 * The subtlety worth recording: `replicateHighFanoutSources` counts distinct
 * consumers per source NODE, not per output PORT. Each of the split's sixteen
 * ports feeds exactly one consumer, so a per-port rule would never have fired
 * and this whole hazard would not exist. That is precisely why it had to be
 * checked against the pipeline instead of reasoned about.
 */

import { chacha20EncryptSpec } from "@/ciphers/chacha20";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { analyzeChaChaDoubleRound } from "@/core/chacha-shape";
import { deriveAuxGraph, replicateHighFanoutSources } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, StepGroup, StepNode } from "@/core/types";
import { DEFAULT_REPLICATION_THRESHOLD } from "@/ui/stores/view-replication";
import { describe, expect, it } from "vitest";

const KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const IV = "01000000000000000000004a00000000";
const PT = "4c616469657320616e642047656e746c";

const chachaGraph = () => {
  const trace = runSpec(chacha20EncryptSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(PT)),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex(KEY)],
      ["iv", bytesFromHex(IV)],
    ]),
  });
  return deriveAuxGraph(trace, chacha20EncryptSpec);
};

/** Every recognized double round in the shipped spec. */
const doubleRoundShapes = () => {
  const out: ReturnType<typeof analyzeChaChaDoubleRound>[] = [];
  const walk = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "group") {
        const s = analyzeChaChaDoubleRound(n as StepGroup);
        if (s) out.push(s);
        walk(n.children);
      } else if (n.kind === "iterate") walk(n.children);
    }
  };
  walk(chacha20EncryptSpec.steps);
  return out.filter((s): s is NonNullable<typeof s> => s !== null);
};

/** The `"never"` map GraphView builds for ChaCha rounds. */
const neverModes = (): Record<string, "never"> => {
  const modes: Record<string, "never"> = {};
  for (const shape of doubleRoundShapes()) {
    for (const id of [
      shape.splitId,
      shape.concatId,
      ...shape.quarterRounds.flatMap((qr) => qr.memberIds),
    ]) {
      modes[id] = "never";
    }
  }
  return modes;
};

describe("ChaCha20 double-round split vs high-fanout replication", () => {
  const shapes = doubleRoundShapes();
  const splitIds = shapes.map((s) => s.splitId);

  it("MEASURED: the split feeds far more distinct consumers than the threshold", () => {
    // The number that decides everything, and it is worth spelling out because
    // guessing it got it wrong. Each of the four COLUMN quarter rounds reads
    // the split through FOUR heads, not three:
    //
    //   a += b   ← takes two split outputs (a and b)
    //   d ^= a   ← takes d
    //   c += d   ← takes c
    //   b ^= c   ← takes b AGAIN, because b is not reassigned until the <<<12
    //              that follows it
    //
    // So 4 rounds × 4 consumers = 16 distinct consumers over 20 edges. (The
    // four DIAGONAL rounds read the column rounds' outputs, not the split.)
    const graph = chachaGraph();
    const edges = graph.edges.filter((e) => e.from === splitIds[0]);
    const consumers = new Set(edges.map((e) => e.to));
    expect(edges).toHaveLength(20);
    expect(consumers.size).toBe(16);
    expect(consumers.size).toBeGreaterThan(DEFAULT_REPLICATION_THRESHOLD);
  });

  it("WITHOUT the guard the split is replicated away — the Twofish failure, reproduced", () => {
    // Not a hypothetical: this is the transform the app actually runs. If this
    // assertion ever flips to "survives", the guard below has become dead code
    // and should be removed rather than left as cargo.
    const replicated = replicateHighFanoutSources(chachaGraph(), DEFAULT_REPLICATION_THRESHOLD);
    const ids = new Set(replicated.nodes.map((n) => n.stepId));
    expect(ids.has(splitIds[0] as string)).toBe(false);
    expect(replicated.nodes.filter((n) => n.replicaOf === splitIds[0]).length).toBe(16);
  });

  it("WITH the guard every split survives and spawns no replicas", () => {
    const replicated = replicateHighFanoutSources(
      chachaGraph(),
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
      chachaGraph(),
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
});
