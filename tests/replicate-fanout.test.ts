/**
 * Tests for `replicateHighFanoutSources` (commit 4 of the graph-readability
 * sequence). Drives the pure transform directly against the AES-128 graph.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { deriveAuxGraph, replicateHighFanoutSources } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY = "000102030405060708090a0b0c0d0e0f";
const PT = "00112233445566778899aabbccddeeff";

const aes128Graph = () => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex(PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]),
  });
  return deriveAuxGraph(trace, aes128Spec);
};

describe("replicateHighFanoutSources", () => {
  it("threshold <= 0 returns the input graph by reference (off short-circuit)", () => {
    const g = aes128Graph();
    expect(replicateHighFanoutSources(g, 0)).toBe(g);
    expect(replicateHighFanoutSources(g, -5)).toBe(g);
  });

  it("no source above threshold returns the input by reference", () => {
    const g = aes128Graph();
    // AES-128 key-expansion has 11 outgoing aux edges. A threshold of 50
    // is above every source's fanout, so the transform is identity.
    expect(replicateHighFanoutSources(g, 50)).toBe(g);
  });

  it("replicates key-expansion (11 roundKey edges) when threshold = 6", () => {
    const g = aes128Graph();
    const r = replicateHighFanoutSources(g, 6);

    // Count nodes that look like replicas of key-expansion.
    const replicas = r.nodes.filter((n) => n.replicaOf === "key-expansion");
    expect(replicas.length).toBe(11);
    // Each replica inherits the source's stepType + label.
    for (const rep of replicas) {
      expect(rep.stepType).toBe("aes.key-expansion@1");
      expect(rep.label).toBe("key-expansion");
    }
    // Every aux edge that used to come FROM `key-expansion` now comes
    // from a replica — original source has no outgoing aux edges left.
    const remainingFromSource = r.edges.filter(
      (e) => e.kind === "aux" && e.from === "key-expansion",
    );
    expect(remainingFromSource.length).toBe(0);
    // Original key-expansion node stays in the graph (linear-list click
    // still works through it).
    expect(r.nodes.find((n) => n.stepId === "key-expansion")).toBeDefined();
  });

  it('mode "always" replicates a low-fanout source that auto would skip', () => {
    const g = aes128Graph();
    // round.0.add-round-key is an aux CONSUMER of key-expansion, not a
    // source. Pick an actual low-fanout source — the iterate doesn't
    // exist in single-block AES, and most leaves don't emit aux. Use
    // `key-expansion` with a HIGH threshold so auto would skip, then
    // force replication via "always".
    const r = replicateHighFanoutSources(g, 50, { "key-expansion": "always" });
    // High threshold alone would have left the graph alone; "always"
    // forces replication anyway.
    expect(r).not.toBe(g);
    const replicas = r.nodes.filter((n) => n.replicaOf === "key-expansion");
    expect(replicas.length).toBe(11);
  });

  it('mode "never" suppresses replication of a high-fanout source that auto would replicate', () => {
    const g = aes128Graph();
    // Threshold 6 would auto-replicate key-expansion (fanout 11), but the
    // "never" override pins it back.
    const r = replicateHighFanoutSources(g, 6, { "key-expansion": "never" });
    expect(r).toBe(g);
    const replicas = r.nodes.filter((n) => n.replicaOf === "key-expansion");
    expect(replicas.length).toBe(0);
  });

  it("threshold <= 0 with no 'always' overrides short-circuits (modes empty)", () => {
    const g = aes128Graph();
    expect(replicateHighFanoutSources(g, 0, {})).toBe(g);
    expect(replicateHighFanoutSources(g, -1, undefined)).toBe(g);
  });

  it("threshold <= 0 with an 'always' override still replicates that source", () => {
    const g = aes128Graph();
    const r = replicateHighFanoutSources(g, 0, { "key-expansion": "always" });
    expect(r).not.toBe(g);
    expect(r.nodes.filter((n) => n.replicaOf === "key-expansion").length).toBe(11);
  });

  it("each replica sits in its consumer's parent container, before the consumer", () => {
    const g = aes128Graph();
    const r = replicateHighFanoutSources(g, 6);
    // Pick one replica's consumer (the `:b{i}` suffix is stripped during
    // graph derivation, so consumer ids look like `round.5.add-round-key`).
    const sample = r.nodes.find((n) => n.replicaOf === "key-expansion");
    if (!sample) throw new Error("no replica produced");
    // The replica id encodes the consumer: `${source}@->${consumer}`.
    const consumerId = sample.stepId.split("@->")[1];
    expect(consumerId).toBeDefined();
    const consumer = r.nodes.find((n) => n.stepId === consumerId);
    expect(consumer).toBeDefined();
    // Same containerPath as the consumer (siblings).
    expect(sample.containerPath).toEqual(consumer?.containerPath);
    // Inside the consumer's parent container, the replica precedes the
    // consumer in the childIds order. (Use the last entry of the
    // consumer's containerPath as the parent; that's the direct parent
    // by construction.)
    const parentId = consumer?.containerPath[consumer.containerPath.length - 1];
    if (parentId) {
      const parent = r.containers.find((c) => c.id === parentId);
      expect(parent).toBeDefined();
      const ix = (parent?.childIds ?? []).indexOf(sample.stepId);
      const cIx = (parent?.childIds ?? []).indexOf(consumerId ?? "");
      expect(ix).toBeGreaterThanOrEqual(0);
      expect(cIx).toBeGreaterThanOrEqual(0);
      expect(ix).toBeLessThan(cIx);
    } else {
      // Root-level consumer (e.g. `initial.add-round-key`): replica
      // should be present in rootIds, immediately before the consumer.
      const rix = r.rootIds.indexOf(sample.stepId);
      const cix = r.rootIds.indexOf(consumerId ?? "");
      expect(rix).toBeGreaterThanOrEqual(0);
      expect(cix).toBeGreaterThanOrEqual(0);
      expect(rix).toBeLessThan(cix);
    }
  });
});
