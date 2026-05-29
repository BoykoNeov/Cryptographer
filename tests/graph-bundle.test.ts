/**
 * Tests for `src/core/graph.ts::bundleEdges` — same-(from, to, kind,
 * isFeedback) collapse for visual decongestion at render time.
 *
 * The motivating regression: AES-128 with the user-toggled "always
 * replicate" + collapsed iterate produces 11 parallel aux arrows from
 * the `key-expansion@->...` replica chip into the iterate's top edge.
 * The visual is correct (11 distinct round keys) but unreadable. The
 * bundler collapses them into one EdgeBundle that the renderer paints
 * as a thicker arrow with a `×11` label.
 *
 * What these tests pin (in addition to the AES headline case):
 *   - Singleton bundles still appear so renderers can walk one list.
 *   - State edges pass through 1:1 (typically one state edge per pair).
 *   - `isFeedback` differences split the bundle even when (from, to,
 *     kind) match — the dashed style applies bundle-wide.
 *   - `auxKeys` order preserves source-edge encounter order so the
 *     inspector lists `roundKey.0`, `roundKey.1`, ... in user-readable
 *     order.
 *   - `edges`, `nodes`, `containers`, `rootIds` are unchanged identity-
 *     wise — bundling is an ADDITIVE transform on top of the source
 *     graph; downstream consumers that index by raw edge identity
 *     don't see any change.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import {
  type GraphEdge,
  buildIterateFeedbackPredicate,
  bundleEdges,
  collapseGraph,
  deriveAuxGraph,
  replicateHighFanoutSources,
} from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const ECB_PLAINTEXT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

const runAes128 = (): Trace =>
  runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    portedDispatchEnabled: true,
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });

// Serpent-128 fixture for the state-edge bundling tests. Byte-native AES-128
// (Slice B1) is no longer a clean single-edge-per-connection graph: each
// internal connection now yields BOTH a port-flow state edge (auxKey
// "port-flow", from `inferPortEdges`) AND a spine state edge (auxKey "state"),
// so (from,to,kind) groups duplicate and bundling collapses them. Serpent is
// still legacy/matrix — its spine is a clean 1:1 `auxKey:"state"` thread with
// no port-flow companion — so it preserves the "no duplicates" / "state edges
// pass 1:1" properties these two tests pin. Retarget to byte-native or delete
// when Serpent converts in B3.
const SERPENT128_PT = "00112233445566778899aabbccddeeff";
const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const runSerpent128 = (): Trace =>
  runSpec(serpent128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SERPENT128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
  });

const runAes128Ecb = (): Trace =>
  runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    // ECB takes the whole multi-block plaintext as a single BytesState;
    // `split-blocks` slices it inside the spec.
    initialState: makeBytesState(bytesFromHex(ECB_PLAINTEXT_4_BLOCKS)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
    // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
    portedDispatchEnabled: true,
  });

describe("bundleEdges — collapse same-(from, to, kind, isFeedback)", () => {
  it("returns a singleton bundle for each unique edge when no duplicates exist", () => {
    // Serpent-128 single-block, NO replication (see `runSerpent128` note on why
    // byte-native AES no longer has a duplicate-free edge set). Every aux edge
    // from key-expansion goes to a UNIQUE consumer and the spine is a clean 1:1
    // `auxKey:"state"` thread, so bundling produces one bundle per edge.
    const trace = runSerpent128();
    const raw = deriveAuxGraph(trace, serpent128Spec);
    const fb = buildIterateFeedbackPredicate(raw);

    const bundled = bundleEdges(raw, fb);

    expect(bundled.bundles.length).toBe(raw.edges.length);
    for (const b of bundled.bundles) {
      expect(b.auxKeys.length).toBe(1);
    }
  });

  it("collapses N parallel aux edges (post-replication) into one bundle of length N", () => {
    // The motivating case from the manual smoke on 2026-05-17: AES-128 ECB
    // with the iterate COLLAPSED + key-expansion source set to "always"
    // replicate. Collapsing folds the 11 per-round AddRoundKey consumers
    // into the iterate-as-a-whole, so all 11 round-key aux edges land at
    // the iterate id. After replication, the chip
    // `key-expansion@->ecb-blocks` carries all 11 outgoing aux edges. The
    // bundler must collapse them into one EdgeBundle.
    const trace = runAes128Ecb();
    const raw = deriveAuxGraph(trace, aes128EcbSpec);
    // Collapse the iterate — this is the user-flagged state.
    const collapsed = collapseGraph(raw, new Set(["ecb-blocks"]));
    // Replicate at threshold 1 so even small fanouts replicate. With the
    // iterate collapsed, key-expansion's outgoing fanout into ecb-blocks
    // is 11 (one per round-key consumer, all folded to the iterate id).
    const replicated = replicateHighFanoutSources(collapsed, 1);
    const fb = buildIterateFeedbackPredicate(replicated);

    const bundled = bundleEdges(replicated, fb);

    // Find the bundle from the key-expansion replica into the iterate.
    // Replica id format: `${sourceId}@->${consumerId}`.
    const keyExpReplicaBundle = bundled.bundles.find(
      (b) => b.from === "key-expansion@->ecb-blocks" && b.to === "ecb-blocks",
    );
    expect(keyExpReplicaBundle).toBeDefined();
    if (!keyExpReplicaBundle) throw new Error("unreachable");
    // 11 round keys for AES-128: roundKey.0 … roundKey.10.
    expect(keyExpReplicaBundle.auxKeys.length).toBe(11);
  });

  it("preserves source-edge encounter order inside a bundle's auxKeys", () => {
    // The inspector renders the auxKeys list in this order; users
    // expect roundKey.0, roundKey.1, ... not a hash-bucket scramble.
    const trace = runAes128Ecb();
    const raw = deriveAuxGraph(trace, aes128EcbSpec);
    const collapsed = collapseGraph(raw, new Set(["ecb-blocks"]));
    const replicated = replicateHighFanoutSources(collapsed, 1);
    const fb = buildIterateFeedbackPredicate(replicated);

    const bundled = bundleEdges(replicated, fb);

    const keyExpReplicaBundle = bundled.bundles.find(
      (b) => b.from === "key-expansion@->ecb-blocks" && b.to === "ecb-blocks",
    );
    if (!keyExpReplicaBundle) throw new Error("expected the replica bundle");
    // Compare against the same-key sequence taken directly from the
    // pre-bundle edges array — that's the canonical encounter order.
    const expected = replicated.edges
      .filter((e) => e.from === keyExpReplicaBundle.from && e.to === keyExpReplicaBundle.to)
      .map((e) => e.auxKey);
    expect(keyExpReplicaBundle.auxKeys).toEqual(expected);
  });

  it("passes state edges through 1:1 as singleton bundles", () => {
    // Serpent (legacy/matrix) — clean `auxKey:"state"` spine with no port-flow
    // companion edges, so state bundles stay singleton. Byte-native AES pairs a
    // port-flow + state edge per connection (see `runSerpent128`).
    const trace = runSerpent128();
    const raw = deriveAuxGraph(trace, serpent128Spec);
    const fb = buildIterateFeedbackPredicate(raw);

    const bundled = bundleEdges(raw, fb);

    const stateBundles = bundled.bundles.filter((b) => b.kind === "state");
    expect(stateBundles.length).toBeGreaterThan(0);
    // Every state bundle is a singleton because the spine is 1:1.
    for (const b of stateBundles) {
      expect(b.auxKeys.length).toBe(1);
      expect(b.auxKeys[0]).toBe("state");
    }
    // The number of state bundles equals the number of raw state edges.
    const rawStateCount = raw.edges.filter((e) => e.kind === "state").length;
    expect(stateBundles.length).toBe(rawStateCount);
  });

  it("Slice 7b — replica-sourced state edges remain singleton bundles (no ×N decoration)", () => {
    // Post-Slice-7b a fully-replicated source's state-out edge fans
    // through the replica too. Each replica has a unique synthetic
    // `from` (`${src}@->${consumer}`), so a `(replica, consumer)` state
    // edge can't collide with anyone else's bundle key — it must come
    // out as a singleton bundle that the renderer paints without the
    // `×N` decoration. Pin this invariant so a future bundling tweak
    // can't accidentally merge them.
    const trace = runAes128();
    const raw = deriveAuxGraph(trace, aes128Spec);
    const replicated = replicateHighFanoutSources(raw, 0, { "key-expansion": "always" });
    const fb = buildIterateFeedbackPredicate(replicated);

    const bundled = bundleEdges(replicated, fb);

    // Every state bundle whose `from` is a key-expansion replica is a
    // singleton — replica ids guarantee per-(from, to) uniqueness.
    const replicaStateBundles = bundled.bundles.filter(
      (b) => b.kind === "state" && b.from.startsWith("key-expansion@->"),
    );
    expect(replicaStateBundles.length).toBeGreaterThan(0);
    for (const b of replicaStateBundles) {
      expect(b.auxKeys.length).toBe(1);
      expect(b.auxKeys[0]).toBe("state");
    }
  });

  it("preserves the source graph's nodes / containers / edges / rootIds by identity", () => {
    // BundledGraph is additive — it ADDS the `bundles` field. Downstream
    // consumers that index by raw edge identity must continue to work
    // unchanged. (validateGraph indexes by GraphEdge object identity in
    // some passes; we don't want bundling to invalidate its cache.)
    const trace = runAes128();
    const raw = deriveAuxGraph(trace, aes128Spec);
    const fb = buildIterateFeedbackPredicate(raw);

    const bundled = bundleEdges(raw, fb);

    expect(bundled.nodes).toBe(raw.nodes);
    expect(bundled.containers).toBe(raw.containers);
    expect(bundled.edges).toBe(raw.edges);
    expect(bundled.rootIds).toBe(raw.rootIds);
  });

  it("splits same-(from, to, kind) into two bundles when the isFeedback flag differs", () => {
    // No shipped cipher today produces same-(from, to, kind) edges with
    // mixed feedback flags — but the invariant is structural, not
    // empirical. Drive it with a synthetic predicate that lies about
    // feedback for half the edges between a chosen pair.
    const trace = runAes128Ecb();
    const raw = deriveAuxGraph(trace, aes128EcbSpec);
    const collapsed = collapseGraph(raw, new Set(["ecb-blocks"]));
    const replicated = replicateHighFanoutSources(collapsed, 1);
    // Find the key-expansion replica bundle's (from, to) so we have
    // a pair with >2 same-pair aux edges to split.
    const replicaSrc = replicated.edges.find((e) => e.from.startsWith("key-expansion@->"));
    if (!replicaSrc) throw new Error("expected a replica edge");
    const pair = { from: replicaSrc.from, to: replicaSrc.to };

    // Stub predicate: returns true for the first half of same-pair edges
    // by auxKey-string comparison, false for the rest. The split is
    // deterministic and gives BOTH classes nonzero population.
    const samePairAuxKeys = replicated.edges
      .filter((e) => e.from === pair.from && e.to === pair.to)
      .map((e) => e.auxKey)
      .sort();
    const half = Math.floor(samePairAuxKeys.length / 2);
    const truthySet = new Set(samePairAuxKeys.slice(0, half));
    const stubPredicate = (e: GraphEdge): boolean =>
      e.from === pair.from && e.to === pair.to && truthySet.has(e.auxKey);

    const bundled = bundleEdges(replicated, stubPredicate);

    const splitBundles = bundled.bundles.filter((b) => b.from === pair.from && b.to === pair.to);
    // Exactly two bundles for this pair — one feedback=true, one false.
    expect(splitBundles.length).toBe(2);
    const fbCount = splitBundles.filter((b) => b.isFeedback).length;
    expect(fbCount).toBe(1);
    // Totals across the split equal the raw same-pair edge count.
    const totalAux = splitBundles.reduce((acc, b) => acc + b.auxKeys.length, 0);
    expect(totalAux).toBe(samePairAuxKeys.length);
  });

  it("returns an empty bundles array for an empty graph", () => {
    const empty = {
      nodes: [],
      containers: [],
      edges: [],
      rootIds: [],
    } as const;
    const bundled = bundleEdges(empty, () => false);
    expect(bundled.bundles).toEqual([]);
  });
});
