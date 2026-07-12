/**
 * Tests for `src/core/graph.ts::bundleEdges` — same-(from, to, kind,
 * isFeedback) collapse for visual decongestion at render time.
 *
 * The motivating regression: AES-128 with the user-toggled "always
 * replicate" + collapsed iterate produces 11 parallel aux arrows from
 * the `key-schedule.publish@->...` replica chip into the iterate's top edge.
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
import { buildSha256Spec } from "@/ciphers/sha-256";
import {
  type GraphEdge,
  PORT_FLOW_AUX_KEY,
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
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });

// Serpent-128 fixture for the state-edge bundling tests. These two tests pin
// bundler PROPERTIES (each spine edge → one singleton bundle; no ×N merge of
// the spine). Since Slice 5.3b Serpent is port-wired, so the two tests pass
// the registry to `deriveAuxGraph` — the S2(f) gate then suppresses the legacy
// consecutive-siblings state-thread, leaving a clean 1:1 port-flow spine (every
// edge `kind:"state"` with `auxKey:"port-flow"`, no duplicate companion edge).
// (Without the registry, a port-wired spec yields BOTH a port-flow edge and a
// legacy state-thread edge per within-group hop, which bundling would collapse
// — the registry is what keeps the spine duplicate-free.)
const SERPENT128_PT = "00112233445566778899aabbccddeeff";
const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const runSerpent128 = (): Trace =>
  runSpec(serpent128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SERPENT128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
    // Serpent's round body is port-native since B3 → ported dispatch required.
  });

const runAes128Ecb = (): Trace =>
  runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    // ECB takes the whole multi-block plaintext as a single BytesState;
    // `split-blocks` slices it inside the spec.
    initialState: makeBytesState(bytesFromHex(ECB_PLAINTEXT_4_BLOCKS)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
    // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
  });

describe("bundleEdges — collapse same-(from, to, kind, isFeedback)", () => {
  it("collapses only the schedule's legitimate multi-tap fan-in; body+aux edges stay 1:1", () => {
    // Serpent-128 single-block, NO replication. With the registry passed, the
    // S2(f) gate leaves a clean 1:1 port-flow body spine and every aux edge
    // from key-schedule.publish goes to a UNIQUE consumer.
    //
    // K3a (2026-06-02): the decomposed key schedule introduces a HANDFUL of
    // legitimate parallel (from→to) edges — the early prekey recurrence's XOR
    // reads MULTIPLE taps from `master-split` (e.g. j0.xor pulls taps idx-8,
    // idx-5, idx-3, idx-1 = 4 parallel edges from master-split until the lag
    // window fills).
    //
    // 2026-07-12: those taps are PORT-FLOW edges into DISTINCT operands of the
    // XOR (different `toPort`s), so the bundler now keys them apart — each tap is
    // its own singleton arrow, independently click-resolvable to its own byte
    // stream (a `×4` state bundle would have four identical `"port-flow"` auxKeys
    // and resolve to "no frame found"). So `bundles.length == edges.length` for
    // the port-flow spine; the only surplus left is genuine AUX fan-in (same
    // (from,to) same auxKey), of which Serpent-128 single-block has none. Compute
    // the surplus with the SAME key `bundleEdges` uses (toPort joins the key for
    // port-flow edges) and assert the bundler removed precisely it — still pinning
    // "no SPURIOUS collapse."
    const trace = runSerpent128();
    const raw = deriveAuxGraph(trace, serpent128Spec, { registry: buildDefaultRegistry() });
    const fb = buildIterateFeedbackPredicate(raw);

    const bundled = bundleEdges(raw, fb);

    // Grouping key mirrors `bundleEdges`' `bundleKey`: `(from,to,kind,isFeedback)`
    // plus `toPort` for port-flow spine edges. `isFeedback` is computed per-edge
    // by the same predicate the bundler uses (it's NOT a field on GraphEdge).
    const groupSizes = new Map<string, number>();
    for (const e of raw.edges) {
      const portSuffix =
        e.kind === "state" && e.auxKey === PORT_FLOW_AUX_KEY && e.toPort !== undefined
          ? `|${e.toPort}`
          : "";
      const k = `${e.from}|${e.to}|${e.kind}|${fb(e) ? 1 : 0}${portSuffix}`;
      groupSizes.set(k, (groupSizes.get(k) ?? 0) + 1);
    }
    const surplus = [...groupSizes.values()].reduce((acc, n) => acc + (n - 1), 0);
    expect(bundled.bundles.length).toBe(raw.edges.length - surplus);
    expect(bundled.bundles.length).toBe(groupSizes.size);
    // Any remaining collapsed bundle (>1 edge) can only be a same-auxKey AUX
    // fan-in — never a port-flow group (those are keyed apart by toPort now).
    for (const b of bundled.bundles) {
      if (b.auxKeys.length > 1) {
        expect(b.kind).toBe("aux");
      }
    }
  });

  it("collapses N parallel aux edges (post-replication) into one bundle of length N", () => {
    // The motivating case from the manual smoke on 2026-05-17: AES-128 ECB
    // with the iterate COLLAPSED + key-schedule.publish source set to "always"
    // replicate. Collapsing folds the 11 per-round AddRoundKey consumers
    // into the iterate-as-a-whole, so all 11 round-key aux edges land at
    // the iterate id. After replication, the chip
    // `key-schedule.publish@->ecb-blocks` carries all 11 outgoing aux edges. The
    // bundler must collapse them into one EdgeBundle.
    const trace = runAes128Ecb();
    const raw = deriveAuxGraph(trace, aes128EcbSpec);
    // Collapse the iterate — this is the user-flagged state.
    const collapsed = collapseGraph(raw, new Set(["ecb-blocks"]));
    // Force `key-schedule.publish` to replicate via "always". With the iterate
    // collapsed, all 11 round-key consumers fold onto the single `ecb-blocks`
    // id, so the source's DISTINCT-consumer fanout is 1 — below any threshold
    // (the 2026-06-02 metric counts distinct consumers, not raw edges, so a
    // single-consumer fan-out defers to the ×11 bundle on the auto path). The
    // explicit "always" override is the sanctioned way to still force the
    // single replica chip here — exactly the case this test pins.
    const replicated = replicateHighFanoutSources(collapsed, 1, {
      "key-schedule.publish": "always",
    });
    const fb = buildIterateFeedbackPredicate(replicated);

    const bundled = bundleEdges(replicated, fb);

    // Find the bundle from the key-schedule.publish replica into the iterate.
    // Replica id format: `${sourceId}@->${consumerId}`.
    const keyExpReplicaBundle = bundled.bundles.find(
      (b) => b.from === "key-schedule.publish@->ecb-blocks" && b.to === "ecb-blocks",
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
    // "always" override — single distinct consumer (ecb-blocks) after collapse;
    // see the sibling test above for why the auto path defers to the bundle.
    const replicated = replicateHighFanoutSources(collapsed, 1, {
      "key-schedule.publish": "always",
    });
    const fb = buildIterateFeedbackPredicate(replicated);

    const bundled = bundleEdges(replicated, fb);

    const keyExpReplicaBundle = bundled.bundles.find(
      (b) => b.from === "key-schedule.publish@->ecb-blocks" && b.to === "ecb-blocks",
    );
    if (!keyExpReplicaBundle) throw new Error("expected the replica bundle");
    // Compare against the same-key sequence taken directly from the
    // pre-bundle edges array — that's the canonical encounter order.
    const expected = replicated.edges
      .filter((e) => e.from === keyExpReplicaBundle.from && e.to === keyExpReplicaBundle.to)
      .map((e) => e.auxKey);
    expect(keyExpReplicaBundle.auxKeys).toEqual(expected);
  });

  it("passes the body-spine state edges through 1:1 as singleton bundles", () => {
    // Serpent (port-wired since 5.3b) with the registry passed → the S2(f)
    // gate leaves a clean port-flow spine: every `kind:"state"` edge carries
    // `auxKey:"port-flow"` with no legacy state-thread companion.
    //
    // K3a (2026-06-02): the decomposed key schedule's early prekey-recurrence
    // XORs pull multiple taps from `master-split` (legitimate parallel
    // port-flow edges, collapsed by the bundler into a few multi-edge bundles).
    // Those live entirely inside the `key-schedule` group. The BODY spine (IP,
    // 32 rounds, FP) is still strictly 1:1 — assert the singleton property on
    // the non-schedule state bundles.
    const trace = runSerpent128();
    const raw = deriveAuxGraph(trace, serpent128Spec, { registry: buildDefaultRegistry() });
    const fb = buildIterateFeedbackPredicate(raw);

    const bundled = bundleEdges(raw, fb);

    const isScheduleId = (id: string): boolean => id.startsWith("key-schedule.");
    const bodyStateBundles = bundled.bundles.filter(
      (b) => b.kind === "state" && !isScheduleId(b.from) && !isScheduleId(b.to),
    );
    expect(bodyStateBundles.length).toBeGreaterThan(0);
    // Every BODY state bundle is a singleton because the body port-flow spine
    // is 1:1.
    for (const b of bodyStateBundles) {
      expect(b.auxKeys.length).toBe(1);
      expect(b.auxKeys[0]).toBe("port-flow");
    }
    // The number of body state bundles equals the number of raw body state edges.
    const rawBodyStateCount = raw.edges.filter(
      (e) => e.kind === "state" && !isScheduleId(e.from) && !isScheduleId(e.to),
    ).length;
    expect(bodyStateBundles.length).toBe(rawBodyStateCount);
  });

  it("Slice 7b — replica-sourced port-flow state edges remain singleton bundles (no ×N decoration)", () => {
    // A fully-replicated port-native source fans its port-flow state-out
    // through one replica per consumer. Each replica has a unique synthetic
    // `from` (`${src}@->${consumer}`), so a `(replica, consumer)` state edge
    // can't collide with anyone else's bundle key — it must come out as a
    // singleton bundle that the renderer paints without the `×N` decoration.
    // Pin this invariant so a future bundling tweak can't accidentally merge
    // them.
    //
    // Retargeted in Slice 5.3e Batch 3 from AES `key-schedule.publish` (whose legacy
    // identity-passthrough state-out retired with `inferStateEdges`) to
    // SHA-256's `final.split-wv`, whose 8 port-flow edges to `final.s0..s7`
    // auto-replicate at threshold 6.
    const emptyTrace: Trace = {
      frames: [],
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalAux: new Map(),
    };
    const raw = deriveAuxGraph(emptyTrace, buildSha256Spec(), { registry: buildDefaultRegistry() });
    const replicated = replicateHighFanoutSources(raw, 6);
    const fb = buildIterateFeedbackPredicate(replicated);

    const bundled = bundleEdges(replicated, fb);

    // Every state bundle whose `from` is a split-wv replica is a singleton —
    // replica ids guarantee per-(from, to) uniqueness. These carry the
    // port-flow auxKey (the spine is entirely port-derived post-5.3e).
    const replicaStateBundles = bundled.bundles.filter(
      (b) => b.kind === "state" && b.from.startsWith("final.split-wv@->"),
    );
    expect(replicaStateBundles.length).toBeGreaterThan(0);
    for (const b of replicaStateBundles) {
      expect(b.auxKeys.length).toBe(1);
      expect(b.auxKeys[0]).toBe("port-flow");
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
    // "always" override — single distinct consumer (ecb-blocks) after collapse;
    // forces the multi-aux replica pair this test splits on the feedback flag.
    const replicated = replicateHighFanoutSources(collapsed, 1, {
      "key-schedule.publish": "always",
    });
    // Find the key-schedule.publish replica bundle's (from, to) so we have
    // a pair with >2 same-pair aux edges to split.
    const replicaSrc = replicated.edges.find((e) => e.from.startsWith("key-schedule.publish@->"));
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
