/**
 * Universal arrival-dot coverage — "every arrow that lands on a leaf ends on a
 * colored dot" (user directive, 2026-07-12).
 *
 * The graph draws a colored terminus dot wherever an arrow is CONSUMED. Three
 * mechanisms produce those dots, all keyed off `GraphView`'s `portArrivalPoints`
 * resolution:
 *   1. a port-flow spine edge lands on the consumer's declared input port
 *      (resolved via `edge.toPort`), or
 *   2. an aux edge lands on the input port a leaf's `meta.auxReadPorts` maps its
 *      key to (resolved via a reverse `auxKey → port` map), or
 *   3. the edge lands on a COLLAPSED container (its own `containerArrivalDots`).
 *
 * A rendered arrow that resolves to NONE of these lands on a bare box edge with
 * no "consumed here" marker — the class of defect the user reported (RSA
 * `result-seed`, DES swap, SHA per-block, and the `load-n`/`load-exp` aux-fed
 * REPLICAS). This test walks the fully-processed graph (collapse + the same
 * round-member "never" replication modes GraphView applies) for every shipped
 * cipher and asserts ZERO leaf/replica-targeted bundles fall through resolution.
 *
 * Why this and not a render count: it pins the honest guarantee ("every landing
 * resolves") AND surfaces the NEXT resolution bug with the exact edge that broke
 * — where a blind catch-all dot would silently paper over it. The 2026-07-12
 * root cause was precisely a resolution gap: the aux reverse map used
 * `findStep(spec, id)`, which returns null for a REPLICA id (not in the spec),
 * so aux-fed replicated loaders (`load-n@->square-0`) never resolved. Resolving
 * `node.replicaOf ?? id` fixed it; this test guards the regression.
 *
 * The resolution predicate below MIRRORS `portArrivalPoints` in
 * `src/ui/components/GraphView.tsx`; `visualEdgeTargetId` + the round-member
 * "never" modes are inlined (the originals live in the `.tsx`, which pulls Solid
 * into a node test). Keep them in sync if that resolution logic changes.
 */
import { aes128Spec } from "@/ciphers/aes-128";
import { aes256Spec } from "@/ciphers/aes-256";
import { blowfishSpec } from "@/ciphers/blowfish";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { buildRsaSpec } from "@/ciphers/rsa";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { twofishSpec } from "@/ciphers/twofish";
import { bigIntToBytes } from "@/core/big-int-codec";
import { analyzeFeistelRound } from "@/core/feistel-shape";
import {
  type ContainerNode,
  type GraphEdge,
  type GraphNode,
  PORT_FLOW_AUX_KEY,
  buildIterateFeedbackPredicate,
  bundleEdges,
  collapseGraph,
  deriveAuxGraph,
  replicateHighFanoutSources,
} from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { getDefaultCollapsedContainers } from "@/core/spec-defaults";
import { findStep } from "@/core/spec-mutations";
import { bytesFromHex } from "@/core/state/bytes";
import { analyzeTwofishRound } from "@/core/twofish-shape";
import type { AuxValue, CipherSpec, StepNode, Trace } from "@/core/types";
import { DEFAULT_KEY_BYTES_BY_CIPHER, DEFAULT_PT_BYTES_BY_CIPHER } from "@/ui/stores/cipher";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

/**
 * Inlined copy of `GraphView`'s `visualEdgeTargetId` — a source→replica edge
 * whose target is an iterate retargets to the iterate's first real body step.
 * Kept behaviourally identical to the exported original.
 */
const visualEdgeTargetId = (
  edge: GraphEdge,
  nodesById: ReadonlyMap<string, GraphNode>,
  containersById: ReadonlyMap<string, ContainerNode>,
): string => {
  const fromNode = nodesById.get(edge.from);
  if (fromNode?.replicaOf === undefined) return edge.to;
  const toContainer = containersById.get(edge.to);
  if (toContainer?.kind !== "iterate") return edge.to;
  const firstNonReplicaChildId = toContainer.childIds.find(
    (cid) => nodesById.get(cid)?.replicaOf === undefined,
  );
  if (firstNonReplicaChildId !== undefined) {
    const firstChildNode = nodesById.get(firstNonReplicaChildId);
    if (firstChildNode?.blockChipOf !== undefined) return edge.to;
  }
  return firstNonReplicaChildId ?? edge.to;
};

/**
 * Round-member "never" replication modes — mirrors `twofishRoundNeverModes` +
 * `feistelRoundNeverModes` in GraphView so the fanning g-splits (Twofish) /
 * splitF (Feistel) stay single nodes instead of scattering into per-consumer
 * chips. Without this the enumeration OVER-replicates and reports phantom
 * fall-throughs that never occur in the real view.
 */
const roundMemberNeverModes = (spec: CipherSpec): Record<string, "never"> => {
  const modes: Record<string, "never"> = {};
  const walk = (nodes: readonly StepNode[]): void => {
    for (const node of nodes) {
      if (node.kind === "step") continue;
      if (node.kind === "group") {
        const tw = analyzeTwofishRound(node);
        if (tw !== null) {
          for (const id of [
            tw.splitId,
            tw.recombineId,
            tw.rolNodeId,
            ...tw.g0Ids,
            ...tw.g1Ids,
            ...tw.phtIds,
            ...tw.r2MixIds,
            ...tw.r3MixIds,
          ]) {
            modes[id] = "never";
          }
        }
        const fe = analyzeFeistelRound(node);
        if (fe !== null) {
          for (const id of [
            fe.splitId,
            fe.fxorId,
            fe.recombineId,
            ...fe.fStackIds,
            ...fe.railNodeIds,
          ]) {
            modes[id] = "never";
          }
        }
      }
      walk(node.children);
    }
  };
  walk(spec.steps);
  return modes;
};

/** All leaf-targeted bundles that do NOT resolve to an arrival dot. */
const unresolvedLandings = (spec: CipherSpec, trace: Trace): string[] => {
  const collapsed = getDefaultCollapsedContainers(spec);
  const raw = deriveAuxGraph(trace, spec, { registry });
  const collapsedG = collapseGraph(raw, collapsed);
  const graph = replicateHighFanoutSources(collapsedG, 3, roundMemberNeverModes(spec));
  const fb = buildIterateFeedbackPredicate(graph);
  const bundled = bundleEdges(graph, fb);

  const nById = new Map(graph.nodes.map((n) => [n.stepId, n] as const));
  const cById = new Map(graph.containers.map((c) => [c.id, c] as const));

  // Reverse aux map WITH the replica-param fix (resolve `replicaOf` first).
  const auxPortByLeaf = new Map<string, Map<string, string>>();
  for (const [id, node] of nById) {
    const readPorts = registry.getRegistration(node.stepType)?.meta?.auxReadPorts;
    if (readPorts === undefined) continue;
    const leaf = findStep(spec, node.replicaOf ?? id);
    if (leaf === null) continue;
    const rev = new Map<string, string>();
    for (const [port, auxKey] of readPorts(leaf.params)) rev.set(auxKey, port);
    auxPortByLeaf.set(id, rev);
  }

  const resolves = (edge: GraphEdge, targetId: string): boolean => {
    if (edge.kind === "state" && edge.auxKey === PORT_FLOW_AUX_KEY && edge.toPort !== undefined) {
      return true;
    }
    return auxPortByLeaf.get(targetId)?.get(edge.auxKey) !== undefined;
  };

  const unresolved: string[] = [];
  for (const b of bundled.bundles) {
    const edge = b.representativeEdge;
    const targetId = visualEdgeTargetId(edge, nById, cById);
    // Container-targeted bundles are out of scope: a COLLAPSED container gets
    // its dot from `containerArrivalDots`; an EXPANDED one is a group-SEED edge
    // (e.g. DES `initial-permutation → rounds`, `toPort` undefined — the group's
    // `in` pseudo-port) whose real landing is the first leaf INSIDE, dotted via
    // the seed→leaf edge that this same test DOES assert (`rounds →
    // round.1.split`, `toPort=input`). Dotting the expanded wrapper too is the
    // deliberate "don't pepper an expanded container" decision (case D). So the
    // guarantee here is precisely "every LEAF/replica-targeted arrow resolves."
    if (cById.has(targetId)) continue;
    if (!resolves(edge, targetId)) {
      const t = nById.get(targetId);
      unresolved.push(
        `${edge.from} → ${targetId} [kind=${edge.kind} aux=${edge.auxKey} type=${t?.stepType ?? "?"}]`,
      );
    }
  }
  return unresolved;
};

const blockTrace = (spec: CipherSpec, cipher: keyof typeof DEFAULT_PT_BYTES_BY_CIPHER): Trace =>
  runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: DEFAULT_PT_BYTES_BY_CIPHER[cipher] },
    initialAux: new Map<string, AuxValue>([["key", DEFAULT_KEY_BYTES_BY_CIPHER[cipher]]]),
  });

const fixtures: { name: string; spec: CipherSpec; trace: Trace }[] = [
  { name: "aes-128", spec: aes128Spec, trace: blockTrace(aes128Spec, "aes-128") },
  { name: "aes-256", spec: aes256Spec, trace: blockTrace(aes256Spec, "aes-256") },
  { name: "serpent-128", spec: serpent128Spec, trace: blockTrace(serpent128Spec, "serpent-128") },
  {
    name: "speck-be",
    spec: speck32_64BeSpec,
    trace: blockTrace(speck32_64BeSpec, "speck-32-64-be"),
  },
  { name: "des", spec: desSpec, trace: blockTrace(desSpec, "des") },
  { name: "blowfish", spec: blowfishSpec, trace: blockTrace(blowfishSpec, "blowfish") },
  { name: "twofish", spec: twofishSpec, trace: blockTrace(twofishSpec, "twofish") },
  {
    name: "sha-256",
    spec: buildSha256Spec(),
    trace: runSpec(buildSha256Spec(), registry, {
      initialState: { shape: "bytes", bytes: bytesFromHex("616263") },
    }),
  },
  {
    name: "rsa",
    spec: buildRsaSpec("encrypt", 2),
    trace: runSpec(buildRsaSpec("encrypt", 2), registry, {
      initialState: { shape: "bytes", bytes: bigIntToBytes(65n, 2) },
    }),
  },
];

describe("graph arrival-dot coverage — every leaf-targeted arrow resolves to a dot", () => {
  for (const { name, spec, trace } of fixtures) {
    it(`${name}: no rendered arrow lands on a leaf without an arrival dot`, () => {
      expect(unresolvedLandings(spec, trace)).toEqual([]);
    });
  }

  it("regression: RSA aux-fed replicated loaders (load-n/load-exp) resolve", () => {
    // Direct guard on the 2026-07-12 replica-param fix: with replication ON, the
    // high-fanout `load-n`/`load-exp` sources fully replicate; their single
    // incoming aux edge (rsa.n / rsa.e) redirects to the spine-entry replica,
    // which must resolve to the `input` port via `replicaOf`-resolved params.
    const spec = buildRsaSpec("encrypt", 2);
    const trace = runSpec(spec, registry, {
      initialState: { shape: "bytes", bytes: bigIntToBytes(65n, 2) },
    });
    const raw = deriveAuxGraph(trace, spec, { registry });
    const graph = replicateHighFanoutSources(raw, 3, {});
    // Confirm the fixture actually replicates the loaders (else the test is vacuous).
    const loaderReplicas = graph.nodes.filter(
      (n) => n.replicaOf === "load-n" || n.replicaOf === "load-exp",
    );
    expect(loaderReplicas.length).toBeGreaterThan(1);
    expect(unresolvedLandings(spec, trace)).toEqual([]);
  });
});
