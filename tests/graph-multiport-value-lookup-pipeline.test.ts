/**
 * Regression + universal guard: the value inspector must resolve EVERY
 * port-flow spine edge between two real leaves, after the FULL graph pipeline
 * the UI actually runs — `deriveAuxGraph → collapseGraph → replicateHighFanoutSources`.
 *
 * ## The bug this pins (reported 2026-07-12, Twofish + Blowfish)
 *
 * `inferPortEdges` stamps each spine edge with the exact port pairing
 * (`fromPort`/`toPort`) so `lookupRegularState` can pick the right byte stream
 * when a `split-bytes` (multi-OUTPUT) feeds a fan-in `xor`/`concat`/`add`
 * (multi-INPUT) — neither endpoint has a single "primary" payload, so the port
 * name is the ONLY way to resolve the value. But BOTH graph rewrite stages
 * reconstructed edges from scratch and silently dropped those two fields:
 *
 *   - `collapseGraph` rebuilds every edge — even ones whose endpoints were NOT
 *     remapped — so the moment ANY container is collapsed (every cipher's key
 *     schedule is default-collapsed) every spine edge lost its pairing.
 *   - `replicateHighFanoutSources` rebuilt replica edges (`src@->consumer`)
 *     without the pairing, breaking high-fanout splits (Twofish's g-function).
 *
 * The pre-existing `des-multiport-value-lookup.test.ts` missed this because it
 * asserted on the RAW `deriveAuxGraph` output — it never ran collapse or
 * replication, the two stages that dropped the fields. This test closes that
 * gap by exercising the real pipeline.
 *
 * ## Why a universal walk, not just the 4 reported edges
 *
 * The failure is structural, not cipher-specific: it bites ANY port-native
 * cipher with a multi-output split or multi-input fan-in once a container is
 * collapsed. Rather than enumerate the handful of edges that happened to be
 * reported, we assert the INVARIANT — "a port-flow spine edge between two
 * frame-backed leaves always resolves to a value" — across every shipped
 * symmetric cipher, in both replication modes. A future cipher that introduces
 * a new split/fan-in shape is covered automatically; a future pipeline stage
 * that drops the pairing again fails here immediately.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes256Spec } from "@/ciphers/aes-256";
import { blowfishSpec } from "@/ciphers/blowfish";
import { blowfishDecryptSpec } from "@/ciphers/blowfish-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { twofishSpec } from "@/ciphers/twofish";
import { twofishDecryptSpec } from "@/ciphers/twofish-decrypt";
import { lookupEdgeValue } from "@/core/edge-value-lookup";
import {
  type CipherGraph,
  type GraphEdge,
  PORT_FLOW_AUX_KEY,
  collapseGraph,
  deriveAuxGraph,
  isEndpointId,
  replicateHighFanoutSources,
} from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { getDefaultCollapsedContainers } from "@/core/spec-defaults";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { canonicalStepId } from "@/core/step-id";
import type { AuxValue, CipherSpec, Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const REPLICA_DELIM = "@->";
/** The real UI replication threshold when the user enables replication. */
const REPLICATION_THRESHOLD = 3;

/** Strip a fan-out replica wrapper (`src@->consumer`) back to the source id. */
const unwrapReplica = (id: string): string => {
  const i = id.indexOf(REPLICA_DELIM);
  return i >= 0 ? id.slice(0, i) : id;
};

type Case = { readonly name: string; readonly spec: CipherSpec; readonly key: string };

// Every shipped symmetric cipher, encrypt + the decrypt specs that carry their
// own distinct split/whitening wiring. Inputs are arbitrary — the lookup
// resolution is independent of the plaintext; we only need a real trace.
const CASES: readonly Case[] = [
  { name: "aes-128", spec: aes128Spec, key: "000102030405060708090a0b0c0d0e0f" },
  { name: "aes-128 decrypt", spec: aes128DecryptSpec, key: "000102030405060708090a0b0c0d0e0f" },
  { name: "aes-192", spec: aes192Spec, key: "000102030405060708090a0b0c0d0e0f1011121314151617" },
  {
    name: "aes-256",
    spec: aes256Spec,
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  },
  { name: "speck-32-64-be", spec: speck32_64BeSpec, key: "1918111009080100" },
  { name: "speck-32-64-le", spec: speck32_64LeSpec, key: "1918111009080100" },
  { name: "serpent-128", spec: serpent128Spec, key: "000102030405060708090a0b0c0d0e0f" },
  {
    name: "serpent-192",
    spec: serpent192Spec,
    key: "000102030405060708090a0b0c0d0e0f1011121314151617",
  },
  {
    name: "serpent-256",
    spec: serpent256Spec,
    key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  },
  { name: "des", spec: desSpec, key: "133457799bbcdff1" },
  { name: "des decrypt", spec: desDecryptSpec, key: "133457799bbcdff1" },
  { name: "blowfish", spec: blowfishSpec, key: "0000000000000000" },
  { name: "blowfish decrypt", spec: blowfishDecryptSpec, key: "0000000000000000" },
  { name: "twofish", spec: twofishSpec, key: "000102030405060708090a0b0c0d0e0f" },
  { name: "twofish decrypt", spec: twofishDecryptSpec, key: "000102030405060708090a0b0c0d0e0f" },
];

/** A 16-byte input truncated/repeated to whatever block size the cipher wants. */
const inputFor = (spec: CipherSpec): string => {
  // Speck32/64 is a 4-byte block; DES/Blowfish 8-byte; the rest 16-byte.
  // Over-long hex is harmless — runSpec reads only the block it needs from the
  // initial state, and we never assert on the ciphertext here.
  void spec;
  return "00112233445566778899aabbccddeeff";
};

const runTrace = (c: Case): Trace =>
  runSpec(c.spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputFor(c.spec).slice(0, blockHexLen(c.spec)))),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(c.key)]]),
  });

/** Hex-char length of the cipher's block (2 chars/byte). */
const blockHexLen = (spec: CipherSpec): number => {
  const id = spec.id;
  if (id.startsWith("speck")) return 8; // 4-byte block
  if (id === "des" || id === "blowfish") return 16; // 8-byte block
  return 32; // 16-byte block (AES / Serpent / Twofish)
};

/** Canonical stepIds of every real trace frame — the "frame-backed" leaf set. */
const frameBackedIds = (trace: Trace): ReadonlySet<string> => {
  const set = new Set<string>();
  for (const f of trace.frames) set.add(canonicalStepId(f.stepId));
  return set;
};

/** True when an edge endpoint resolves to a real leaf frame (after unwrapping a
 *  replica wrapper). Endpoint pills and collapsed-container ids are excluded —
 *  a state edge touching those legitimately has no leaf-to-leaf byte value. */
const isFrameBacked = (id: string, frames: ReadonlySet<string>): boolean => {
  if (isEndpointId(id)) return false;
  return frames.has(canonicalStepId(unwrapReplica(id)));
};

/** Build the graph exactly as the UI does, at a given replication threshold
 *  (0 = replication off). */
const buildGraph = (spec: CipherSpec, trace: Trace, threshold: number): CipherGraph => {
  const raw = deriveAuxGraph(trace, spec, { registry: buildDefaultRegistry() });
  const collapsed = collapseGraph(raw, getDefaultCollapsedContainers(spec));
  return threshold > 0 ? replicateHighFanoutSources(collapsed, threshold) : collapsed;
};

/** The spine edges we assert on: port-flow STATE edges between two real leaves. */
const resolvableSpineEdges = (graph: CipherGraph, frames: ReadonlySet<string>): GraphEdge[] =>
  graph.edges.filter(
    (e) =>
      e.kind === "state" &&
      e.auxKey === PORT_FLOW_AUX_KEY &&
      isFrameBacked(e.from, frames) &&
      isFrameBacked(e.to, frames),
  );

describe("value-inspector resolves every port-flow spine edge through the full UI pipeline", () => {
  for (const c of CASES) {
    for (const [modeLabel, threshold] of [
      ["replication off", 0],
      ["replication on", REPLICATION_THRESHOLD],
    ] as const) {
      it(`${c.name} — ${modeLabel}: no spine edge between real leaves is "missing"`, () => {
        const trace = runTrace(c);
        const frames = frameBackedIds(trace);
        const graph = buildGraph(c.spec, trace, threshold);
        const edges = resolvableSpineEdges(graph, frames);
        // Sanity: the cipher actually has spine edges to check (guards against a
        // future refactor silently emptying the set and making this vacuous).
        expect(edges.length).toBeGreaterThan(0);

        const broken = edges
          .map((e) => ({ e, r: lookupEdgeValue(e, c.spec, trace, undefined) }))
          .filter(({ r }) => r.status !== "value");
        // Surface the exact failing edges in the assertion message so a
        // regression names the wire, not just a count.
        expect(
          broken.map(
            ({ e, r }) =>
              `${e.from} → ${e.to} [fp=${e.fromPort} tp=${e.toPort}] => ${r.status}${
                r.status === "missing" ? `: ${r.reason}` : ""
              }`,
          ),
        ).toEqual([]);
      });
    }
  }
});

// Explicit regression anchors for the four edges the user reported, so a
// failure points straight back at the original report.
describe("reported regression edges resolve after the fix", () => {
  const anchors: ReadonlyArray<readonly [string, string, string]> = [
    // [caseName, from, to]
    ["twofish", "round.1.g1.split@->round.1.g1.s3", "round.1.g1.s3"],
    ["twofish", "whiten-in.split@->whiten-in.r3", "whiten-in.r3"],
    ["blowfish", "round.1.split", "round.1.xorR"],
    ["blowfish", "whiten.split", "whiten.left"],
  ];
  for (const [caseName, from, to] of anchors) {
    it(`${caseName}: ${from} → ${to}`, () => {
      const c = CASES.find((x) => x.name === caseName);
      if (c === undefined) throw new Error(`case ${caseName} missing`);
      const trace = runTrace(c);
      // Twofish anchors need replication ON (the g-split is high-fanout); the
      // Blowfish anchors fail on the collapse path alone. Build with replication
      // ON so both replica and non-replica forms are present.
      const graph = buildGraph(c.spec, trace, REPLICATION_THRESHOLD);
      const edge = graph.edges.find((e) => e.from === from && e.to === to);
      if (edge === undefined) throw new Error(`edge ${from} → ${to} not in ${caseName} graph`);
      const r = lookupEdgeValue(edge, c.spec, trace, undefined);
      expect(r.status).toBe("value");
    });
  }
});
