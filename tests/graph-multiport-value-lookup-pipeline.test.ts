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
import { rsaDecryptSpec, rsaEncryptSpec } from "@/ciphers/rsa";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { twofishSpec } from "@/ciphers/twofish";
import { twofishDecryptSpec } from "@/ciphers/twofish-decrypt";
import { bigIntToBytes } from "@/core/big-int-codec";
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

type Case = { readonly name: string; readonly spec: CipherSpec; readonly run: () => Trace };

/** A keyed symmetric-cipher case. `keyHex` sets aux["key"]; `inputHex` sizes the
 *  block. Inputs are arbitrary — lookup resolution is independent of the actual
 *  plaintext; we only need a real trace. */
const sym = (name: string, spec: CipherSpec, keyHex: string, inputHex: string): Case => ({
  name,
  spec,
  run: () =>
    runSpec(spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(inputHex)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
    }),
});

const BLK16 = "00112233445566778899aabbccddeeff"; // 16-byte block (AES/Serpent/Twofish)
const BLK8 = "0011223344556677"; // 8-byte block (DES/Blowfish)
const BLK4 = "00112233"; // 4-byte block (Speck32/64)

// Every shipped port-native cipher/hash/asymmetric family. This deliberately
// spans BEYOND the reported Blowfish/Twofish: SHA-256 (`final.split-wv`/`-H` are
// 8-output splits feeding fan-in adds + the 8-input `final.assemble` — the exact
// multi-port shape) and RSA (bigint ladder is 2-input `mod-mul`/`cond-mod-mul`
// fan-ins) have the vulnerable topology too, and both have default-collapsed
// containers, so the regression bit them identically. The universal invariant
// below (every spine edge between two real leaves resolves) covers all of them.
const CASES: readonly Case[] = [
  sym("aes-128", aes128Spec, "000102030405060708090a0b0c0d0e0f", BLK16),
  sym("aes-128 decrypt", aes128DecryptSpec, "000102030405060708090a0b0c0d0e0f", BLK16),
  sym("aes-192", aes192Spec, "000102030405060708090a0b0c0d0e0f1011121314151617", BLK16),
  sym(
    "aes-256",
    aes256Spec,
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    BLK16,
  ),
  sym("speck-32-64-be", speck32_64BeSpec, "1918111009080100", BLK4),
  sym("speck-32-64-le", speck32_64LeSpec, "1918111009080100", BLK4),
  sym("serpent-128", serpent128Spec, "000102030405060708090a0b0c0d0e0f", BLK16),
  sym("serpent-192", serpent192Spec, "000102030405060708090a0b0c0d0e0f1011121314151617", BLK16),
  sym(
    "serpent-256",
    serpent256Spec,
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    BLK16,
  ),
  sym("des", desSpec, "133457799bbcdff1", BLK8),
  sym("des decrypt", desDecryptSpec, "133457799bbcdff1", BLK8),
  sym("blowfish", blowfishSpec, "0000000000000000", BLK8),
  sym("blowfish decrypt", blowfishDecryptSpec, "0000000000000000", BLK8),
  sym("twofish", twofishSpec, "000102030405060708090a0b0c0d0e0f", BLK16),
  sym("twofish decrypt", twofishDecryptSpec, "000102030405060708090a0b0c0d0e0f", BLK16),
  // SHA-256 — hash: message bytes on initialState, no key aux. A short
  // single-block message keeps the trace legible; the `final.*` region is what
  // matters and is identical regardless of message.
  {
    name: "sha-256",
    spec: buildSha256Spec(),
    run: () =>
      runSpec(buildSha256Spec(), buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex("616263")), // "abc"
      }),
  },
  // RSA — asymmetric: a small numeric message, no key aux (p/q/e are spec params
  // with defaults). W=2 default width. Both directions exercise the bigint ladder.
  {
    name: "rsa encrypt",
    spec: rsaEncryptSpec,
    run: () =>
      runSpec(rsaEncryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bigIntToBytes(42n, 2)),
      }),
  },
  {
    name: "rsa decrypt",
    spec: rsaDecryptSpec,
    run: () =>
      runSpec(rsaDecryptSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bigIntToBytes(42n, 2)),
      }),
  },
];

const runTrace = (c: Case): Trace => c.run();

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
    // SHA-256 has the SAME multi-port shape (advisor 2026-07-12): `final.s0 →
    // final.assemble` lands on the 8-input concat (collapse-path vulnerable), and
    // the 8-output `final.split-wv` replicates → the replica-path form. Both
    // present at the default collapse (the `blocks` iterate is NOT collapsed, so
    // the `final.*` leaves render) — so these anchors are non-vacuous.
    ["sha-256", "final.s0", "final.assemble"],
    ["sha-256", "final.split-wv@->final.s0", "final.s0"],
    // RSA's bigint ladder: `square-0 → mult-0` lands on the 4-input
    // `cond-mod-mul` (base port). Top-level ladder, so present at default collapse.
    ["rsa encrypt", "square-0", "mult-0"],
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
