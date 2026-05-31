/**
 * Graph-derivation structural sanity for the PORT-NATIVE DES spec
 * (B4 — universal-port Phase 4d). DES no longer uses `feistel-round`: each
 * round is a port-mode `group` wiring split / des.expand-R / des.xor-with-K /
 * des.s-boxes / des.p-permutation / xor / concat. This file pins that
 * shipped topology — 16 round-group containers, the F-function leaf chain,
 * the key-schedule → xor-K aux fan-out, and the ABSENCE of any feistel
 * container or rejoin/passthrough synthetic.
 *
 * The Feistel graph derivation itself (feistel-kind containers, L/R
 * passthrough chips, rejoin synthesis, the R-bypass chip, all edge classes)
 * is still covered against the surviving primitive by
 * `tests/feistel-graph.test.ts` (the toy fixture) — this file is the
 * port-native counterpart, mirroring how SHA-256's port-native graph is
 * pinned.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { deriveAuxGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

const emptyTrace = {
  frames: [],
  initialState: { shape: "bytes" as const, bytes: new Uint8Array(8) },
  finalState: { shape: "bytes" as const, bytes: new Uint8Array(8) },
  finalAux: new Map(),
};

// A real (ported) trace so the aux-edge assertions have frame.auxRead entries
// to bite on. FIPS 46-3 Appendix B vector — same one des-vectors.test.ts uses.
const desTrace = runSpec(desSpec, buildDefaultRegistry(), {
  initialState: { shape: "bytes" as const, bytes: bytesFromHex("0123456789abcdef") },
  initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
  portedDispatchEnabled: true,
});

describe("DES (port-native) graph derivation — structural sanity", () => {
  it("emits 16 round-group containers (one per round) inside the rounds group", () => {
    const graph = deriveAuxGraph(emptyTrace, desSpec);
    for (let r = 1; r <= 16; r++) {
      const round = graph.containers.find((c) => c.id === `round.${r}`);
      expect(round, `round.${r} container`).toBeDefined();
      expect(round?.containerPath).toEqual(["rounds"]);
    }
    // The outer rounds group is a container too.
    expect(graph.containers.find((c) => c.id === "rounds")).toBeDefined();
  });

  // (The "emits NO feistel-kind containers / synthesizes NO rejoin or
  // passthrough nodes" guards were retired in Phase 5 Slice 5.3e — the
  // `kind: "feistel"` ContainerNode variant and the `synthetic` GraphNode
  // field no longer exist, so "DES is port-native" is now enforced by the
  // type system rather than a runtime assertion.)

  it("each round carries the 7 port-native F-body leaves", () => {
    const graph = deriveAuxGraph(emptyTrace, desSpec);
    const suffixes = ["split", "expand-R", "xor-K", "s-boxes", "p-permute", "fxor", "recombine"];
    for (let r = 1; r <= 16; r++) {
      for (const s of suffixes) {
        const id = `round.${r}.${s}`;
        expect(
          graph.nodes.find((n) => n.stepId === id),
          id,
        ).toBeDefined();
      }
    }
  });

  it("carries the $input source + IP/FP cipher-boundary leaves", () => {
    const graph = deriveAuxGraph(emptyTrace, desSpec);
    expect(
      graph.nodes.find((n) => n.stepId === "$input"),
      "$input source",
    ).toBeDefined();
    expect(
      graph.nodes.find((n) => n.stepId === "initial-permutation"),
      "IP",
    ).toBeDefined();
    expect(
      graph.nodes.find((n) => n.stepId === "final-permutation"),
      "FP",
    ).toBeDefined();
  });

  it("fans the key-schedule out to all 16 xor-K leaves with the right round key", () => {
    const graph = deriveAuxGraph(desTrace, desSpec);
    for (let r = 1; r <= 16; r++) {
      const edge = graph.edges.find(
        (e) =>
          e.from === "key-schedule" &&
          e.to === `round.${r}.xor-K` &&
          e.kind === "aux" &&
          e.auxKey === `roundKey.${r - 1}`,
      );
      expect(edge, `key-schedule → round.${r}.xor-K (roundKey.${r - 1})`).toBeDefined();
    }
  });

  it("does not throw on the full 16-round port-native DES spec", () => {
    expect(() => deriveAuxGraph(emptyTrace, desSpec)).not.toThrow();
    expect(() => deriveAuxGraph(desTrace, desSpec)).not.toThrow();
  });
});
