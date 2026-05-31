/**
 * Byte-native AES graph derivation — `$input` materialization + CBC chain-port
 * resolution (scaffolding-suppression B1.5, Findings 1 + 2).
 *
 * Two graph-derivation gaps surfaced by a browser look at the byte-native CBC
 * graph; both are spec-derived (so they reproduce on an empty trace).
 *
 * **Finding 1 — the dangling plaintext pill (ECB *and* CBC).** The port-mode
 * `iterate` references `$input` via its *container* `seedInput` field, not via
 * any child leaf's `portInputs`. `specReferencesInputSource` walked only leaf
 * `portInputs`, so it returned `false`, the `$input` synthetic node was never
 * materialized — yet `inferPortEdges` still resolved `port(iterate,"in") →
 * $input` and emitted an edge to a node that was never drawn (a dangling edge,
 * rendered as the floating plaintext pill). The fix teaches
 * `specReferencesInputSource` to inspect container `seedInput`/`chainInput`/
 * `chainFeedback`. Pinned here as: (a) `$input` is materialized, and (b) the
 * graph has NO dangling edge (every endpoint resolves to a real node).
 *
 * **Finding 2 — fetch-iv floats + spurious "block body → cbc-xor" arrow (CBC).**
 * `cbc-xor` reads `port("cbc-blocks","chain")`. `inferPortEdges` resolved
 * `port(iter,"in")` through `seedInput` but let `port(iter,"chain")` fall
 * through to the container id — so the chain edge pointed at the `cbc-blocks`
 * container (the spurious whole-body→cbc-xor arrow) and `fetch-iv`'s output was
 * read by nobody (it floated). The fix mirrors the seed resolution with a
 * `chainSeedByIterateId` map so `port(iter,"chain")` resolves through
 * `chainInput` → `fetch-iv`. Pinned here as: `fetch-iv → cbc-xor` exists, the
 * `cbc-blocks → cbc-xor` arrow is gone, and `fetch-iv` is connected.
 *
 * NB: these are STRUCTURAL pins (edge endpoints). The visual/geometry gate — does
 * the pill actually render connected? — is a browser smoke, per the plan's B1.5
 * verification gates; jsdom can't see layout.
 */

import { buildAesCbcSpec } from "@/ciphers/aes-cbc-builder";
import { buildAesEcbSpec } from "@/ciphers/aes-ecb-builder";
import type { AesVariant, CipherDirection } from "@/ciphers/aes-ecb-builder";
import { deriveAuxGraph } from "@/core/graph";
import type { CipherSpec, Trace } from "@/core/types";
import { INPUT_SOURCE_ID } from "@/core/types";
import { describe, expect, it } from "vitest";

const emptyTrace = (): Trace => ({
  frames: [],
  initialState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalAux: new Map(),
});

// Port-flow + state edges come from the spec, so no run is needed.
const graphOf = (spec: CipherSpec) => deriveAuxGraph(emptyTrace(), spec);

// Every id a real node/container in the graph can be referenced by.
const materializedIds = (spec: CipherSpec): ReadonlySet<string> => {
  const g = graphOf(spec);
  return new Set<string>([...g.nodes.map((n) => n.stepId), ...g.containers.map((c) => c.id)]);
};

const VARIANTS: readonly AesVariant[] = ["aes-128", "aes-192", "aes-256"];
const DIRECTIONS: readonly CipherDirection[] = ["encrypt", "decrypt"];

describe("byte-native AES graph — Finding 1: `$input` is materialized + no dangling edges", () => {
  // ECB and CBC both seed their iterate from `$input` via the container
  // `seedInput`, so both regressed identically before the fix.
  for (const variant of VARIANTS) {
    for (const direction of DIRECTIONS) {
      const ecb = buildAesEcbSpec(variant, direction);
      const cbc = buildAesCbcSpec(variant, direction);

      it(`${variant} ECB (${direction}): \`$input\` node is materialized + connected`, () => {
        const g = graphOf(ecb);
        expect(g.nodes.some((n) => n.stepId === INPUT_SOURCE_ID)).toBe(true);
        // The resolved port edge `$input → <body head>` must exist — the pill
        // is connected, not floating.
        expect(g.edges.some((e) => e.from === INPUT_SOURCE_ID)).toBe(true);
      });

      it(`${variant} CBC (${direction}): \`$input\` node is materialized + connected`, () => {
        const g = graphOf(cbc);
        expect(g.nodes.some((n) => n.stepId === INPUT_SOURCE_ID)).toBe(true);
        expect(g.edges.some((e) => e.from === INPUT_SOURCE_ID)).toBe(true);
      });

      it(`${variant} ECB (${direction}): every edge endpoint resolves to a real node (no dangling edge)`, () => {
        const ids = materializedIds(ecb);
        const g = graphOf(ecb);
        const dangling = g.edges.filter((e) => !ids.has(e.from) || !ids.has(e.to));
        expect(dangling).toEqual([]);
      });

      it(`${variant} CBC (${direction}): every edge endpoint resolves to a real node (no dangling edge)`, () => {
        const ids = materializedIds(cbc);
        const g = graphOf(cbc);
        const dangling = g.edges.filter((e) => !ids.has(e.from) || !ids.has(e.to));
        expect(dangling).toEqual([]);
      });
    }
  }
});

describe("byte-native AES CBC graph — Finding 2: chain port resolves through `chainInput` to `fetch-iv`", () => {
  for (const variant of VARIANTS) {
    for (const direction of DIRECTIONS) {
      const cbc = buildAesCbcSpec(variant, direction);

      it(`${variant} CBC (${direction}): the chain edge runs \`fetch-iv → cbc-xor\` (not the container)`, () => {
        const g = graphOf(cbc);
        // The IV bootstrap edge resolves through the iterate's `chainInput`.
        const fetchIvToXor = g.edges.some(
          (e) => e.from === "fetch-iv" && e.to === "cbc-xor" && e.kind === "state",
        );
        expect(fetchIvToXor).toBe(true);
        // The spurious "whole block body → cbc-xor" arrow (chain falling through
        // to the container id) must be gone.
        const containerToXor = g.edges.some((e) => e.from === "cbc-blocks" && e.to === "cbc-xor");
        expect(containerToXor).toBe(false);
      });

      it(`${variant} CBC (${direction}): \`fetch-iv\` is connected (not floating)`, () => {
        const g = graphOf(cbc);
        expect(g.edges.some((e) => e.from === "fetch-iv")).toBe(true);
      });

      it(`${variant} CBC (${direction}): the body's "in" reads still resolve to \`$input\` (chain branch didn't disturb them)`, () => {
        // The F2 change only branches on `port === "chain"`; the `"in"` path —
        // which carries the per-block input to the body head (and, in decrypt,
        // is what `chainFeedback` reuses) — must still resolve to `$input`.
        const g = graphOf(cbc);
        expect(g.edges.some((e) => e.from === INPUT_SOURCE_ID && e.to === "cbc-xor")).toBe(
          direction === "encrypt",
        );
        // Decrypt's body head is the AES inverse body, not cbc-xor; either way
        // some leaf consumes `$input`.
        expect(g.edges.some((e) => e.from === INPUT_SOURCE_ID)).toBe(true);
      });
    }
  }
});
