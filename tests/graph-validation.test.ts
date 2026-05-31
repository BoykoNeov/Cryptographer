/**
 * Tests for `src/core/graph.ts::validateGraph` and the runtime's
 * `auxReadMissing` capture (Slice 9 of the 2D editor plan).
 *
 * Three classes of warnings are exercised:
 *
 *   - **Zero-false-positives baseline.** Every shipped (cipher × spec)
 *     produces an empty warning list. If validation gains a false-positive
 *     this is the canary — a passing CI on a fresh checkout asserts that
 *     no shipped cipher is reported as malformed.
 *
 *   - **Orphaned read.** No shipped step gracefully handles a missing aux
 *     today (the strict consumers like `add-round-key` throw, so they never
 *     emit a frame). To exercise the detector without registering a
 *     production-impacting synthetic step type, we build a hand-crafted
 *     `Trace` whose frame carries `auxReadMissing` directly — the runtime's
 *     output as if a graceful aux consumer (`aux-xor`, landing in Slice 10)
 *     had read a key that wasn't there. This is what the validator must
 *     surface when Slice 10's primitives go in.
 *
 *   - **Unused write.** A frame writes an aux key that no later frame
 *     reads. Build a small `(graph, trace)` pair where this is true and
 *     assert the warning fires.
 *
 *   - **Cycle.** Hand-construct a `CipherGraph` with a 2- and 3-node cycle
 *     in its edge list and assert the detector picks them up. Trace-walked
 *     graphs are acyclic by construction (writers stamp time forward), so
 *     this only fires on future surfaces that synthesize edges from non-
 *     trace sources — defense in depth.
 *
 * The runtime tests at the top verify the new `auxReadMissing` field
 * survives the full executor → frame pipeline. Without this end-to-end
 * coverage, a future runtime refactor could drop the capture silently and
 * Slice 10's orphan reporting would stop working without any test light
 * turning red.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128CbcDecryptSpec } from "@/ciphers/aes-128-cbc-decrypt";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes256Spec } from "@/ciphers/aes-256";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { requiresPortedDispatch } from "@/core/dispatch";
import {
  type CipherGraph,
  type GraphEdge,
  buildIterateFeedbackPredicate,
  deriveAuxGraph,
  validateGraph,
} from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Test fixtures ─────────────────────────────────────────────────────────

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const AES192_KEY = "000102030405060708090a0b0c0d0e0f1011121314151617";
const AES256_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const SPECK_KEY = "1918111009080100";
const SPECK_PT = "65746957"; // 4 bytes — LE-NSA vector; BE byte-order is also length 4

const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const SERPENT192_KEY = "00112233445566778899aabbccddeeff0011223344556677";
const SERPENT256_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const SERPENT_PT = "00112233445566778899aabbccddeeff";

// 4-block plaintext for ECB (NIST SP 800-38A §F.1.1).
const ECB_PT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";
const ECB_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
// CBC fixtures (NIST SP 800-38A §F.2.1). Byte-native (Slice B1.4b): the chain
// rides the iterate's `chain` PORT (`chainInput`/`chainFeedback`), not an aux
// slot, so there's no `cbc-snapshot` aux write to leave dangling — the
// zero-warnings assertion below is the gate that the injected `chain` port
// produces no false orphaned-read / unused-write. Ported dispatch required.
const CBC_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
const CBC_IV = "000102030405060708090a0b0c0d0e0f";
const CBC_PT_1_BLOCK = "6bc1bee22e409f96e93d7e117393172a";
const CBC_PT_2_BLOCKS = `${CBC_PT_1_BLOCK}ae2d8a571e03ac9c9eb76fac45af8e51`;

const runCbc = (spec: typeof aes128CbcSpec, pt: string): Trace =>
  runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(pt)),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex(CBC_KEY)],
      ["iv", bytesFromHex(CBC_IV)],
    ]),
    portedDispatchEnabled: true,
  });

const runBytes = (spec: typeof aes128EcbSpec, key: string, pt: string): Trace => {
  const registry = buildDefaultRegistry();
  // Dispatch mode varies per spec: byte-native ECB (B1.4) + byte-native Speck
  // rounds (B2) need ported dispatch; still-lifted Serpent does not.
  // `requiresPortedDispatch` picks correctly per spec.
  return runSpec(spec, registry, {
    initialState: makeBytesState(bytesFromHex(pt)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(key)]]),
    portedDispatchEnabled: requiresPortedDispatch(spec, registry),
  });
};

// Byte-native single-block AES (Slices B1.1–B1.3): bytes state + ported
// dispatch (port-native primitives have no legacy executor). Covers every
// single-block AES — 128/192/256, both directions. Only the AES-128 ECB/CBC
// modes stay matrix (`runBytes`/`runCbc`) until B1.4.
const runPorted = (spec: typeof aes128Spec, key: string, pt: string): Trace =>
  runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(pt)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(key)]]),
    portedDispatchEnabled: true,
  });

const emptyTrace: Trace = {
  frames: [],
  initialState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalAux: new Map(),
};

// ─── Zero-false-positive baseline ──────────────────────────────────────────

describe("validateGraph — zero warnings on shipped specs", () => {
  // The whole point of this test block: every (cipher × spec) that ships
  // today must produce zero warnings. If validation gains a false positive
  // for AES key-expansion's roundKey fan-out, an iterate's mediated edges,
  // or any other genuinely-correct dataflow, this is the canary that lights
  // up first.

  it("AES-128 encrypt", () => {
    const trace = runPorted(aes128Spec, AES128_KEY, AES128_PT);
    const graph = deriveAuxGraph(trace, aes128Spec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("AES-128 decrypt", () => {
    // Byte-native (Slice B1.2). Use a trivially-valid ciphertext+key pair; the
    // SPECIFIC ciphertext doesn't matter — only that the run completes and the
    // graph derives.
    const ct = "69c4e0d86a7b0430d8cdb78070b4c55a";
    const trace = runPorted(aes128DecryptSpec, AES128_KEY, ct);
    const graph = deriveAuxGraph(trace, aes128DecryptSpec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("AES-192 encrypt", () => {
    const trace = runPorted(aes192Spec, AES192_KEY, AES128_PT);
    const graph = deriveAuxGraph(trace, aes192Spec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("AES-256 encrypt", () => {
    const trace = runPorted(aes256Spec, AES256_KEY, AES128_PT);
    const graph = deriveAuxGraph(trace, aes256Spec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("AES-128 CBC encrypt — single block (chain port produces no false warning)", () => {
    // Byte-native (Slice B1.4b): the chain rides the iterate's `chain` port,
    // injected by the runtime (like `in`). A single block exercises ZERO
    // chain feedback hops, so this is the tightest check that the injected
    // `chain` port doesn't read as an orphaned aux read and the chaining XOR's
    // port input doesn't leave any aux write dangling as unused.
    const trace = runCbc(aes128CbcSpec, CBC_PT_1_BLOCK);
    const graph = deriveAuxGraph(trace, aes128CbcSpec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("AES-128 CBC encrypt — multi-block (chain feedback across blocks, still clean)", () => {
    // Multi-block exercises the cross-iteration chain carry (block 1's chain
    // = block 0's ciphertext). The `:b{i}` collapse merges per-iteration port
    // reads onto canonical stepIds; this pins that the collapse + the chain
    // port together produce no false orphaned-read / unused-write / cycle.
    const trace = runCbc(aes128CbcSpec, CBC_PT_2_BLOCKS);
    const graph = deriveAuxGraph(trace, aes128CbcSpec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("AES-128 CBC decrypt — single block (decrypt-direction chain port, no false warning)", () => {
    // Decrypt's chainFeedback reads the raw input block (port(it,"in")), a
    // different binding shape from encrypt. Pin that the decrypt-direction
    // chain wiring is also warning-clean.
    const trace = runCbc(aes128CbcDecryptSpec, CBC_PT_1_BLOCK);
    const graph = deriveAuxGraph(trace, aes128CbcDecryptSpec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("AES-128 ECB (multi-block iterate)", () => {
    // Multi-block is the trickiest case: round-keys are read inside the
    // iterate body 11× per block × 4 blocks = 44 raw read events, all
    // collapsed by `:b{i}` stripping. If the unused-write detector
    // accidentally counted the per-iteration replicas separately it
    // would mark roundKey writes as unused. This test pins the dedup.
    const trace = runBytes(aes128EcbSpec, ECB_KEY, ECB_PT_4_BLOCKS);
    const graph = deriveAuxGraph(trace, aes128EcbSpec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("Speck32/64 (BE byte order)", () => {
    const trace = runBytes(speck32_64BeSpec, SPECK_KEY, SPECK_PT);
    const graph = deriveAuxGraph(trace, speck32_64BeSpec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("Speck32/64 (LE-NSA byte order)", () => {
    const trace = runBytes(speck32_64LeSpec, SPECK_KEY, SPECK_PT);
    const graph = deriveAuxGraph(trace, speck32_64LeSpec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("Serpent-128", () => {
    const trace = runBytes(serpent128Spec, SERPENT128_KEY, SERPENT_PT);
    const graph = deriveAuxGraph(trace, serpent128Spec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("Serpent-192", () => {
    const trace = runBytes(serpent192Spec, SERPENT192_KEY, SERPENT_PT);
    const graph = deriveAuxGraph(trace, serpent192Spec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("Serpent-256", () => {
    const trace = runBytes(serpent256Spec, SERPENT256_KEY, SERPENT_PT);
    const graph = deriveAuxGraph(trace, serpent256Spec);
    expect(validateGraph(graph, trace)).toEqual([]);
  });

  it("empty trace → no warnings (structure-only graph)", () => {
    // No frames means no reads or writes to inspect, so even a spec that
    // would warn on a real run produces zero warnings pre-run. Validation
    // therefore costs nothing on the boot path (no flicker of false alarms
    // before the first auto-rerun completes).
    const graph = deriveAuxGraph(emptyTrace, aes128Spec);
    expect(validateGraph(graph, emptyTrace)).toEqual([]);
  });
});

// ─── Cross-iteration feedback edge synthesis (matrix-CBC, REMOVED B1.4b) ────
//
// These three tests asserted the AUX feedback edge `cbc-snapshot → cbc-xor`
// (encrypt) / `cbc-advance-chain → cbc-xor` (decrypt) on aux key `chain`,
// synthesized by `deriveEdges` from the matrix CBC's per-iterate-body aux
// writer/reader topology. Byte-native CBC (B1.4b) carries the chain on the
// iterate's `chain` PORT, not an aux slot, so none of those leaves or aux
// edges exist anymore. No shipped spec exercises the aux structural-feedback
// synthesis now; the synthesis MECHANISM stays registered + unit-pinned by the
// hand-built `buildIterateFeedbackPredicate` / cycle-filter describes below.
//
// Drawing the byte-native chain-port feedback as a dashed over-the-top arc is
// the deferred cross-iteration recurrence-visibility work (see
// `docs/plans/universal-port-dataflow.md` defers; same gap as SHA-256's
// W_{t-N} arrows). When that lands it owns the port-feedback edge + its render
// test.

// ─── Orphaned-read detection ───────────────────────────────────────────────

describe("validateGraph — orphaned-read warnings", () => {
  // The runtime stamps `auxReadMissing` on a frame whose step requested
  // an aux key with no upstream producer. Today's shipped strict consumers
  // throw on missing aux so they never emit a frame at all; Slice 10's
  // graceful primitives (`aux-xor` etc.) will be the first to produce
  // these warnings naturally. Until then, exercise the detector by
  // hand-crafting a frame with the field already set.

  const makeOrphanFrame = (stepId: string, missing: readonly string[]): TraceFrame => ({
    index: 0,
    path: [stepId],
    stepId,
    stepType: "generic.test@1",
    params: {},
    stateBefore: { shape: "bytes", bytes: new Uint8Array(0) },
    stateAfter: { shape: "bytes", bytes: new Uint8Array(0) },
    auxRead: new Map(),
    auxWritten: new Map(),
    auxReadMissing: missing,
  });

  it("flags a single orphan with stepId + auxKey", () => {
    const trace: Trace = {
      frames: [makeOrphanFrame("xor.foo", ["nonexistent.key"])],
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalAux: new Map(),
    };
    const graph: CipherGraph = {
      nodes: [
        {
          stepId: "xor.foo",
          stepType: "generic.test@1",
          label: "xor.foo",
          containerPath: [],
        },
      ],
      containers: [],
      edges: [],
      rootIds: ["xor.foo"],
    };
    const warnings = validateGraph(graph, trace);
    expect(warnings).toEqual([
      { kind: "orphaned-read", stepId: "xor.foo", auxKey: "nonexistent.key" },
    ]);
  });

  it("dedups the same (stepId, auxKey) across multi-block iterations", () => {
    // Two frames whose stepIds share the canonical "iter.body" id after
    // `:b{i}` strip should produce ONE warning, not two — matching the
    // edge-dedup that `deriveAuxGraph` does for natural reads/writes.
    const trace: Trace = {
      frames: [
        {
          ...makeOrphanFrame("iter.body:b0", ["missing"]),
          index: 0,
          blockIndex: 0,
        },
        {
          ...makeOrphanFrame("iter.body:b1", ["missing"]),
          index: 1,
          blockIndex: 1,
        },
      ],
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalAux: new Map(),
    };
    const graph: CipherGraph = {
      nodes: [
        {
          stepId: "iter.body",
          stepType: "generic.test@1",
          label: "iter.body",
          containerPath: [],
        },
      ],
      containers: [],
      edges: [],
      rootIds: ["iter.body"],
    };
    const warnings = validateGraph(graph, trace);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toEqual({
      kind: "orphaned-read",
      stepId: "iter.body",
      auxKey: "missing",
    });
  });

  it("emits one warning per distinct missing aux key on the same step", () => {
    // A step that reads two aux keys, both missing, gets one warning per
    // key — so the user sees what every gap is, not just the first.
    const trace: Trace = {
      frames: [makeOrphanFrame("multi.read", ["a", "b"])],
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalAux: new Map(),
    };
    const graph: CipherGraph = {
      nodes: [
        {
          stepId: "multi.read",
          stepType: "generic.test@1",
          label: "multi.read",
          containerPath: [],
        },
      ],
      containers: [],
      edges: [],
      rootIds: ["multi.read"],
    };
    const warnings = validateGraph(graph, trace);
    expect(warnings).toEqual([
      { kind: "orphaned-read", stepId: "multi.read", auxKey: "a" },
      { kind: "orphaned-read", stepId: "multi.read", auxKey: "b" },
    ]);
  });
});

// ─── Runtime captures auxReadMissing ───────────────────────────────────────

describe("runtime — auxReadMissing capture", () => {
  // Even though no shipped step gracefully handles missing aux, the
  // runtime's filter — `if (v !== undefined) auxRead.set(k, v)` — has been
  // extended to ALSO record the missing keys for any step that returns a
  // value-yielding executor. Test the negative case: when an aux read
  // succeeds (key-expansion produces roundKey.0; add-round-key consumes
  // it), the frame's auxReadMissing stays undefined (no allocation).

  it("frames whose reads succeed carry no auxReadMissing field", () => {
    const trace = runPorted(aes128Spec, AES128_KEY, AES128_PT);
    for (const frame of trace.frames) {
      expect(frame.auxReadMissing).toBeUndefined();
    }
  });
});

// ─── Unused-write detection ────────────────────────────────────────────────

describe("validateGraph — unused-write warnings", () => {
  // Build a 2-step trace by hand:
  //   producer writes aux "junk"
  //   consumer (a separate step) does NOTHING with it
  // Graph has no edge for "junk" — validator should mark it unused.

  it("flags an aux write that no downstream step reads", () => {
    const trace: Trace = {
      frames: [
        {
          index: 0,
          path: ["producer"],
          stepId: "producer",
          stepType: "generic.test@1",
          params: {},
          stateBefore: { shape: "bytes", bytes: new Uint8Array(0) },
          stateAfter: { shape: "bytes", bytes: new Uint8Array(0) },
          auxRead: new Map(),
          auxWritten: new Map<string, AuxValue>([["junk", new Uint8Array(4)]]),
        },
        {
          index: 1,
          path: ["consumer"],
          stepId: "consumer",
          stepType: "generic.test@1",
          params: {},
          stateBefore: { shape: "bytes", bytes: new Uint8Array(0) },
          stateAfter: { shape: "bytes", bytes: new Uint8Array(0) },
          auxRead: new Map(),
          auxWritten: new Map(),
        },
      ],
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalAux: new Map(),
    };
    const graph: CipherGraph = {
      nodes: [
        { stepId: "producer", stepType: "generic.test@1", label: "producer", containerPath: [] },
        { stepId: "consumer", stepType: "generic.test@1", label: "consumer", containerPath: [] },
      ],
      containers: [],
      edges: [],
      rootIds: ["producer", "consumer"],
    };
    const warnings = validateGraph(graph, trace);
    expect(warnings).toEqual([{ kind: "unused-write", stepId: "producer", auxKey: "junk" }]);
  });

  it("does NOT flag a write that has a downstream edge", () => {
    // Producer + consumer with a real aux edge — happy path, no warning.
    const trace: Trace = {
      frames: [
        {
          index: 0,
          path: ["producer"],
          stepId: "producer",
          stepType: "generic.test@1",
          params: {},
          stateBefore: { shape: "bytes", bytes: new Uint8Array(0) },
          stateAfter: { shape: "bytes", bytes: new Uint8Array(0) },
          auxRead: new Map(),
          auxWritten: new Map<string, AuxValue>([["k", new Uint8Array(4)]]),
        },
      ],
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalState: { shape: "bytes", bytes: new Uint8Array(0) },
      finalAux: new Map(),
    };
    const graph: CipherGraph = {
      nodes: [
        { stepId: "producer", stepType: "generic.test@1", label: "producer", containerPath: [] },
        { stepId: "consumer", stepType: "generic.test@1", label: "consumer", containerPath: [] },
      ],
      containers: [],
      edges: [{ from: "producer", to: "consumer", auxKey: "k", kind: "aux" }],
      rootIds: ["producer", "consumer"],
    };
    expect(validateGraph(graph, trace)).toEqual([]);
  });
});

// Hand-built CipherGraph fixtures used across the cycle-detection and the
// iterate-feedback-predicate describe blocks. Defined at module scope so
// both consumers share the same shape.
const makeNode = (id: string) => ({
  stepId: id,
  stepType: "generic.test@1",
  label: id,
  containerPath: [] as readonly string[],
});

const auxEdge = (from: string, to: string, key: string): GraphEdge => ({
  from,
  to,
  auxKey: key,
  kind: "aux",
});

// ─── Cycle detection ───────────────────────────────────────────────────────

describe("validateGraph — cycle detection", () => {
  // Trace-derived graphs are acyclic by construction (writers stamp time
  // forward), so the detector only fires for hand-built or future-
  // synthesized graphs. Build cycles by hand for unit coverage.

  it("flags a 2-node cycle", () => {
    const graph: CipherGraph = {
      nodes: [makeNode("a"), makeNode("b")],
      containers: [],
      edges: [auxEdge("a", "b", "x"), auxEdge("b", "a", "y")],
      rootIds: ["a", "b"],
    };
    const warnings = validateGraph(graph, emptyTrace);
    const cycle = warnings.find((w) => w.kind === "cycle");
    expect(cycle).toBeDefined();
    expect(cycle?.kind).toBe("cycle");
    if (cycle?.kind === "cycle") {
      // Cycle is reported as a sequence of node ids. Both members must be
      // present; order can be either direction depending on DFS start.
      expect(cycle.stepIds).toContain("a");
      expect(cycle.stepIds).toContain("b");
    }
  });

  it("flags a 3-node cycle", () => {
    const graph: CipherGraph = {
      nodes: [makeNode("a"), makeNode("b"), makeNode("c")],
      containers: [],
      edges: [auxEdge("a", "b", "x"), auxEdge("b", "c", "y"), auxEdge("c", "a", "z")],
      rootIds: ["a", "b", "c"],
    };
    const warnings = validateGraph(graph, emptyTrace);
    const cycle = warnings.find((w) => w.kind === "cycle");
    expect(cycle).toBeDefined();
    if (cycle?.kind === "cycle") {
      expect(new Set(cycle.stepIds)).toEqual(new Set(["a", "b", "c"]));
    }
  });

  it("does NOT flag an acyclic DAG", () => {
    // Diamond: a → {b, c} → d. No cycle.
    const graph: CipherGraph = {
      nodes: [makeNode("a"), makeNode("b"), makeNode("c"), makeNode("d")],
      containers: [],
      edges: [
        auxEdge("a", "b", "x"),
        auxEdge("a", "c", "y"),
        auxEdge("b", "d", "z"),
        auxEdge("c", "d", "w"),
      ],
      rootIds: ["a", "b", "c", "d"],
    };
    const warnings = validateGraph(graph, emptyTrace);
    expect(warnings.filter((w) => w.kind === "cycle")).toEqual([]);
  });

  it("does NOT flag self-edges on the diagonal of an acyclic chain", () => {
    // Forward-only chain — the simplest acyclic structure. If the cycle
    // detector mistakes a long chain for a cycle, this catches it.
    const graph: CipherGraph = {
      nodes: [makeNode("a"), makeNode("b"), makeNode("c"), makeNode("d")],
      containers: [],
      edges: [auxEdge("a", "b", "x"), auxEdge("b", "c", "y"), auxEdge("c", "d", "z")],
      rootIds: ["a", "b", "c", "d"],
    };
    expect(validateGraph(graph, emptyTrace)).toEqual([]);
  });

  // ─── Iterate-feedback exclusion ───────────────────────────────────────────
  // CBC's chain feedback (writer→reader within one iterate body, going
  // backwards in spec order) is the canonical motivator: the `:b{i}`
  // stepId-strip merges iteration N's snapshot-write with iteration N+1's
  // xor-read, producing an edge that looks like a cycle in canonical-id
  // space but is just per-iteration feedback. Filter it out at the cycle
  // detector — same edge stays in graph.edges (renderer still draws it).

  it("does NOT flag aux feedback inside an iterate body (CBC chain pattern)", () => {
    // Hand-build: an iterate "loop" with two leaves; the second writes
    // aux[chain] and the first reads it (the `:b{i}`-collapsed shape).
    // A forward state edge from xor → snapshot completes the
    // would-be-cycle. The fix suppresses the cycle warning.
    const graph: CipherGraph = {
      nodes: [
        { ...makeNode("xor"), containerPath: ["loop"] },
        { ...makeNode("snapshot"), containerPath: ["loop"] },
      ],
      containers: [
        {
          kind: "iterate",
          id: "loop",
          label: "loop",
          containerPath: [],
          childIds: ["xor", "snapshot"],
        },
      ],
      edges: [
        // Forward state edge (the AES body, simplified to a single hop).
        { from: "xor", to: "snapshot", auxKey: "state", kind: "state" },
        // Backwards aux edge: snapshot writes chain, xor reads it
        // (canonicalized across iteration boundaries).
        auxEdge("snapshot", "xor", "chain"),
      ],
      rootIds: ["loop"],
    };
    const warnings = validateGraph(graph, emptyTrace);
    expect(warnings.filter((w) => w.kind === "cycle")).toEqual([]);
  });

  it("STILL flags a real cycle inside a non-iterate group (filter is iterate-specific)", () => {
    // Group ancestor (not iterate). A genuine logic loop here is a real
    // cycle the user would want to know about. The filter must not fire.
    const graph: CipherGraph = {
      nodes: [
        { ...makeNode("a"), containerPath: ["grp"] },
        { ...makeNode("b"), containerPath: ["grp"] },
      ],
      containers: [
        {
          kind: "group",
          id: "grp",
          label: "grp",
          containerPath: [],
          childIds: ["a", "b"],
        },
      ],
      edges: [auxEdge("a", "b", "x"), auxEdge("b", "a", "y")],
      rootIds: ["grp"],
    };
    const warnings = validateGraph(graph, emptyTrace);
    const cycle = warnings.find((w) => w.kind === "cycle");
    expect(cycle).toBeDefined();
  });

  it("STILL flags a cycle that crosses an iterate boundary (filter requires SHARED iterate ancestor)", () => {
    // One endpoint inside an iterate, one outside. The common ancestor is
    // the root (not an iterate), so the filter must not fire even though
    // the iterate-feedback shape looks similar.
    const graph: CipherGraph = {
      nodes: [
        { ...makeNode("outer"), containerPath: [] },
        { ...makeNode("inner"), containerPath: ["loop"] },
      ],
      containers: [
        {
          kind: "iterate",
          id: "loop",
          label: "loop",
          containerPath: [],
          childIds: ["inner"],
        },
      ],
      edges: [auxEdge("outer", "inner", "x"), auxEdge("inner", "outer", "y")],
      rootIds: ["outer", "loop"],
    };
    const warnings = validateGraph(graph, emptyTrace);
    const cycle = warnings.find((w) => w.kind === "cycle");
    expect(cycle).toBeDefined();
  });
});

/**
 * Direct unit coverage for `buildIterateFeedbackPredicate`. The renderer
 * uses the same predicate to mark iterate-feedback edges with a dashed
 * style (e.g. CBC's `cbc-snapshot → cbc-xor`) so the predicate must:
 *
 *   1. Return TRUE for a backwards-in-spec-order aux edge inside the same
 *      iterate body (the canonical chain-mode shape).
 *   2. Return FALSE for ordinary forward aux edges (e.g. round-key fan-out).
 *   3. Return FALSE for state edges regardless of direction (they're
 *      forward-only by construction; a backward state edge is a real bug
 *      the renderer should NOT silently dress as feedback).
 *   4. Return FALSE for edges whose endpoints don't share an iterate
 *      ancestor (a real cycle inside a `group`, or one endpoint outside
 *      the iterate entirely).
 *
 * Shared with `validateGraph` so both the cycle filter and the renderer
 * stay in sync — same predicate, two consumers.
 */
describe("buildIterateFeedbackPredicate — shared cycle-filter / renderer helper", () => {
  it("flags backwards aux edge inside the same iterate (CBC shape)", () => {
    const graph: CipherGraph = {
      nodes: [
        { ...makeNode("xor"), containerPath: ["loop"] },
        { ...makeNode("snapshot"), containerPath: ["loop"] },
      ],
      containers: [
        {
          kind: "iterate",
          id: "loop",
          label: "loop",
          containerPath: [],
          childIds: ["xor", "snapshot"],
        },
      ],
      edges: [auxEdge("snapshot", "xor", "chain")],
      rootIds: ["loop"],
    };
    const predicate = buildIterateFeedbackPredicate(graph);
    expect(predicate(graph.edges[0] as GraphEdge)).toBe(true);
  });

  it("does NOT flag a forward aux edge inside the same iterate (normal flow)", () => {
    const graph: CipherGraph = {
      nodes: [
        { ...makeNode("xor"), containerPath: ["loop"] },
        { ...makeNode("snapshot"), containerPath: ["loop"] },
      ],
      containers: [
        {
          kind: "iterate",
          id: "loop",
          label: "loop",
          containerPath: [],
          childIds: ["xor", "snapshot"],
        },
      ],
      edges: [auxEdge("xor", "snapshot", "data")],
      rootIds: ["loop"],
    };
    const predicate = buildIterateFeedbackPredicate(graph);
    expect(predicate(graph.edges[0] as GraphEdge)).toBe(false);
  });

  it("never flags state edges, even when going backwards in spec order", () => {
    // Defensive — state edges are forward-only by construction, but if a
    // future bug stamps one backwards we don't want the dashed style to
    // silently hide it. validateGraph's cycle detector should still see it.
    const graph: CipherGraph = {
      nodes: [
        { ...makeNode("xor"), containerPath: ["loop"] },
        { ...makeNode("snapshot"), containerPath: ["loop"] },
      ],
      containers: [
        {
          kind: "iterate",
          id: "loop",
          label: "loop",
          containerPath: [],
          childIds: ["xor", "snapshot"],
        },
      ],
      edges: [{ from: "snapshot", to: "xor", auxKey: "state", kind: "state" }],
      rootIds: ["loop"],
    };
    const predicate = buildIterateFeedbackPredicate(graph);
    expect(predicate(graph.edges[0] as GraphEdge)).toBe(false);
  });

  it("does NOT flag a backwards aux edge that lacks a shared iterate ancestor", () => {
    // Two leaves inside the same `group` (not iterate). A backwards aux
    // edge here is a real cycle, not iterate feedback — predicate must
    // not absorb it.
    const graph: CipherGraph = {
      nodes: [
        { ...makeNode("a"), containerPath: ["grp"] },
        { ...makeNode("b"), containerPath: ["grp"] },
      ],
      containers: [
        {
          kind: "group",
          id: "grp",
          label: "grp",
          containerPath: [],
          childIds: ["a", "b"],
        },
      ],
      edges: [auxEdge("b", "a", "x")],
      rootIds: ["grp"],
    };
    const predicate = buildIterateFeedbackPredicate(graph);
    expect(predicate(graph.edges[0] as GraphEdge)).toBe(false);
  });
});
