/**
 * Phase 0, Q-gate-9 (the load-bearing assertion) for the universal port-based
 * dataflow plan (`docs/plans/universal-port-dataflow.md`). Runs the existing
 * legacy runtime over real AES-128 fixtures, picks frames for the three
 * target shapes, and asserts the project→reconstruct round-trip is byte-
 * equal to the original frame.
 *
 * Why this test is the gate:
 *
 *   The other 8 Phase-0 gates ("linear view still works", "MatrixView
 *   highlights still work", etc.) pass trivially when the adapter merely
 *   COPIES legacy frames through the new contract — they test for
 *   regressions, not for the truth of the migration's premise. Only the
 *   round-trip asserts what the entire plan rests on:
 *
 *     "Every TraceFrame is one projection of unified per-port byte arrays.
 *      The legacy state/aux split is lossless against (inputs, outputs,
 *      layoutTags)."
 *
 * If THIS gate fails, Phases 1–5 need re-planning before any further work.
 * If it passes, the load-bearing claim is validated empirically and the
 * rest of Phase 0 is mechanical (lift → dual-dispatch → end-to-end smoke).
 *
 * Phase-0 SCOPE (per user pick 2026-05-23):
 *   - Three target step types from real shipped specs:
 *     1. `generic.byte-substitution@1` (pure state-only, matrix4x4-bytes)
 *     2. `generic.add-round-key@1` (aux-reading round key, matrix4x4-bytes)
 *     3. EITHER OF THE ABOVE emitted INSIDE the ECB iterate (validates
 *        `blockIndex` stamping + `:b{i}` stepId suffix preservation)
 *   - Bitvec and bigint State variants are NOT exercised here — they're
 *     TODO-marked in `core/types.ts` (`LayoutTags`) and
 *     `core/port-projection.ts` for Phase 1 when SHA-2 (or RSA later)
 *     forces them. The design accommodates them; this fixture doesn't
 *     stress them.
 *
 * Anti-trivial discipline check (TWO layers, 2026-05-23):
 *
 *   1. **Type-level**: `LayoutTags` (in `core/types.ts`) has no field that
 *      could carry a `State` object — only the State variant tag, optional
 *      bit-length / bigint-encoding fields, and aux-key name bindings. So
 *      `reconstruct` literally CANNOT "cheat" by reading the original
 *      State variant from the sidecar at compile time.
 *
 *   2. **Runtime structural clone barrier** (advisor item 2, bundled with
 *      Phase 0 close): every assertion wraps the `tags` value in
 *      `structuredClone(tags)` before passing to `reconstruct`. If a future
 *      refactor weakens `LayoutTags` to smuggle a `State` (e.g., by
 *      stuffing it into a generic field that survives the type system),
 *      structuredClone would either fail (non-cloneable property) or
 *      strip the smuggled branding — and the assertion's `expectFrameByte
 *      Equal` would catch the resulting drift. Node ≥17 (vitest's runtime
 *      target) supports structuredClone natively, including `ReadonlyMap`.
 *
 * Together, these two layers ensure the round-trip's GREEN status is
 * EVIDENCE that the migration's premise holds, not just an artifact of
 * a permissive type signature.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { type ProjectionMetadata, project, reconstruct } from "@/core/port-projection";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, Json, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Slice 1.0 — Dynamic-N aux-write round-trip ─────────────────────────
//
// Why this lives alongside Q-gate-9 (and not its own file): the round-trip
// machinery exercised here (project / reconstruct / structuredClone barrier
// / expectFrameByteEqual) is identical; the new thing is that the
// `auxWritePorts(params)` function returns a port-count sized by
// `params.rounds`, validating Decision B (port-per-roundkey) for the five
// key-schedule step types Slices 1.4–1.8 will lift. Phase 0 only had
// static single-binding metadata.

// FIPS-197 Appendix B test vectors. The fixture data is not important
// for what's being tested (we're checking byte-identity round-trip, not
// cipher correctness — that's the job of `aes-vectors.test.ts`). Real
// vector values pin the trace shape and make any future regression
// inspectable in `git blame`.
const FIPS_B_PLAINTEXT = "3243f6a8885a308d313198a2e0370734";
const FIPS_B_KEY = "2b7e151628aed2a6abf7158809cf4f3c";

// SP 800-38A §F.1.1 — one block extracted from the four-block ECB fixture.
const ECB_BLOCK_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
const ECB_ONE_BLOCK_PLAINTEXT = "6bc1bee22e409f96e93d7e117393172a";

// ─── Projection metadata for the two Phase-0 lifted step types ─────────
//
// These are the only two contracts the round-trip exercises. Inlined here
// (rather than in a registry) because Phase 0's scope is intentionally
// small — Phase 1 will fold metadata into the StepRegistration union
// itself, eliminating the need for the test to know contracts.

const META_BYTE_SUBSTITUTION: ProjectionMetadata = {
  stateLayout: "matrix4x4-bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
  // No aux read/write — byte substitution is purely state-local.
};

/**
 * `add-round-key`'s aux key name lives in `params.auxName` (typically
 * "roundKey.0" through "roundKey.N"). The function shape is mandatory
 * here, not a static map: the same step type's leaves have DIFFERENT
 * aux key names per round, so the binding can only be resolved with
 * `params` in hand.
 */
const META_ADD_ROUND_KEY: ProjectionMetadata = {
  stateLayout: "matrix4x4-bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
  auxReadPorts: (params: Json) => {
    if (
      typeof params !== "object" ||
      params === null ||
      Array.isArray(params) ||
      !("auxName" in params) ||
      typeof (params as { auxName: unknown }).auxName !== "string"
    ) {
      throw new Error("add-round-key projection metadata expected params.auxName: string");
    }
    return new Map([["key", (params as { auxName: string }).auxName]]);
  },
};

// ─── Helpers ────────────────────────────────────────────────────────────

const findFirstFrame = (frames: readonly TraceFrame[], stepType: string): TraceFrame => {
  const frame = frames.find((f) => f.stepType === stepType);
  if (!frame) {
    throw new Error(`fixture missing a frame for stepType=${stepType}`);
  }
  return frame;
};

const findFirstFrameInIterate = (frames: readonly TraceFrame[], stepType: string): TraceFrame => {
  // "Inside iterate" is observable on the frame as `blockIndex !== undefined`
  // AND the stepId carrying the `:b{i}` suffix. We assert both so the
  // fixture choice is self-validating.
  const frame = frames.find((f) => f.stepType === stepType && f.blockIndex !== undefined);
  if (!frame) {
    throw new Error(`fixture missing an iterate-body frame for stepType=${stepType}`);
  }
  if (!frame.stepId.includes(":b")) {
    throw new Error(
      `iterate-body frame for stepType=${stepType} should carry :b{i} suffix; got stepId=${frame.stepId}`,
    );
  }
  if (frame.blockIndex === undefined) {
    // Belt-and-braces: the find() predicate already guarantees this.
    throw new Error("iterate-body frame missing blockIndex");
  }
  return frame;
};

/**
 * Custom byte-equality for the round-trip assertion. Vitest's default
 * `toEqual` performs deep-equality but compares Uint8Array via reference
 * unless the path traverses them as iterables. We unpack the maps and
 * compare the byte arrays element-wise to make any mismatch loud and
 * locatable.
 */
const expectFrameByteEqual = (recovered: TraceFrame, original: TraceFrame): void => {
  expect(recovered.index).toBe(original.index);
  expect(recovered.path).toEqual(original.path);
  expect(recovered.stepId).toBe(original.stepId);
  expect(recovered.stepType).toBe(original.stepType);
  expect(recovered.params).toEqual(original.params);

  // Frame metadata that's optional on the legacy frame; the projection
  // must preserve presence/absence symmetrically.
  expect(recovered.blockIndex).toBe(original.blockIndex);
  expect(recovered.branchPath).toEqual(original.branchPath);
  expect(recovered.auxReadMissing).toEqual(original.auxReadMissing);

  // State: cross-check shape AND bytes. cloneState() in `bytesToState`
  // produces a fresh Uint8Array, so we're comparing values, not refs.
  expect(recovered.stateBefore.shape).toBe(original.stateBefore.shape);
  expect(recovered.stateAfter.shape).toBe(original.stateAfter.shape);
  expectStateBytesEqual(recovered.stateBefore, original.stateBefore);
  expectStateBytesEqual(recovered.stateAfter, original.stateAfter);

  // Aux maps: compare key sets AND per-key Uint8Array bytes.
  expectAuxMapByteEqual(recovered.auxRead, original.auxRead);
  expectAuxMapByteEqual(recovered.auxWritten, original.auxWritten);
};

const expectStateBytesEqual = (
  recovered: TraceFrame["stateBefore"],
  original: TraceFrame["stateBefore"],
): void => {
  // Phase 0 only exercises bytes / matrix4x4-bytes; switch is exhaustive
  // by State union, but the bitvec/bigint arms throw a recognizable
  // error if a fixture surprise routes data through them.
  if (recovered.shape !== original.shape) {
    throw new Error(
      `state shape mismatch: recovered=${recovered.shape} original=${original.shape}`,
    );
  }
  switch (original.shape) {
    case "bytes":
    case "matrix4x4-bytes": {
      if (recovered.shape !== original.shape) return;
      expect(Array.from(recovered.bytes)).toEqual(Array.from(original.bytes));
      return;
    }
    case "bitvec":
      throw new Error("Phase 0 fixture should not produce bitvec frames");
    case "bigint":
      throw new Error("Phase 0 fixture should not produce bigint frames");
  }
};

const expectAuxMapByteEqual = (
  recovered: ReadonlyMap<string, AuxValue>,
  original: ReadonlyMap<string, AuxValue>,
): void => {
  expect([...recovered.keys()].sort()).toEqual([...original.keys()].sort());
  for (const [key, origValue] of original) {
    const recValue = recovered.get(key);
    if (!(origValue instanceof Uint8Array)) {
      // Phase 0 only handles Uint8Array aux values; project() throws if
      // anything else is targeted by a binding. If a fixture surfaces a
      // non-Uint8Array value here, that's a Phase 0 finding to report.
      throw new Error(
        `Phase 0 fixture aux key "${key}" has non-Uint8Array value (type=${typeof origValue})`,
      );
    }
    if (!(recValue instanceof Uint8Array)) {
      throw new Error(`recovered aux key "${key}" has non-Uint8Array value`);
    }
    expect(Array.from(recValue)).toEqual(Array.from(origValue));
  }
};

// ─── The round-trip test ───────────────────────────────────────────────

describe("port-projection — Q-gate-9 round-trip (Phase 0 load-bearing)", () => {
  describe("single-block AES-128 (no iterate)", () => {
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: matrixFromBytes(bytesFromHex(FIPS_B_PLAINTEXT)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(FIPS_B_KEY)]]),
    });

    it("pure state-only frame (generic.byte-substitution@1) round-trips byte-for-byte", () => {
      const frame = findFirstFrame(trace.frames, "generic.byte-substitution@1");
      const { frame: ported, tags } = project(frame, META_BYTE_SUBSTITUTION);
      // structuredClone barrier — see header. Strips any smuggled State
      // branding; non-cloneable smuggling would throw before reconstruct
      // even sees the tags.
      const recovered = reconstruct(ported, structuredClone(tags));

      // Sanity: the projection produced an input + output state port
      // and no aux bindings (byte substitution reads no aux).
      expect(ported.inputs.has("state")).toBe(true);
      expect(ported.outputs.has("state")).toBe(true);
      expect(tags.auxInputBindings).toBeUndefined();
      expect(tags.auxOutputBindings).toBeUndefined();
      expect(tags.stateLayout).toBe("matrix4x4-bytes");

      expectFrameByteEqual(recovered, frame);
    });

    it("aux-reading frame (generic.add-round-key@1) round-trips byte-for-byte", () => {
      const frame = findFirstFrame(trace.frames, "generic.add-round-key@1");
      const { frame: ported, tags } = project(frame, META_ADD_ROUND_KEY);
      const recovered = reconstruct(ported, structuredClone(tags));

      // Sanity: the aux read became a "key" input port; the binding
      // maps "key" back to the spec's roundKey.N name.
      expect(ported.inputs.has("state")).toBe(true);
      expect(ported.inputs.has("key")).toBe(true);
      expect(tags.auxInputBindings).toBeDefined();
      const auxKey = tags.auxInputBindings?.get("key");
      expect(typeof auxKey).toBe("string");
      expect(auxKey?.startsWith("roundKey.")).toBe(true);

      expectFrameByteEqual(recovered, frame);
    });
  });

  describe("aux-write round-trip — dynamic-N port count (Slice 1.0, Decision B)", () => {
    // The first leaf in aes128Spec is `aes.key-expansion@1`. State is
    // matrix4x4-bytes (the spec loads its initial state via matrixFromBytes
    // before walking the spec); the executor leaves state unchanged
    // ("preserveInput" shape contract). The aux writes are 11 entries
    // (`roundKey.0` … `roundKey.10`) — that's the dynamic-N case the
    // metadata's `auxWritePorts(params)` function must size by
    // `params.rounds`. AES-192 / 256 would size to 13 / 15 respectively,
    // and Speck (22) / Serpent (33) / DES (16) take the same shape.
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: matrixFromBytes(bytesFromHex(FIPS_B_PLAINTEXT)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(FIPS_B_KEY)]]),
    });

    // One-off metadata for AES key-expansion. Test-fixture only — Slice 1.4
    // moves this to co-located metadata in src/steps/key-expansion.ts as
    // part of the StepRegistration entry. The function shape on both
    // auxReadPorts and auxWritePorts is mandatory: every leaf can have a
    // different `keyAuxName` (read binding) and a different `outputPrefix`
    // (write bindings), so static maps don't cut it.
    const META_AES_KEY_EXPANSION: ProjectionMetadata = {
      stateLayout: "matrix4x4-bytes",
      stateInputPort: "state",
      stateOutputPort: "state",
      auxReadPorts: (params: Json) => {
        if (typeof params !== "object" || params === null || Array.isArray(params)) {
          throw new Error("aes.key-expansion projection: params must be an object");
        }
        const p = params as { keyAuxName?: unknown };
        if (typeof p.keyAuxName !== "string") {
          throw new Error("aes.key-expansion projection: params.keyAuxName: string required");
        }
        // Port name "masterKey" disambiguates the input from the per-round
        // output ports (`key0`, `key1`, …) — naming a single input port
        // `key` would conflict with the natural shape of the outputs.
        return new Map([["masterKey", p.keyAuxName]]);
      },
      auxWritePorts: (params: Json) => {
        if (typeof params !== "object" || params === null || Array.isArray(params)) {
          throw new Error("aes.key-expansion projection: params must be an object");
        }
        const p = params as { outputPrefix?: unknown; rounds?: unknown };
        if (typeof p.outputPrefix !== "string") {
          throw new Error("aes.key-expansion projection: params.outputPrefix: string required");
        }
        if (typeof p.rounds !== "number" || !Number.isInteger(p.rounds) || p.rounds < 1) {
          throw new Error("aes.key-expansion projection: params.rounds: positive integer required");
        }
        // N+1 round-key ports — one for the pre-round AddRoundKey plus one
        // per round. Iteration in `r = 0..rounds` order; Map iteration
        // preserves insertion order in JS, which the round-trip relies on
        // to regenerate auxWritten in the original order (asserted below).
        const bindings = new Map<string, string>();
        for (let r = 0; r <= p.rounds; r++) {
          bindings.set(`key${r}`, `${p.outputPrefix}.${r}`);
        }
        return bindings;
      },
    };

    const KEY_EXPANSION_FRAME = findFirstFrame(trace.frames, "aes.key-expansion@1");

    it("projects 11 output ports + 1 input port for AES-128 (rounds=10)", () => {
      const { frame: ported, tags } = project(KEY_EXPANSION_FRAME, META_AES_KEY_EXPANSION);

      // 1 state output port + 11 round-key output ports.
      expect(ported.outputs.size).toBe(12);
      expect(ported.outputs.has("state")).toBe(true);
      for (let r = 0; r <= 10; r++) {
        expect(ported.outputs.has(`key${r}`)).toBe(true);
      }

      // 1 state input port + 1 master-key input port.
      expect(ported.inputs.size).toBe(2);
      expect(ported.inputs.has("state")).toBe(true);
      expect(ported.inputs.has("masterKey")).toBe(true);

      // Each round-key output port carries exactly 16 bytes (AES round
      // key length). Belt-and-braces against a future projection refactor
      // that drops the byte payload while leaving the port name in place.
      for (let r = 0; r <= 10; r++) {
        expect(ported.outputs.get(`key${r}`)?.length).toBe(16);
      }

      // Tags carry both binding sides; sizes match the port counts so
      // reconstruction can rebuild auxRead + auxWritten exactly.
      expect(tags.auxInputBindings).toBeDefined();
      expect(tags.auxInputBindings?.size).toBe(1);
      expect(tags.auxInputBindings?.get("masterKey")).toBe("key");

      expect(tags.auxOutputBindings).toBeDefined();
      expect(tags.auxOutputBindings?.size).toBe(11);
      for (let r = 0; r <= 10; r++) {
        expect(tags.auxOutputBindings?.get(`key${r}`)).toBe(`roundKey.${r}`);
      }
    });

    it("round-trips byte-for-byte (all 11 round keys recover exact bytes)", () => {
      const { frame: ported, tags } = project(KEY_EXPANSION_FRAME, META_AES_KEY_EXPANSION);
      // structuredClone barrier — same anti-trivial discipline as the
      // single-binding Phase-0 round-trips. Particularly important here
      // because tags.auxOutputBindings is a ReadonlyMap<string, string>
      // with 11 entries; a clone failure would surface as a structurally
      // identical but reference-different map, and the round-trip would
      // still pass — that's the desired property (the test passes through
      // a clone-equivalent representation, exercising "tags carry data
      // not references").
      const recovered = reconstruct(ported, structuredClone(tags));
      expectFrameByteEqual(recovered, KEY_EXPANSION_FRAME);

      // The whole-frame expectFrameByteEqual above subsumes the per-key
      // check, but a dedicated per-key assertion gives a localizable
      // failure if the round-trip ever regresses — "auxWritten[roundKey.7]
      // bytes mismatch" is a sharper signal than "auxWritten maps differ".
      expect(recovered.auxWritten.size).toBe(11);
      for (let r = 0; r <= 10; r++) {
        const recoveredKey = recovered.auxWritten.get(`roundKey.${r}`);
        const originalKey = KEY_EXPANSION_FRAME.auxWritten.get(`roundKey.${r}`);
        expect(recoveredKey).toBeInstanceOf(Uint8Array);
        expect(originalKey).toBeInstanceOf(Uint8Array);
        expect(Array.from(recoveredKey as Uint8Array)).toEqual(
          Array.from(originalKey as Uint8Array),
        );
      }
    });

    it("preserves auxWritten Map insertion order across the round-trip", () => {
      // Map iteration is insertion-ordered in JS. Consumers walking
      // auxWritten (e.g., the round-key panel that lays out `key0` …
      // `keyN` left-to-right; narration that says "the 11 round keys
      // are produced in this order") depend on this. The reconstruction
      // path iterates `tags.auxOutputBindings` in its insertion order
      // to rebuild auxWritten — if that order ever diverges from the
      // legacy frame's, the visual / narrated order changes silently.
      const { frame: ported, tags } = project(KEY_EXPANSION_FRAME, META_AES_KEY_EXPANSION);
      const recovered = reconstruct(ported, structuredClone(tags));

      const originalKeyOrder = [...KEY_EXPANSION_FRAME.auxWritten.keys()];
      const recoveredKeyOrder = [...recovered.auxWritten.keys()];
      expect(recoveredKeyOrder).toEqual(originalKeyOrder);
    });

    it("preserves the master-key auxRead binding name across the round-trip", () => {
      // The input-port side of Decision B: round-trip must regenerate
      // the legacy `key` aux key (NOT `masterKey`, which is the port
      // name). The asymmetry between port-name (contract-level, stable)
      // and aux-key (spec-leaf-level, varies) is exactly what the
      // tags.auxInputBindings sidecar exists to preserve.
      const { frame: ported, tags } = project(KEY_EXPANSION_FRAME, META_AES_KEY_EXPANSION);
      const recovered = reconstruct(ported, structuredClone(tags));

      expect(recovered.auxRead.size).toBe(1);
      expect(recovered.auxRead.has("key")).toBe(true);
      expect(recovered.auxRead.has("masterKey")).toBe(false);
      const recoveredMaster = recovered.auxRead.get("key");
      const originalMaster = KEY_EXPANSION_FRAME.auxRead.get("key");
      expect(recoveredMaster).toBeInstanceOf(Uint8Array);
      expect(originalMaster).toBeInstanceOf(Uint8Array);
      expect(Array.from(recoveredMaster as Uint8Array)).toEqual(
        Array.from(originalMaster as Uint8Array),
      );
    });
  });

  describe("iterate body — AES-128 ECB (single block)", () => {
    // ONE 16-byte block — the iterate runs once, so iterate-body frames
    // carry blockIndex=0 and :b0 stepId suffix. Round-trip must
    // preserve both.
    const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(ECB_ONE_BLOCK_PLAINTEXT)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(ECB_BLOCK_KEY)]]),
    });

    it("byte-substitution INSIDE iterate preserves blockIndex + :b{i} stepId suffix", () => {
      const frame = findFirstFrameInIterate(trace.frames, "generic.byte-substitution@1");
      const { frame: ported, tags } = project(frame, META_BYTE_SUBSTITUTION);
      const recovered = reconstruct(ported, structuredClone(tags));

      expect(ported.blockIndex).toBe(0);
      expect(ported.stepId.endsWith(":b0")).toBe(true);
      expectFrameByteEqual(recovered, frame);
    });

    it("add-round-key INSIDE iterate preserves blockIndex + aux binding + :b{i} suffix", () => {
      const frame = findFirstFrameInIterate(trace.frames, "generic.add-round-key@1");
      const { frame: ported, tags } = project(frame, META_ADD_ROUND_KEY);
      const recovered = reconstruct(ported, structuredClone(tags));

      expect(ported.blockIndex).toBe(0);
      expect(ported.stepId.endsWith(":b0")).toBe(true);
      expect(tags.auxInputBindings?.get("key")).toBeDefined();
      expectFrameByteEqual(recovered, frame);
    });
  });
});
