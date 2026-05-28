/**
 * SHA-256 decomposition parity test — universal-port plan Phase 2
 * Slice 2.6d step 5 (2026-05-25).
 *
 * Proves that the **decomposed spec** shipped in Slice 2.6d (which uses
 * port-native compositions of rotate/xor/and/etc. + the new bridges
 * `aux-load-bytes@1`, `byte-slice@1`, `split-bytes@1`) produces
 * byte-identical output to a hypothetical **legacy spec** built from the
 * three SHA-256-specific lifted-legacy helpers (`sha2.message-schedule-
 * step@1`, `sha2.compression-round@1`, `sha2.final-add@1`) that remain
 * registered for backward-compatibility (per user pick Q2).
 *
 * This is the **Q-A-parity β** assertion that the parent plan
 * (`docs/plans/universal-port-dataflow.md`) calls for: frame-equivalence
 * at the cipher boundary between an old coarse-helper implementation and
 * a fine-primitive decomposition. The test gives us a long-term
 * regression net — any future change to either the sha2.* helpers OR
 * any of the universal port-native primitives the decomposition relies
 * on (rotate-bits-right, shift-bits-right, xor, add-mod-32, and, not,
 * concat, split-bytes, byte-slice, aux-load-bytes, constant-load,
 * state-to-bytes, bytes-to-state, state-to-aux) will be caught here if
 * it introduces a divergence between the two paths.
 *
 * **What this test does NOT pin:** per-frame correspondence (the
 * "frameMap" the plan mentions). Frame-level alignment between a 123-
 * frame run and a 2485-frame run is structural (1 helper frame ≈ 14 or
 * 28 decomposed frames in known shapes), but the byte-equality at the
 * cipher boundary is the load-bearing safety net. Per-frame structural
 * pins live in `tests/sha-256.test.ts` (28 leaves per round group +
 * K_t offset = 4 * t).
 *
 * **Why an inline legacy spec builder (not exported from sha-256.ts):**
 * the legacy spec is fixture data for THIS test only — the live
 * `buildSha256Spec` has been rewritten to the decomposed form and the
 * legacy form is no longer canonical. Keeping it inline here makes the
 * test self-contained and avoids exporting a deprecated spec builder
 * from the production module.
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  SHA256_INITIAL_HASH_VALUES,
  SHA256_ROUND_CONSTANTS,
  buildSha256Spec,
} from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import type { CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Legacy spec builder (uses the still-registered sha2.* helpers) ───────

/**
 * Reconstruct the pre-Slice-2.6d "coarse-helper" SHA-256 topology. This
 * mirrors the spec that shipped in Slice 2.6b; the math inside each
 * sha2.* helper is byte-identical to FIPS 180-4. The three helpers stay
 * registered post-2.6d for exactly this kind of round-trip / regression
 * net (user pick Q2 = keep registered + allowlisted, 2026-05-25).
 */
const wordsToBytes = (words: readonly number[]): number[] => {
  const out = new Array<number>(words.length * 4);
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as number;
    out[i * 4 + 0] = (w >>> 24) & 0xff;
    out[i * 4 + 1] = (w >>> 16) & 0xff;
    out[i * 4 + 2] = (w >>> 8) & 0xff;
    out[i * 4 + 3] = w & 0xff;
  }
  return out;
};

const SHA256_K_BYTES = wordsToBytes(SHA256_ROUND_CONSTANTS);
const SHA256_H_BYTES = wordsToBytes(SHA256_INITIAL_HASH_VALUES);

const buildSha256SpecLegacy = (): CipherSpec => {
  const buildCompressionRoundGroups = (): readonly StepNode[] => {
    const rounds: StepNode[] = [];
    for (let t = 0; t < 64; t++) {
      rounds.push({
        kind: "group",
        id: `round.${t}`,
        label: `Round ${t}`,
        children: [
          {
            kind: "step",
            id: `compress.${t}`,
            type: "sha2.compression-round@1",
            params: { roundIndex: t },
          },
        ],
      });
    }
    return rounds;
  };
  return {
    id: "sha-256@1-legacy",
    name: "SHA-256 (legacy / coarse-helper)",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      { kind: "step", id: "plaintext-source", type: "state-to-bytes@1", params: {} },
      {
        kind: "step",
        id: "pad",
        type: "pad-with-byte@1",
        params: { padByte: 0x80, blockSize: 64, padTarget: 56 },
        portInputs: { input: { node: "plaintext-source", port: "output" } },
      },
      {
        kind: "step",
        id: "length-append",
        type: "append-be64-length@1",
        params: {},
        portInputs: {
          data: { node: "pad", port: "output" },
          "length-source": { node: "plaintext-source", port: "output" },
        },
      },
      {
        kind: "step",
        id: "seed-schedule",
        type: "bytes-to-state@1",
        params: {},
        portInputs: { input: { node: "length-append", port: "output" } },
      },
      {
        kind: "for-each-subgraph-with-history",
        id: "msg-schedule",
        label: "Message schedule W_0..W_63",
        iterationCount: 48,
        lookbackOffsets: [2, 7, 15, 16],
        historyEntryByteLength: 4,
        children: [
          {
            kind: "step",
            id: "expand",
            type: "sha2.message-schedule-step@1",
            params: {},
          },
        ],
      },
      {
        kind: "step",
        id: "H-to-aux",
        type: "generic.aux-load@1",
        params: { auxName: "H", value: SHA256_H_BYTES },
      },
      {
        kind: "step",
        id: "K-to-aux",
        type: "generic.aux-load@1",
        params: { auxName: "K", value: SHA256_K_BYTES },
      },
      { kind: "step", id: "W-source", type: "state-to-bytes@1", params: {} },
      {
        kind: "step",
        id: "H-constant",
        type: "constant-load@1",
        params: { bytes: SHA256_H_BYTES },
      },
      {
        kind: "step",
        id: "compression-state-init",
        type: "concat@1",
        params: { inputCount: 2 },
        portInputs: {
          input0: { node: "H-constant", port: "output" },
          input1: { node: "W-source", port: "output" },
        },
      },
      {
        kind: "step",
        id: "compression-bridge",
        type: "bytes-to-state@1",
        params: {},
        portInputs: { input: { node: "compression-state-init", port: "output" } },
      },
      ...buildCompressionRoundGroups(),
      { kind: "step", id: "final-add", type: "sha2.final-add@1", params: {} },
    ],
  };
};

// ─── Helpers ──────────────────────────────────────────────────────────────

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const runHash = (spec: CipherSpec, plaintext: Uint8Array): Uint8Array => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: plaintext },
    portedDispatchEnabled: true,
  });
  if (trace.finalState.shape !== "bytes") {
    throw new Error(`expected bytes finalState, got ${trace.finalState.shape}`);
  }
  return trace.finalState.bytes;
};

// ─── Parity tests ──────────────────────────────────────────────────────────

describe("SHA-256 decomposition parity — legacy helpers vs decomposed primitives", () => {
  const cases: ReadonlyArray<{ readonly label: string; readonly bytes: Uint8Array }> = [
    { label: "empty string", bytes: new Uint8Array() },
    { label: "single byte 0x00", bytes: new Uint8Array([0x00]) },
    { label: "single byte 0xff", bytes: new Uint8Array([0xff]) },
    { label: "'a' (1 byte)", bytes: new Uint8Array([0x61]) },
    { label: "'abc' (3 bytes)", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    {
      label: "55-byte deterministic (max single-block)",
      bytes: new Uint8Array(Array.from({ length: 55 }, (_, i) => (i * 13 + 7) & 0xff)),
    },
  ];

  for (const c of cases) {
    it(`legacy (sha2.* helpers) and decomposed (port-native primitives) produce byte-identical hash for: ${c.label}`, () => {
      const legacyHash = runHash(buildSha256SpecLegacy(), c.bytes);
      const decomposedHash = runHash(buildSha256Spec(), c.bytes);
      // Three-way pin: both must equal each other AND node:crypto.
      const reference = createHash("sha256").update(c.bytes).digest();
      expect(bytesToHex(legacyHash)).toBe(bytesToHex(decomposedHash));
      expect(bytesToHex(legacyHash)).toBe(bytesToHex(new Uint8Array(reference)));
    });
  }
});

// ─── Frame-count divergence pin ───────────────────────────────────────────
//
// The headline pedagogical win of the decomposition: every algorithmic
// sub-step is now an individually visible frame. Pinning both frame
// counts catches accidental re-collapsing of the decomposition (e.g., a
// future refactor that merges leaves into a single chip would surface
// here AS WELL AS in tests/sha-256.test.ts's frame-count pin).

describe("SHA-256 decomposition parity — frame counts diverge as expected", () => {
  it("legacy = 123 frames (Slice 2.6b coarse helpers); decomposed = 2303 frames (Slice 2.6d primitives, post-A3b)", () => {
    const plaintext = new Uint8Array([0x61, 0x62, 0x63]); // "abc"
    const traceLegacy = runSpec(buildSha256SpecLegacy(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: plaintext },
      portedDispatchEnabled: true,
    });
    const traceDecomposed = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: plaintext },
      portedDispatchEnabled: true,
    });
    expect(traceLegacy.frames).toHaveLength(123);
    // 2303 post scaffolding-suppression A3b (was 2433 post-A3a, 2485 post-A1,
    // 2487 pre-A1). A3b dropped the round-body + final state bridges:
    // init-working-vars + state-in (×64) + state-out (×64) + final.state-in
    // = −130 frames. The legacy fixture below still builds its own coarse
    // spec, so 123 is unaffected.
    expect(traceDecomposed.frames).toHaveLength(2303);
    // ~19× ratio is the pedagogy payoff — every ROTR / XOR / add-mod is visible.
    expect(traceDecomposed.frames.length / traceLegacy.frames.length).toBeGreaterThan(15);
  });
});

// ─── Q2 (Slice 2.6d user pick) — helpers stay registered ──────────────────
//
// User picked Q2 = keep sha2.* registered + allowlisted (vs. retiring
// them from the registry). The narration / provenance contract tests
// already enforce that registered cell-shape step types are either
// covered or allowlisted. THIS test adds an explicit pin: the three
// helpers must remain in the registry so old saved documents that
// reference them continue to load + run.

describe("SHA-256 decomposition — Q2 pinning (sha2.* helpers stay registered)", () => {
  it("sha2.message-schedule-step@1, sha2.compression-round@1, sha2.final-add@1 all remain registered", () => {
    const registry = buildDefaultRegistry();
    expect(registry.has("sha2.message-schedule-step@1")).toBe(true);
    expect(registry.has("sha2.compression-round@1")).toBe(true);
    expect(registry.has("sha2.final-add@1")).toBe(true);
  });
});
