/**
 * SHA-256 end-to-end KAT test — universal-port plan Phase 2 Slice 2.6b
 * (2026-05-25).
 *
 * The first port-native cipher under the universal-port-dataflow plan.
 * The cipher ships at coarse step granularity (per the Slice 2.6b
 * re-scope — three SHA-256-specific lifted-legacy helper steps:
 * `sha2.message-schedule-step@1`, `sha2.compression-round@1`,
 * `sha2.final-add@1`); the in-spec port-native composition lands in
 * Slice 2.6d after the bridge vocabulary is designed in 2.6c.
 *
 * This file's KAT is the load-bearing exit gate for Slice 2.6b:
 *
 *  - **FIPS 180-4 §A.1 single-block "abc"**: the canonical KAT. Expected
 *    hash: `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
 *
 *  - **Cross-check with node:crypto**: a second independent SHA-256
 *    implementation. Catches any divergence the FIPS table can't (e.g., a
 *    bug that happens to flip the same bits in both our impl AND our
 *    transcription of the §A.1 expected hash).
 *
 *  - **Frame count expectation**: the cipher emits a specific number of
 *    frames per run. Pinning the count guards against silent control-flow
 *    changes (a future refactor that accidentally drops or duplicates a
 *    leaf would surface here).
 *
 *  - **State shape transitions**: state is BytesState throughout — 3
 *    bytes (plaintext) → 56 (padded) → 64 (padded+length) → 64 still
 *    (seeded into FES-with-history) → 256 (W) → 288 (H||W after concat) →
 *    288 through 64 rounds → 32 (final hash). Pin a few intermediate
 *    states to catch shape regressions.
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import type { StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const runSha256 = (plaintext: Uint8Array): Uint8Array => {
  const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: plaintext },
  });
  if (trace.finalState.shape !== "bytes") {
    throw new Error(`expected bytes finalState, got ${trace.finalState.shape}`);
  }
  return trace.finalState.bytes;
};

// Slice 2.11b: the per-block body (message schedule + 64 rounds + final-add)
// lives inside the port-mode `iterate` "blocks". The structural pins reach the
// round groups through it rather than off the top-level `spec.steps`.
const blockBody = (): readonly StepNode[] => {
  const spec = buildSha256Spec();
  const blocks = spec.steps.find((s) => s.id === "blocks");
  if (blocks === undefined || blocks.kind !== "iterate") {
    throw new Error("expected a `blocks` iterate node at the top level");
  }
  return blocks.children;
};

// ─── FIPS 180-4 §A.1 KAT ──────────────────────────────────────────────────

describe("SHA-256 — FIPS 180-4 §A.1 'abc' KAT", () => {
  it("produces ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad for the 3-byte message 'abc'", () => {
    const plaintext = new Uint8Array([0x61, 0x62, 0x63]); // "abc"
    const hash = runSha256(plaintext);
    expect(hash.length).toBe(32);
    expect(bytesToHex(hash)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("hash matches node:crypto SHA-256 for the same input ('abc')", () => {
    const plaintext = new Uint8Array([0x61, 0x62, 0x63]);
    const ours = runSha256(plaintext);
    const reference = createHash("sha256").update(plaintext).digest();
    expect(Array.from(ours)).toEqual(Array.from(reference));
  });
});

// ─── Single-block edge cases against node:crypto ──────────────────────────

describe("SHA-256 — single-block messages against node:crypto", () => {
  // Single-block scope: message length ≤ 55 bytes (so msg + 0x80 + zeros
  // + 8-byte length suffix fits in one 64-byte block).
  const cases: ReadonlyArray<{ readonly label: string; readonly bytes: Uint8Array }> = [
    { label: "empty string", bytes: new Uint8Array() },
    { label: "single byte 0x00", bytes: new Uint8Array([0x00]) },
    { label: "single byte 0xff", bytes: new Uint8Array([0xff]) },
    { label: "'a' (1 byte)", bytes: new Uint8Array([0x61]) },
    { label: "'abc' (3 bytes)", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    {
      label: "55-byte message (max single-block input)",
      bytes: new Uint8Array(Array.from({ length: 55 }, (_, i) => (i * 13 + 7) & 0xff)),
    },
  ];

  for (const c of cases) {
    it(`matches node:crypto for: ${c.label}`, () => {
      const ours = runSha256(c.bytes);
      const reference = createHash("sha256").update(c.bytes).digest();
      expect(bytesToHex(ours)).toBe(bytesToHex(new Uint8Array(reference)));
    });
  }
});

// ─── Frame count + state shape pins (regression guards) ──────────────────

describe("SHA-256 — frame count and state shape pins", () => {
  it("emits the expected number of frames per run", () => {
    // Frame budget for a SINGLE-block run (message "abc", N=1). Slice 2.11b
    // wraps the per-block body (message schedule + 64 rounds + final-add) in a
    // port-mode `iterate` "blocks": the container emits no frame of its own,
    // but every body frame's stepId now carries a `:b0` suffix. The fold also
    // retired the `final.fetch-H` aux-load-bytes leaf (the final-add addend is
    // the iterate `chain` port — the running hash — not the constant aux["H"]),
    // so a single-block run is one frame shorter than the pre-2.11b 2303.
    //
    //   - 3 parent-scope leaves: pad + length-append + init.fetch-H
    //     (init.fetch-H bootstraps the iterate's chainInput = block 0's H).
    //   - inside the "blocks" iterate (one pass for a single block):
    //       - 13 schedule body leaves × 48 iterations = 624 frames.
    //       - 26 leaves × 64 compression rounds = 1664 frames.
    //       - 11 final-add leaves: split-wv + split-H + 8×add-mod-32 + concat
    //         (was 12 — `final.fetch-H` retired in 2.11b).
    //     = 624 + 1664 + 11 = 2299 frames per block.
    //
    // Total: 3 + 2299 = 2302 frames (was 2303 pre-2.11b). A multi-block run is
    // 3 parent frames + N × 2299 body frames (e.g. a 2-block message = 4601).
    const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    });
    expect(trace.frames).toHaveLength(2302);
  });

  it("finalState is always 32 bytes BytesState (the hash)", () => {
    const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    });
    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") throw new Error("unreachable");
    expect(trace.finalState.bytes.length).toBe(32);
  });

  it("aux['H'] and aux['K'] survive end-to-end in finalAux (materialized from cipherConstants, never deleted)", () => {
    const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    });
    expect(trace.finalAux.has("H")).toBe(true);
    expect(trace.finalAux.has("K")).toBe(true);
    const h = trace.finalAux.get("H");
    const k = trace.finalAux.get("K");
    if (!(h instanceof Uint8Array)) throw new Error("expected aux['H'] to be Uint8Array");
    if (!(k instanceof Uint8Array)) throw new Error("expected aux['K'] to be Uint8Array");
    expect(h.length).toBe(32);
    expect(k.length).toBe(256);
  });
});

// ─── A3b carry visibility (Q1 — USER hard requirement) ────────────────────
//
// Scaffolding-suppression A3b carries the working variables a..h port-to-port
// between rounds (the `state-in`/`state-out` bridges are gone). The user's
// hard requirement (plan Q1 visibility): the carried values MUST stay visible
// AND consistent at a round boundary in the linear scrubber, so a learner sees
// how a..h change. `round.{t}.repack` (concat — round t's output) and
// `round.{t+1}.split` (split — round t+1's input) are real computational
// frames; the 32 bytes leaving repack must be exactly the 32 bytes split reads
// (8 × 4-byte working variables). This is the opposite of the pre-A3b bridges,
// which showed a stale `state` value contradicting the ports (the smoke bug).

describe("SHA-256 — A3b carry visibility (Q1)", () => {
  it("carried a..h are visible AND consistent at every round boundary", () => {
    const spec = buildSha256Spec();
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    });
    const byId = new Map(trace.frames.map((f) => [f.stepId, f]));

    // Slice 2.11b: the per-block body runs inside the "blocks" iterate, so for
    // the single-block "abc" message every body frame's stepId gains a `:b0`
    // suffix. Round 0 is now seeded (via round.0.seedInput → port("blocks",
    // "chain")) with block 0's running hash, which IS the initial hash a..h =
    // cipherConstants.H (the iterate's chainInput bootstrap). init.fetch-H
    // stays in the PARENT scope (it feeds chainInput) so its frame has no
    // `:b0` suffix.
    const r0Split = byId.get("round.0.split:b0");
    expect(byId.get("init.fetch-H")).toBeDefined();
    expect(r0Split).toBeDefined();
    expect(r0Split?.portInputs?.get("input")).toEqual(spec.cipherConstants?.H);

    // Every inter-round boundary: round t's repack output === t+1's split input.
    for (let t = 0; t < 63; t++) {
      const repack = byId.get(`round.${t}.repack:b0`);
      const nextSplit = byId.get(`round.${t + 1}.split:b0`);
      expect(repack, `round.${t}.repack:b0 must be a visible frame`).toBeDefined();
      expect(nextSplit, `round.${t + 1}.split:b0 must be a visible frame`).toBeDefined();
      const carried = repack?.portOutputs?.get("output");
      expect(carried?.length).toBe(32); // 8 × 4-byte working variables a..h
      expect(nextSplit?.portInputs?.get("input")).toEqual(carried);
    }

    // Exit: round 63's repack feeds final.split-wv (the post-round-63 a..h).
    const finalSplit = byId.get("final.split-wv:b0");
    expect(byId.get("round.63.repack:b0")).toBeDefined();
    expect(finalSplit).toBeDefined();
    expect(finalSplit?.portInputs?.get("input")).toEqual(
      byId.get("round.63.repack:b0")?.portOutputs?.get("output"),
    );
  });
});

// ─── Spec structural pins ────────────────────────────────────────────────

describe("SHA-256 — spec structural pins", () => {
  it("spec exposes the expected top-level fields", () => {
    const spec = buildSha256Spec();
    expect(spec.id).toBe("sha-256@1");
    expect(spec.name).toBe("SHA-256");
    expect(spec.stateShape).toBe("bytes");
    expect(spec.inputs.key.byteLength).toBe(0);
    expect(spec.inputs.plaintext.shape).toBe("bytes");
  });

  // Slice 2.11b: the per-block fold. The "blocks" iterate threads the running
  // hash as its chain — chainInput bootstraps it from init.fetch-H (block 0's
  // H), chainFeedback advances it from final.assemble, and chainOutput
  // ("digest") harvests the final value, which `outputFrom` reads as the
  // 32-byte digest. seedInput is the padded message split at 64-byte blocks.
  it("wraps the per-block body in a port-mode `iterate` fold (running-hash chain)", () => {
    const spec = buildSha256Spec();
    const blocks = spec.steps.find((s) => s.id === "blocks");
    if (blocks === undefined || blocks.kind !== "iterate") {
      throw new Error("expected a `blocks` iterate node");
    }
    expect(blocks.blockByteLength).toBe(64);
    expect(blocks.seedInput).toEqual({ node: "length-append", port: "output" });
    expect(blocks.chainInput).toEqual({ node: "init.fetch-H", port: "output" });
    expect(blocks.chainFeedback).toEqual({ node: "final.assemble", port: "output" });
    expect(blocks.chainOutput).toBe("digest");
    expect(spec.outputFrom).toEqual({ node: "blocks", port: "digest" });
  });

  it("spec has 64 compression round groups (inside the `blocks` iterate)", () => {
    const rounds = blockBody().filter((s) => s.kind === "group" && /^round\.\d+$/.test(s.id));
    expect(rounds).toHaveLength(64);
  });

  // Slice 2.6d follow-up (2026-05-25). Without `defaultCollapsed: true`
  // on every round group, the graph view shows 1792 chips on first
  // render — the chip-wall failure mode flagged in Slice 2.6c plan F.1.
  // Pin the marker so a future SHA-256 refactor that loses it surfaces
  // here, not as a "users complain about a chip wall" bug report.
  it("every compression round group carries defaultCollapsed: true (chip-wall avoidance)", () => {
    const rounds = blockBody().filter(
      (s): s is Extract<StepNode, { kind: "group" }> =>
        s.kind === "group" && /^round\.\d+$/.test(s.id),
    );
    expect(rounds).toHaveLength(64);
    for (const round of rounds) {
      expect(round.defaultCollapsed).toBe(true);
    }
  });

  it("validateShapes finds zero warnings on the SHA-256 spec", async () => {
    const { validateShapes } = await import("@/core/spec-shapes");
    const warnings = validateShapes(buildSha256Spec(), buildDefaultRegistry());
    expect(warnings).toEqual([]);
  });

  // Under the Slice 2.6d decomposed topology, each round group wraps the
  // algorithmic sub-steps as leaves. Scaffolding-suppression A3b retired the
  // two state bridges (`state-in` state-to-bytes + `state-out` bytes-to-state)
  // per round: `split` now reads the group's `seedInput` port and `repack` is
  // the group's `bodyOutput`. So each round wraps 26 leaves (split-bytes,
  // Σ0/Σ1/Ch/Maj chains, T1/T2 adds, new_a/new_e, repack-concat). The
  // byte-slice offset is the load-bearing per-round disambiguator in the
  // decomposed form — different rounds extract from different positions in K/W.
  it("each compression-round group has 26 leaves with K_t offset = 4 * t", () => {
    const seenIndices = new Set<number>();
    for (const step of blockBody()) {
      if (step.kind !== "group") continue;
      const m = /^round\.(\d+)$/.exec(step.id);
      if (m === null) continue;
      const t = Number.parseInt(m[1] as string, 10);
      expect(step.children).toHaveLength(26);
      // Locate the K_t byte-slice leaf and assert its offset.
      const ktSlice = step.children.find((c) => c.kind === "step" && c.id === `round.${t}.K_t`);
      if (!ktSlice || ktSlice.kind !== "step") throw new Error("expected K_t byte-slice leaf");
      const params = ktSlice.params as { readonly offset?: unknown };
      expect(params.offset).toBe(4 * t);
      seenIndices.add(t);
    }
    expect(seenIndices.size).toBe(64);
    for (let t = 0; t < 64; t++) expect(seenIndices.has(t)).toBe(true);
  });
});
