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
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const runSha256 = (plaintext: Uint8Array): Uint8Array => {
  const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: plaintext },
    portedDispatchEnabled: true,
  });
  if (trace.finalState.shape !== "bytes") {
    throw new Error(`expected bytes finalState, got ${trace.finalState.shape}`);
  }
  return trace.finalState.bytes;
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
    // Frame budget for single-block run under the Slice 2.6d decomposed
    // topology (every algorithmic sub-step is now a visible chip):
    //   - 4 preprocessing leaves: plaintext-source + pad + length-append
    //     + seed-schedule
    //   - 14 schedule body leaves × 48 iterations = 672 frames
    //     (aux-load ×4 + σ1 chain ×4 + σ0 chain ×4 + W_t 4-way add
    //     + bytes-to-state)
    //   - 5 between-phases leaves: W-publish + K-to-aux + H-to-aux
    //     + H-constant + init-working-vars
    //   - 28 leaves × 64 compression rounds = 1792 frames
    //     (state-to-bytes + split-bytes + 2×(aux-load-bytes + byte-slice)
    //     + Σ1 ×4 + Σ0 ×4 + Ch ×4 + Maj ×4 + T1 + T2 + new_a + new_e
    //     + concat + bytes-to-state)
    //   - 13 final-add leaves: state-to-bytes + split-bytes + aux-load-bytes
    //     + split-bytes + 8×add-mod-32 + concat + bytes-to-state
    //   - +1 from runtime control flow (FES outer accounting)
    //
    // Total: 4 + 672 + 5 + 1792 + 13 + 1 = 2487 frames
    //
    // Pre-2.6d (coarse helpers): 123 frames. Pedagogy payoff: ~20× more
    // frames means every ROTR, every XOR, every modular add is visible.
    const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
      portedDispatchEnabled: true,
    });
    expect(trace.frames).toHaveLength(2487);
  });

  it("finalState is always 32 bytes BytesState (the hash)", () => {
    const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
      portedDispatchEnabled: true,
    });
    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") throw new Error("unreachable");
    expect(trace.finalState.bytes.length).toBe(32);
  });

  it("aux['H'] and aux['K'] survive end-to-end in finalAux (loaded via aux-load, never deleted)", () => {
    const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
      portedDispatchEnabled: true,
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

  it("spec has 64 compression round groups", () => {
    const spec = buildSha256Spec();
    const rounds = spec.steps.filter((s) => s.kind === "group" && /^round\.\d+$/.test(s.id));
    expect(rounds).toHaveLength(64);
  });

  it("validateShapes finds zero warnings on the SHA-256 spec", async () => {
    const { validateShapes } = await import("@/core/spec-shapes");
    const warnings = validateShapes(buildSha256Spec(), buildDefaultRegistry());
    expect(warnings).toEqual([]);
  });

  // Under the Slice 2.6d decomposed topology, each round group no longer
  // wraps a single `sha2.compression-round@1` leaf with `roundIndex` param
  // — it wraps 28 leaves (state-to-bytes, split-bytes, Σ0/Σ1/Ch/Maj
  // chains, T1/T2 adds, concat, bytes-to-state). The pin updates from
  // "single leaf carries roundIndex" to "28 leaves per group, each
  // round's K_t byte-slice carries offset = 4 * t". The byte-slice
  // offset is the load-bearing per-round disambiguator in the decomposed
  // form — different rounds extract from different positions in K and W.
  it("each compression-round group has 28 leaves with K_t offset = 4 * t", () => {
    const spec = buildSha256Spec();
    const seenIndices = new Set<number>();
    for (const step of spec.steps) {
      if (step.kind !== "group") continue;
      const m = /^round\.(\d+)$/.exec(step.id);
      if (m === null) continue;
      const t = Number.parseInt(m[1] as string, 10);
      expect(step.children).toHaveLength(28);
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
