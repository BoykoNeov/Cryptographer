/**
 * SHA-256 narrationOverride coverage test — universal-port plan Phase 2
 * Slice 2.8 (2026-05-26).
 *
 * Slice 2.8's pass/fail gate per `docs/plans/universal-port-phase-2-slices.md`:
 *
 *   > Every SHA-256 leaf renders cipher-specific narration in
 *   > `<StepDescription>` (manual browser smoke + unit test walking the
 *   > spec asserting `narrationOverride` is non-null on every leaf).
 *
 * This file is the unit-test half of that gate. The walker recurses
 * `buildSha256Spec().steps` through every container kind (group,
 * iterate, for-each-subgraph, for-each-subgraph-with-history,
 * feistel-round) and asserts:
 *
 *   1. Every `kind: "step"` node carries a `narrationOverride`.
 *   2. Each override has non-empty `name`, `summary`, `detail`.
 *   3. Each override carries at least one `FIPS 180-4` reference.
 *
 * **Presence-only.** This test cannot verify prose CORRECTNESS — a
 * copy-paste typo in a FIPS section number, or a swapped Σ0/Σ1 constant
 * in the prose itself, would pass this gate. Content correctness is
 * the manual-browser-smoke half of Slice 2.8's gate.
 *
 * **Reference-sharing tracked separately.** The 28 compression-round
 * roles each have ONE prose object that's shared by reference across
 * all 64 rounds (saves memory, intentional per Slice 2.8 advisor
 * pre-consult; safe because `narrationOverride` is read-only). One
 * extra assertion at the bottom of the file verifies this sharing —
 * the test counts distinct override identities across rounds and
 * asserts the count equals the number of distinct roles (28), not
 * 64×28.
 */

import { buildSha256Spec } from "@/ciphers/sha-256";
import type { StepDocumentation, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

/**
 * Recursive walker: yields every `kind: "step"` leaf under a node,
 * descending into every container kind that holds children.
 */
function* walkLeaves(node: StepNode): Generator<StepNode & { kind: "step" }> {
  if (node.kind === "step") {
    yield node;
    return;
  }
  if (
    node.kind === "group" ||
    node.kind === "iterate" ||
    node.kind === "for-each-subgraph" ||
    node.kind === "for-each-subgraph-with-history"
  ) {
    for (const child of node.children) {
      yield* walkLeaves(child);
    }
    return;
  }
  if (node.kind === "feistel-round") {
    for (const track of node.tracks) {
      for (const child of track.children) {
        yield* walkLeaves(child);
      }
    }
    return;
  }
}

const spec = buildSha256Spec();
const leaves = [...spec.steps.flatMap((s) => [...walkLeaves(s)])];

describe("SHA-256 narrationOverride coverage (Slice 2.8)", () => {
  it("spec produces at least one leaf (sanity)", () => {
    // After Slice 2.6d's decomposition the spec contains:
    //   - 4 preprocessing leaves
    //   - 14 schedule-body leaves (defined ONCE in the FES body — the
    //     runtime instantiates them 48 times, but they appear once in
    //     the spec tree)
    //   - 3 aux setup + 2 init = 5 leaves
    //   - 64 compression rounds × 28 leaves = 1792 leaves
    //   - 14 final-add leaves (state-in, split-wv, fetch-H, split-H,
    //     8 × s_i, assemble, out)
    //   = 1829 leaves in the spec tree.
    expect(leaves.length).toBe(1829);
  });

  it("every leaf carries a non-null narrationOverride", () => {
    const missing = leaves.filter((l) => l.narrationOverride === undefined);
    // Build a small diagnostic if any leaves miss the override — surfaces
    // exactly which step IDs are not annotated.
    expect(missing.map((l) => l.id)).toEqual([]);
  });

  it("every override has a non-empty name, summary, and detail", () => {
    const malformed: string[] = [];
    for (const leaf of leaves) {
      const doc = leaf.narrationOverride;
      if (doc === undefined) continue; // caught by the prior assertion
      if (!doc.name || doc.name.length === 0) malformed.push(`${leaf.id}: empty name`);
      if (!doc.summary || doc.summary.length === 0) malformed.push(`${leaf.id}: empty summary`);
      if (!doc.detail || doc.detail.length === 0) malformed.push(`${leaf.id}: empty detail`);
    }
    expect(malformed).toEqual([]);
  });

  it("every override carries at least one FIPS 180-4 reference", () => {
    const noRef: string[] = [];
    for (const leaf of leaves) {
      const doc = leaf.narrationOverride;
      if (doc === undefined) continue;
      const refs = doc.references ?? [];
      if (refs.length === 0) {
        noRef.push(`${leaf.id}: no references`);
        continue;
      }
      // At least one reference must mention FIPS 180-4 (the SHA-256 spec).
      // Prose authors might cite other standards too but the SHA-256
      // citation MUST be present so the user can trace the formula back.
      if (!refs.some((r) => r.includes("FIPS 180-4"))) {
        noRef.push(`${leaf.id}: no FIPS 180-4 reference (refs=${refs.join("; ")})`);
      }
    }
    expect(noRef).toEqual([]);
  });

  it("compression-round overrides are shared by reference across all 64 rounds", () => {
    // The 28 distinct round-body roles each have ONE prose object that's
    // attached to all 64 rounds' instantiations. Verify this by counting
    // distinct override identities across the rounds: should be 28
    // (one per role), not 64×28 = 1792.
    //
    // We identify "round leaves" by their id prefix `round.<t>.<role>` —
    // strip the `round.<t>.` prefix and group leaves by role.
    const roundLeaves = leaves.filter((l) => /^round\.\d+\./.test(l.id));
    expect(roundLeaves.length).toBe(64 * 28);

    const distinctOverrides = new Set<StepDocumentation>();
    for (const leaf of roundLeaves) {
      // narrationOverride is non-null by the earlier assertion; guard
      // defensively so this assertion's failure mode is clean.
      if (leaf.narrationOverride !== undefined) distinctOverrides.add(leaf.narrationOverride);
    }
    expect(distinctOverrides.size).toBe(28);
  });

  it("schedule-body overrides are defined once (not duplicated across iterations)", () => {
    // The FES-with-history body is defined ONCE in the spec tree — the
    // runtime expands it 48 times at runtime, but the spec tree contains
    // exactly 14 schedule-body leaves. This assertion pins that — if a
    // future refactor accidentally unrolled the body into the spec tree,
    // the leaf count would jump and we'd want to know.
    const schedLeaves = leaves.filter((l) =>
      [
        "fetch-p2",
        "fetch-p7",
        "fetch-p15",
        "fetch-p16",
        "sigma1-r17",
        "sigma1-r19",
        "sigma1-s10",
        "sigma1",
        "sigma0-r7",
        "sigma0-r18",
        "sigma0-s3",
        "sigma0",
        "w-t",
        "schedule-out",
      ].includes(l.id),
    );
    expect(schedLeaves.length).toBe(14);
  });
});
