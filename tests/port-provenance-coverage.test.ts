/**
 * Port-provenance coverage contract (inspector-cell-hover plan, Slice 1,
 * 2026-06-04). The CI gate that turns "did I handle every port-native primitive"
 * from a manual audit into a failing test. Sibling of
 * `tests/narration-registry-contract.test.ts` — same fn-or-allowlist shape.
 *
 * **Scope = the universal bare-name port-native vocabulary** (registry types with
 * no `.` prefix: `xor@1`, `permute@1`, …). This is the cleanest mechanical reading
 * of "port-native step types reached by shipped specs": all four AES-round-body
 * primitives (`byte-substitute@1` / `permute@1` / `gf-matrix-multiply@1` /
 * `xor-with-aux@1`) are bare-name, so the scope covers 100% of the cell-hover's
 * primary target as a fixed ~20-entry set, while the ~35 prefixed cipher-specific
 * types (`des.*`, `serpent.*`, `speck.*`, `generic.*`, the key-schedule oracles)
 * stay out.
 *
 * **Known-uncovered, by design (fast-follow).** The bare-name scope deliberately
 * excludes the prefixed *exact* mappings — `des.xor-with-K@1` +
 * `serpent.add-round-key@1` (the `xor-with-aux` shape) and `serpent.sub-bytes@1`
 * (byte substitution). They could get exact fns; v1 draws the line at the
 * universal vocabulary. So this gate does NOT catch a future *prefixed*
 * port-native primitive — a documented choice, pinned by the last `it` below.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  PROVENANCE_FN_STEP_TYPES,
  PROVENANCE_NO_OP_ALLOWLIST,
  lookupProvenance,
} from "@/core/port-provenance";
import { describe, expect, it } from "vitest";

/** Bare-name = a port-native primitive in the universal vocabulary (no `cipher.`
 *  / `generic.` prefix). The step-type grammar is `name@N`, so the absence of a
 *  `.` is exactly the bare-name signal. */
const isBareName = (stepType: string): boolean => !stepType.includes(".");

describe("port-provenance coverage contract", () => {
  const registry = buildDefaultRegistry();
  const bareNameTypes = registry.types().filter(isBareName).sort();

  it("inventories a non-empty bare-name vocabulary (sanity check)", () => {
    expect(bareNameTypes.length).toBeGreaterThan(0);
  });

  it("every bare-name port-native step type has a provenance fn OR an allowlist entry", () => {
    const uncovered: string[] = [];
    for (const stepType of bareNameTypes) {
      const hasFn = lookupProvenance(stepType) !== undefined;
      const allowlisted = PROVENANCE_NO_OP_ALLOWLIST.has(stepType);
      if (!hasFn && !allowlisted) uncovered.push(stepType);
      // Crossed wires: a type both registered AND allowlisted means we said
      // "no meaningful provenance" while also writing a fn. Fail loudly.
      if (hasFn && allowlisted) {
        throw new Error(
          `step type "${stepType}" is BOTH provenance-registered AND on the no-op allowlist; pick one`,
        );
      }
    }
    if (uncovered.length > 0) {
      const bullets = uncovered.map((t) => `  - ${t}`).join("\n");
      throw new Error(
        `Provenance-coverage gap. These bare-name port-native step types have neither a provenance fn nor an allowlist entry:\n${bullets}\n\nFor each, either:\n  - Add an exact mapping fn in src/core/port-provenance.ts (register it in PROVENANCE_REGISTRY); OR\n  - Add the stepType to PROVENANCE_NO_OP_ALLOWLIST with a one-line rationale (approximate / no-inputs / partial-synthesis / exact-but-plumbing).`,
      );
    }
    expect(uncovered).toEqual([]);
  });

  it("the bare-name vocabulary is exactly fn-set ∪ allowlist (set-equality pin)", () => {
    // This is the gate's teeth: a NEW bare-name primitive lands in the registry
    // but neither set → this assertion fails until a conscious decision is made.
    // A STALE entry (in a set but dropped from the registry) also fails here.
    const covered = new Set<string>([...PROVENANCE_FN_STEP_TYPES, ...PROVENANCE_NO_OP_ALLOWLIST]);
    expect(new Set(bareNameTypes)).toEqual(covered);
  });

  it("fn-set and allowlist are disjoint", () => {
    for (const t of PROVENANCE_FN_STEP_TYPES) {
      expect(PROVENANCE_NO_OP_ALLOWLIST.has(t), `${t} is in both sets`).toBe(false);
    }
  });

  it("allowlist contents are exactly the expected 15 (rationale set-pin)", () => {
    // Grouped by the FOUR distinct rationales — see PROVENANCE_NO_OP_ALLOWLIST's
    // doc. Keeping the groups visible here stops a future edit from quietly
    // relabelling an exact-but-plumbing bridge as "approximate".
    const expected = new Set<string>([
      // approximate — an exact-looking byte highlight would mislead
      "add-mod-32@1",
      "add-mod-16@1",
      "rotate-bits-right@1",
      "shift-bits-right@1",
      // approximate — RSA big-integer arithmetic (carries/borrows mix all bytes)
      "mul@1",
      "sub@1",
      "mod-mul@1",
      "cond-mod-mul@1",
      "mod-inverse@1",
      // no inputs
      "constant-load@1",
      // partial — synthesizes bytes with no input source
      "pad-with-byte@1",
      "append-be64-length@1",
      // exact-but-plumbing — identity bridge, deferred as low-value
      "state-to-bytes@1",
      "bytes-to-state@1",
      "aux-load-bytes@1",
    ]);
    expect(PROVENANCE_NO_OP_ALLOWLIST).toEqual(expected);
  });

  it("does NOT cover the prefixed exact mappings (documented v1 fast-follow)", () => {
    // These are genuinely exact (xor-with-aux / byte-substitution shapes) but
    // cipher-prefixed, so out of the bare-name scope. Asserting they're uncovered
    // documents the choice — flip these to a fn + remove this assertion when the
    // fast-follow lands.
    for (const t of ["des.xor-with-K@1", "serpent.add-round-key@1", "serpent.sub-bytes@1"]) {
      expect(lookupProvenance(t), `${t} should be uncovered in v1`).toBeUndefined();
    }
  });
});
