// @vitest-environment jsdom

/**
 * **Architectural-invariant enumeration test.** Walks every entry in
 * `CROSS_MODE_MIRROR_ENTRIES` and asserts that selecting a step of the
 * named type makes `ParamEditor` render a button carrying
 * `data-mirror-class="{class}"`.
 *
 * The principle this test locks in (from `CLAUDE.md` → "Cross-mode
 * mirror buttons"): every class-1 (identity-mirrored) or class-2
 * (inverse-mirrored) step type ships with an opt-in, labelled Sync/Copy
 * button below its editor. Without this test, a new cipher addition
 * could silently drop the button — the principle would rot to prose.
 *
 * When this test fails, the error message identifies BOTH the missing
 * step type AND the expected mirror class so the fix path is obvious:
 * either add the button to `ParamEditor.tsx` (most common — the
 * registry entry is the canonical "this needs a button" list) or
 * remove the entry from the registry (if the relationship genuinely
 * no longer applies, e.g. a step type was deprecated).
 *
 * Per-step setup notes:
 *   - Entries carrying a `leafScope` (today: both `byte-substitute@1`
 *     roles) are selected via `leafScope.sampleLeafId` — round-body
 *     SubBytes at `round.1.sub-bytes` (inverse) and the decomposed
 *     key-schedule SubWord at `key-schedule.g1.subword` (identity). Both
 *     live on the default byte-native AES-128 spec.
 *   - `serpent.sub-bytes@1` requires switching to Serpent-128 first;
 *     `round.1.sub-bytes` is a stable leaf id (S_0).
 *   - `gf-matrix-multiply@1` is byte-native AES MixColumns; `round.1.mix-columns`
 *     works on canonical AES-128.
 *
 * The per-S-box-index Serpent semantic (`groupBy: "sboxIndex"`) is NOT
 * asserted by this enumeration test — a single Sync button on the
 * leaf is sufficient to pass the "button exists" check. The per-index
 * propagation contract is pinned separately by
 * `tests/sync-serpent-sbox-inverse.test.ts`.
 */

import { App } from "@/ui/App";
import {
  CROSS_MODE_MIRROR_ENTRIES,
  type CrossModeMirrorEntry,
} from "@/ui/components/cross-mode-mirror-registry";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipher } from "@/ui/stores/spec";
import { __resetTraceForTests, setSelectedStepId } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetHistoryForTests();
  __resetLayoutsForTests();
  __resetPaddingForTests();
  __resetReplicationForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetViewModeForTests();
};

// Per-entry setup. Returns the leaf id to select, or throws with a
// descriptive message if the entry's prerequisite isn't satisfiable.
const setupForEntry = (entry: CrossModeMirrorEntry): string => {
  // Role-scoped entries carry their own canonical sample leaf id. Since the
  // key-schedule decomposition (2026-06-01), `byte-substitute@1` has TWO
  // entries — round-body SubBytes (inverse, `round.1.sub-bytes`) and
  // key-schedule SubWord (identity, `key-schedule.g1.subword`) — that the
  // stepType switch alone can't tell apart, so `leafScope.sampleLeafId` is
  // the disambiguator. Both live on the default byte-native AES-128 spec,
  // no `setCipher` needed.
  if (entry.leafScope) {
    return entry.leafScope.sampleLeafId;
  }
  switch (entry.stepType) {
    // NOTE: the matrix `generic.byte-substitution@1` + `generic.mix-columns@1`
    // cases were removed in Slice B1.4b; the monolithic `aes.key-expansion@1/@2`
    // identity cases were removed in key-schedule-decomposition K1c (the Copy
    // affordance re-homed onto the SubWord `byte-substitute@1` leaf above).
    case "serpent.sub-bytes@1": {
      // Serpent-128 canonical. `round.1.sub-bytes` has sboxIndex=0
      // (S_{(r-1) mod 8} for r=1 → S_0).
      setCipher("serpent-128");
      return "round.1.sub-bytes";
    }
    case "gf-matrix-multiply@1": {
      // Byte-native AES MixColumns (Slice B1.2). Default AES-128, round 1
      // always has a MixColumns leaf (every round except the final).
      return "round.1.mix-columns";
    }
    default:
      throw new Error(
        `cross-mode-mirror-coverage: unhandled stepType ${entry.stepType} — add a setup branch for it`,
      );
  }
};

// Find a button carrying the expected data-mirror-class. Scoped to the
// ParamEditor's container by class — the graph view's data attributes
// could in principle collide otherwise.
const findMirrorButton = (root: HTMLElement, mirrorClass: string): HTMLButtonElement | null =>
  root.querySelector(
    `.param-editor button[data-mirror-class="${mirrorClass}"]`,
  ) as HTMLButtonElement | null;

describe("cross-mode-mirror-coverage — every registered (stepType, paramKey, class) pair has a button", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  // Sanity check on the registry itself: we want at least one entry per
  // mirror class so the test exercises both code paths. A future change
  // that empties the identity branch (e.g. removing key-expansion) should
  // either drop this sanity assertion or replace it with the new entry.
  it("registry has both identity and inverse entries", () => {
    const classes = new Set(CROSS_MODE_MIRROR_ENTRIES.map((e) => e.mirrorClass));
    expect(classes.has("identity")).toBe(true);
    expect(classes.has("inverse")).toBe(true);
  });

  // describe.each-style fan-out via a plain for-loop so the failure
  // message names the offending entry. vitest's `it` accepts dynamic
  // titles, which is what makes the failure mode legible:
  //   "FAIL  aes.key-expansion@2 (identity) — Sync/Copy button missing"
  for (const entry of CROSS_MODE_MIRROR_ENTRIES) {
    it(`${entry.stepType} (${entry.mirrorClass}) renders a button with data-mirror-class="${entry.mirrorClass}"`, async () => {
      const { container } = render(() => <App />);

      const leafId = setupForEntry(entry);
      setSelectedStepId(leafId);

      // The KeyExpansion S-box and its Copy button sit inside a
      // <details> that is collapsed by default. The button is still
      // in the DOM (just not visible to the user), so a CSS-attribute
      // query finds it.
      await waitFor(() => {
        const btn = findMirrorButton(container, entry.mirrorClass);
        if (!btn) {
          throw new Error(
            `Step type "${entry.stepType}" is registered with mirrorClass="${entry.mirrorClass}" but no <button data-mirror-class="${entry.mirrorClass}"> rendered in the ParamEditor when ${leafId} was selected. Fix: either add the button to src/ui/components/ParamEditor.tsx (most common — the registry is the canonical "needs a button" list), or remove the entry from src/ui/components/cross-mode-mirror-registry.ts if the relationship no longer applies.`,
          );
        }
      });

      const btn = findMirrorButton(container, entry.mirrorClass);
      expect(btn).not.toBeNull();
      // The button must be a real, click-receiving <button> — not a
      // <div role="button"> hack — so the ActionButton flash + aria-live
      // primitive works.
      expect(btn?.tagName).toBe("BUTTON");
    });
  }
});
