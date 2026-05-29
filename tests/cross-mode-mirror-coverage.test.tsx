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
 *   - `aes.key-expansion@1` lives at the top level of canonical AES-128
 *     under id "key-expansion".
 *   - `aes.key-expansion@2` is the renumber variant — only appears
 *     after `duplicateRoundInSpec` bumps a round group. We trigger the
 *     duplicate against canonical round.1, then re-select "key-expansion"
 *     whose `type` field is now `@2`.
 *   - `serpent.sub-bytes@1` requires switching to Serpent-128 first;
 *     `round.1.sub-bytes` is a stable leaf id (S_0).
 *   - `generic.byte-substitution@1` is the AES SubBytes step type; any
 *     `round.N.sub-bytes` leaf works on canonical AES-128.
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
import { __resetSpecForTests, duplicateRoundInSpec, setCipher, useSpec } from "@/ui/stores/spec";
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

// Find the first leaf in the live spec of the given type. Returns the
// leaf's id, or null if none exists. Used to look up a v2 key-expansion
// leaf after `duplicateRoundInSpec` morphs the canonical v1 leaf in
// place — we don't hard-code "key-expansion" for that case because the
// mutator's id-stability is an implementation detail.
type Node = {
  kind: string;
  id?: string;
  type?: string;
  children?: readonly Node[];
};
const findFirstLeafIdOfType = (stepType: string): string | null => {
  const spec = useSpec()();
  let found: string | null = null;
  const visit = (nodes: readonly Node[]): void => {
    for (const n of nodes) {
      if (found !== null) return;
      if (n.kind === "step" && n.type === stepType && typeof n.id === "string") {
        found = n.id;
        return;
      }
      if ((n.kind === "group" || n.kind === "iterate") && n.children) {
        visit(n.children);
      }
    }
  };
  visit(spec.steps as readonly Node[]);
  return found;
};

// Per-entry setup. Returns the leaf id to select, or throws with a
// descriptive message if the entry's prerequisite isn't satisfiable
// (e.g. v2 needs a successful duplicateRoundInSpec).
const setupForEntry = (entry: CrossModeMirrorEntry): string => {
  switch (entry.stepType) {
    case "generic.byte-substitution@1": {
      // AES-128 single-block ENCRYPT is byte-native as of Slice B1, so its
      // `round.1.sub-bytes` leaf is now `byte-substitute@1` — NOT this
      // type. The legacy matrix `generic.byte-substitution@1` still ships
      // on every un-converted AES spec (AES-192/256 both modes, AES-128
      // decrypt, ECB/CBC), so pick a still-matrix cipher to exercise this
      // entry's button. AES-192 keeps the stable `round.1.sub-bytes` id.
      // (The byte-native `byte-substitute@1` mirror entry lands in B1.2,
      // when decrypt is ALSO byte-native and the same-type mutator works
      // end-to-end — adding it in B1 would ship a no-op sync button.)
      setCipher("aes-192");
      return "round.1.sub-bytes";
    }
    case "generic.mix-columns@1": {
      // Same as above: AES-128 single-block encrypt MixColumns is now
      // `gf-matrix-multiply@1` (byte-native). AES-192 is still matrix and
      // round 1 always has a MixColumns leaf (FIPS-197: every round except
      // the final). Same step type on both AES-192 encrypt/decrypt specs.
      setCipher("aes-192");
      return "round.1.mix-columns";
    }
    case "aes.key-expansion@1": {
      // Top-level leaf on canonical AES-128.
      return "key-expansion";
    }
    case "aes.key-expansion@2": {
      // v2 only appears after a round duplicate. Trigger on round.1,
      // then look up whatever leaf id ends up carrying the @2 type.
      // (Today it's still "key-expansion" — the mutator preserves the
      // id and only bumps `rounds` + the `type` suffix — but we don't
      // hard-code that.)
      duplicateRoundInSpec("round.1");
      const id = findFirstLeafIdOfType("aes.key-expansion@2");
      if (!id) {
        throw new Error(
          "Test setup failure: duplicateRoundInSpec did not produce an aes.key-expansion@2 leaf",
        );
      }
      return id;
    }
    case "serpent.sub-bytes@1": {
      // Serpent-128 canonical. `round.1.sub-bytes` has sboxIndex=0
      // (S_{(r-1) mod 8} for r=1 → S_0).
      setCipher("serpent-128");
      return "round.1.sub-bytes";
    }
    case "byte-substitute@1": {
      // Byte-native AES SubBytes (Slice B1.2). AES-128 single-block is the
      // app default and byte-native on BOTH modes now, so `round.1.sub-bytes`
      // is `byte-substitute@1` with no `setCipher` needed. The sync writes to
      // the byte-native decrypt counterpart.
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
