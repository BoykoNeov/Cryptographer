// @vitest-environment jsdom

/**
 * jsdom tests for the Phase 5 duplicate-round button in the graph view.
 *
 * The button is a small `+` chip in the container's header band, mirror
 * of the existing × delete affordance. It's rendered only on AES round
 * groups whose auto-mirror has a clean landing site on the counterpart
 * side — `isRoundDuplicatable` is the gate.
 *
 * Properties pinned here:
 *   1. Button renders for `round.1..round.9` in canonical AES-128
 *      encrypt (every full round, plus the penultimate one with a
 *      higher-numbered sibling).
 *   2. Button does NOT render for `round.10` (the final no-MixColumns
 *      round; auto-mirror to `inv-round.10` would fail).
 *   3. Clicking the button fires `duplicateRoundInSpec`, which grows
 *      the spec from 10 rounds to 11.
 *   4. After a duplicate, the button now renders on `round.10` too
 *      (because `round.11` is the new final).
 *
 * Companion mode-flip behavior is covered in
 * `tests/duplicate-round-store.test.ts` — this file scopes to the UI
 * affordance only.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  // Byte-native AES-128 (Slice B1): flat BytesState in, ported dispatch on.
  const registry = buildDefaultRegistry();
  const trace = runSpec(aes128Spec, registry, {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
  __resetLayoutsForTests();
};

const findDuplicateButton = (container: HTMLElement, containerId: string): Element | null =>
  container.querySelector(`[data-testid="graph-duplicate-${containerId}"]`);

const countRoundGroups = (container: HTMLElement): number => {
  // The graph view emits one `graph-container-header-round.{N}` per
  // round group, plus matching iterate/header testids. Counting the
  // round-header testids is the cleanest "how many rounds rendered."
  const headers = container.querySelectorAll('[data-testid^="graph-container-header-round."]');
  // Filter out the inv-round headers (decrypt view) — they share the
  // "round." prefix in the matcher.
  return Array.from(headers).filter(
    (h) => !(h.getAttribute("data-testid") ?? "").startsWith("graph-container-header-inv-round"),
  ).length;
};

describe("GraphView — Phase 5 duplicate-round button", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders the duplicate button on round.1 through round.9 (canonical AES-128)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    for (let n = 1; n <= 9; n++) {
      expect(findDuplicateButton(container, `round.${n}`)).not.toBeNull();
    }
  });

  it("does NOT render the duplicate button on round.10 (the canonical final round)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // round.10 is the final round in canonical AES-128 (no-MixColumns,
    // no `round.11` sibling) — `isRoundDuplicatable` returns false so
    // no button renders.
    expect(findDuplicateButton(container, "round.10")).toBeNull();
  });

  it("clicking the button on round.2 grows the spec from 10 to 11 round groups", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    expect(countRoundGroups(container)).toBe(10);

    const button = findDuplicateButton(container, "round.2");
    expect(button).not.toBeNull();
    // The button itself is an SVG <g>. fireEvent.click bubbles through.
    fireEvent.click(button as Element);

    expect(countRoundGroups(container)).toBe(11);
  });

  it("after a duplicate, the new penultimate round (was round.10, now round.11 final) has its button suppressed; the new round.10 has its button shown", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const button = findDuplicateButton(container, "round.5");
    expect(button).not.toBeNull();
    fireEvent.click(button as Element);

    // Old round.10 has been renumbered to round.11 (the new final).
    expect(findDuplicateButton(container, "round.11")).toBeNull();
    // The new round.10 is what was round.9 — it's now penultimate and
    // duplicatable.
    expect(findDuplicateButton(container, "round.10")).not.toBeNull();
  });
});
