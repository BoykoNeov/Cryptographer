// @vitest-environment jsdom

/**
 * Component test for `<StepNarration />`. Mounts the component with an
 * AES SubBytes frame, asserts 16 `<details>` render with the right
 * summaries, and verifies that toggling the byte format updates prose
 * text inside the open disclosures WITHOUT recreating the `<details>`
 * elements (which would snap them shut).
 *
 * The `<details>` open-state preservation across format toggles is the
 * core reactivity contract the per-frame narration design depends on.
 * If a regression there ever lands, this test catches it.
 */

import type { AuxValue, TraceFrame } from "@/core/types";
import { StepNarration } from "@/ui/components/StepNarration";
import "@/ui/narration/index"; // eagerly register Phase 1 narrators
import { __resetByteFormatForTests, setByteFormat } from "@/ui/stores/format";
import { cleanup, render } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// Serpent SubBytes is the surviving 16-unit per-byte narrator used to
// exercise StepNarration's component-level behavior (one disclosure per
// byte, open-state preservation across format toggle + frame-reference
// swap). The matrix AES SubBytes narrator that originally drove these tests
// retired in Phase 5 Slice 5.1 (2026-05-30) with the MatrixState shape.
const makeSubBytesFrame = (): TraceFrame => {
  const before = new Uint8Array(16);
  for (let i = 0; i < 16; i++) before[i] = i * 17;
  // The narrator derives its prose from the before/after bytes alone, so an
  // identity after-state is sufficient for the structural tests below.
  const after = new Uint8Array(before);
  return {
    index: 0,
    path: [],
    stepId: "test.sub-bytes",
    stepType: "serpent.sub-bytes@1",
    params: {},
    // The Serpent SubBytes narrator reads before/after off the `"state"` port
    // via frameStateInBytes / frameStateOutBytes (the stateBefore/stateAfter
    // State fields retired in Slice 5.3e Batch 4).
    portInputs: new Map([["state", before]]),
    portOutputs: new Map([["state", after]]),
    auxRead: new Map<string, AuxValue>(),
    auxWritten: new Map(),
  };
};

describe("StepNarration — Serpent SubBytes frame", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("renders 16 <details> elements, one per byte", () => {
    const frame = makeSubBytesFrame();
    const { container } = render(() => <StepNarration frame={frame} />);
    const details = container.querySelectorAll(".step-narration-unit");
    expect(details.length).toBe(16);
    // Spot-check summaries (Serpent's BytesState narrator labels by linear
    // byte index, no row/col; sboxIndex omitted → no "(uses S_N)" suffix).
    expect(details[0]?.querySelector("summary")?.textContent).toBe("byte 0");
    expect(details[5]?.querySelector("summary")?.textContent).toBe("byte 5");
    expect(details[15]?.querySelector("summary")?.textContent).toBe("byte 15");
  });

  it("preserves <details> open state across byte-format toggle", () => {
    const frame = makeSubBytesFrame();
    const { container } = render(() => <StepNarration frame={frame} />);
    // Open the second disclosure.
    const target = container.querySelector(
      '.step-narration-unit[data-key="byte:1"]',
    ) as HTMLDetailsElement | null;
    expect(target).not.toBeNull();
    if (!target) return;
    target.open = true;
    expect(target.open).toBe(true);
    // Capture the element reference to confirm it isn't recreated.
    const originalElement = target;
    // Toggle format → decimal.
    setByteFormat("decimal");
    // The same element should still exist, still be open.
    const after = container.querySelector(
      '.step-narration-unit[data-key="byte:1"]',
    ) as HTMLDetailsElement | null;
    expect(after).toBe(originalElement);
    expect(after?.open).toBe(true);
    // Prose body should now contain decimal-formatted byte values.
    const proseText = after?.querySelector(".step-narration-unit-prose")?.textContent ?? "";
    // byte 1 = 17 in decimal; the S-box lookup result is AES_SBOX[17].
    expect(proseText).toContain("17");
  });

  it("renders nothing for allowlisted step types", () => {
    const frame: TraceFrame = {
      ...makeSubBytesFrame(),
      stepType: "aes.key-expansion@1",
    };
    const { container } = render(() => <StepNarration frame={frame} />);
    expect(container.querySelector(".step-narration")).toBeNull();
  });

  it("preserves <details> open state when the frame REFERENCE changes (re-run path)", () => {
    // Regression: the App's createEffect at App.tsx:680 fires a 200ms
    // debounced re-run on byte-format toggle (via inputText change), which
    // produces a new TraceFrame object with the SAME stepId but a fresh
    // reference. With <For> keyed by item-reference, every NarrationUnit
    // was treated as "new" (new closures per re-run), and every <details>
    // was unmounted + recreated — destroying the browser's open state.
    // <Index> keys by position, so the <details> at byte-N persists
    // across the swap. This test simulates the path by feeding the
    // component two distinct frame objects with identical content.
    const [frameSignal, setFrame] = createSignal(makeSubBytesFrame());
    const { container } = render(() => <StepNarration frame={frameSignal()} />);
    const target = container.querySelector(
      '.step-narration-unit[data-key="byte:1"]',
    ) as HTMLDetailsElement | null;
    expect(target).not.toBeNull();
    if (!target) return;
    target.open = true;
    const originalElement = target;
    // Simulate a re-run: build a new frame object with the same content
    // and stepId. With <For>, the old <details> would unmount and the
    // open state would be lost. With <Index>, the element persists.
    setFrame(makeSubBytesFrame());
    const after = container.querySelector(
      '.step-narration-unit[data-key="byte:1"]',
    ) as HTMLDetailsElement | null;
    expect(after).toBe(originalElement);
    expect(after?.open).toBe(true);
  });
});
