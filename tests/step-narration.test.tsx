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

import { AES_SBOX } from "@/ciphers/aes-constants";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, TraceFrame } from "@/core/types";
import { StepNarration } from "@/ui/components/StepNarration";
import "@/ui/narration/index"; // eagerly register Phase 1 narrators
import { __resetByteFormatForTests, setByteFormat } from "@/ui/stores/format";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const makeSubBytesFrame = (): TraceFrame => {
  const before = new Uint8Array(16);
  for (let i = 0; i < 16; i++) before[i] = i * 17;
  const after = new Uint8Array(16);
  for (let i = 0; i < 16; i++) after[i] = AES_SBOX[before[i] ?? 0] ?? 0;
  return {
    index: 0,
    path: [],
    stepId: "test.sub-bytes",
    stepType: "generic.byte-substitution@1",
    params: { sbox: [...AES_SBOX] },
    stateBefore: matrixFromBytes(before),
    stateAfter: matrixFromBytes(after),
    auxRead: new Map<string, AuxValue>(),
    auxWritten: new Map(),
  };
};

describe("StepNarration — AES SubBytes frame", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("renders 16 <details> elements, one per cell", () => {
    const frame = makeSubBytesFrame();
    const { container } = render(() => <StepNarration frame={frame} />);
    const details = container.querySelectorAll(".step-narration-unit");
    expect(details.length).toBe(16);
    // Spot-check summaries.
    expect(details[0]?.querySelector("summary")?.textContent).toBe("byte 0 (row 0, col 0)");
    expect(details[5]?.querySelector("summary")?.textContent).toBe("byte 5 (row 1, col 1)");
    expect(details[15]?.querySelector("summary")?.textContent).toBe("byte 15 (row 3, col 3)");
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
});
