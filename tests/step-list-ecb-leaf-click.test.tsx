// @vitest-environment jsdom

/**
 * Regression test for the ECB-mode "leaf disabled" bug surfaced during the
 * Phase-3 narration smoke (2026-05-18).
 *
 * StepList renders one button per spec leaf and uses the leaf's `id` to
 * locate the corresponding trace frame. In multi-block modes (ECB / CBC)
 * the runtime suffixes per-iteration stepIds with `:b{i}` (see
 * `runtime.ts:129`), so the unsuffixed spec id never appears as a frame
 * stepId. The pre-fix lookup `frameIndexByStepId.get(node.id)` returned
 * undefined → every leaf inside the iterate body rendered with
 * `disabled` and the user couldn't click to jump.
 *
 * The fix in `StepList.tsx` also maps the unsuffixed prefix → first
 * matching frame (block 0) AND strips the suffix when computing
 * `activeAncestors`, so the leaf both clicks AND highlights correctly.
 *
 * This test pins the behaviour:
 *   - All iterate-body leaves render as enabled, clickable buttons.
 *   - Clicking one moves the scrubber to the matching block-0 frame.
 *   - When the scrubber points at a `:b{2}` frame, the corresponding
 *     leaf renders as active (its `.active` class is applied).
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { StepList } from "@/ui/components/StepList";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setFrame, setTrace, useFrameIndex } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
// 4-block plaintext (NIST SP 800-38A §F.1.1) → 4 ECB iterations.
const PT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

const seedTrace = () => {
  setCipherMode("ecb");
  const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
    // Byte-native ECB (B1.4) — port-native body needs ported dispatch.
  });
  setTrace(trace);
  return trace;
};

beforeEach(() => {
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetTraceForTests();
});

afterEach(() => {
  cleanup();
});

/**
 * Position the scrubber on a round-body frame so the surrounding
 * groups auto-expand and the leaves we want to assert against are
 * actually in the DOM. Without this, `step-tree` only renders the
 * collapsed root-level rows (key-expansion, split-blocks, the iterate
 * header, …) plus the active ancestors' expansions — the round leaves
 * stay hidden behind closed `.group-row` buttons.
 */
const scrubToRound1SubBytes = (trace: ReturnType<typeof seedTrace>): void => {
  const f = trace.frames.find((fr) => fr.stepId === "round.1.sub-bytes:b0");
  if (!f) throw new Error("test fixture: round.1.sub-bytes:b0 not in trace");
  setFrame(f.index);
};

describe("StepList — ECB iterate-body leaves are clickable", () => {
  it("renders the iterate-body leaves as enabled buttons (not disabled)", () => {
    const trace = seedTrace();
    scrubToRound1SubBytes(trace);
    const { container } = render(() => <StepList />);

    // The SubBytes leaf inside round 1 lives at spec id
    // `round.1.sub-bytes`. Before the fix this rendered
    // disabled because no frame had that exact stepId — every frame
    // emitted as `…:b0`, `…:b1`, `…:b2`, `…:b3`.
    const buttons = Array.from(
      container.querySelectorAll("button.step-row"),
    ) as HTMLButtonElement[];
    expect(buttons.length).toBeGreaterThan(0);

    // Find at least one iterate-body leaf — its title attr is the spec
    // leaf id (e.g. `round.1.sub-bytes`). The iterate node itself has
    // id `ecb-blocks`; children inside it keep their unsuffixed ids and
    // the runtime adds `:b{i}` only when emitting frames.
    // Pre-fix: every match would be disabled.
    const iterateBodyLeaves = buttons.filter((b) => {
      const t = b.getAttribute("title") ?? "";
      return /^(initial|round)\./.test(t);
    });
    expect(iterateBodyLeaves.length).toBeGreaterThan(0);
    for (const b of iterateBodyLeaves) {
      expect(b.disabled).toBe(false);
    }
  });

  it("clicking an iterate-body leaf jumps to its block-0 frame", () => {
    const trace = seedTrace();
    // Scrub to a round-1 frame first so the iterate + round groups are
    // expanded, then move OFF (back to frame 0 / key-expansion) before
    // we click — the test wants to assert that the click DOES move the
    // scrubber, so the pre-click position needs to differ from block 0.
    scrubToRound1SubBytes(trace);
    const { container } = render(() => <StepList />);
    setFrame(0); // key-expansion frame; round groups stay expanded

    // Find the SubBytes leaf inside round 1 by its title attribute.
    const target = Array.from(container.querySelectorAll("button.step-row")).find((b) => {
      const t = b.getAttribute("title") ?? "";
      return t.startsWith("round.1.sub-bytes");
    }) as HTMLButtonElement | undefined;
    expect(target).toBeDefined();
    if (!target) return;

    fireEvent.click(target);

    // Should land on the block-0 frame for that step id. Pre-fix the
    // lookup returned undefined and the click was a no-op (frameIndex
    // unchanged).
    const newFrame = trace.frames[useFrameIndex()()];
    expect(newFrame).toBeDefined();
    expect(newFrame?.stepId).toBe("round.1.sub-bytes:b0");
    expect(newFrame?.blockIndex).toBe(0);
  });

  it("scrubbing to a `:b{N>0}` frame highlights the corresponding leaf", () => {
    const trace = seedTrace();
    const { container } = render(() => <StepList />);

    // Find the frame index for round 1 SubBytes in block 2.
    const targetFrame = trace.frames.find((f) => f.stepId === "round.1.sub-bytes:b2");
    expect(targetFrame).toBeDefined();
    if (!targetFrame) return;
    setFrame(targetFrame.index);

    // The leaf for `round.1.sub-bytes` should carry the
    // `.active` class even though its `frameIdx` resolves to block-0's
    // frame (the current frame is block 2). Pre-fix this required
    // strict `frameIdx === activeFrameIndex` equality, which never
    // matched on `:b{N>0}` frames.
    const target = Array.from(container.querySelectorAll("button.step-row")).find((b) => {
      const t = b.getAttribute("title") ?? "";
      return t.startsWith("round.1.sub-bytes");
    });
    expect(target).toBeDefined();
    expect(target?.classList.contains("active")).toBe(true);
  });
});
