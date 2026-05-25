// @vitest-environment jsdom

/**
 * Slice 1.10 — `narrationOverride?: StepDocumentation` on `StepLeaf`.
 *
 * The field is a Phase 1 foundation for Phase 3's AES-rebuild-from-medium-
 * primitives: each rebuilt spec leaf will be able to shadow the registry's
 * generic doc with cipher-specific prose. No shipped spec uses the field
 * yet, so the only behaviors to pin here are:
 *
 *   1. **Fallback (the explicit slice gate):** when a leaf carries no
 *      `narrationOverride`, `<StepDescription>` renders the registry's
 *      doc keyed by `stepType`. This is the long-shipped behavior; the
 *      test asserts the lookup-then-fallback chain didn't regress.
 *
 *   2. **Override path (robustness):** when a leaf carries a
 *      `narrationOverride`, the override's `name` / `summary` / `detail`
 *      render in place of the registry's. Otherwise the field would be
 *      dead code that Phase 3 only discovers is broken when it tries
 *      to use it.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import type { CipherDocument } from "@/core/document";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { CipherSpec, StepDocumentation, TraceFrame } from "@/core/types";
import { StepDescription } from "@/ui/components/StepDescription";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setSpecFromDocument } from "@/ui/stores/spec";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const KEY_HEX = "000102030405060708090a0b0c0d0e0f";
const PLAINTEXT_HEX = "00112233445566778899aabbccddeeff";

const resetSpecStores = (): void => {
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
};

/** Pick the first frame whose canonical stepId matches the given leaf id. */
const findFrameByStepId = (frames: readonly TraceFrame[], stepId: string): TraceFrame => {
  const f = frames.find((frame) => frame.stepId === stepId);
  if (!f) throw new Error(`no frame with stepId="${stepId}" in trace`);
  return f;
};

describe("StepDescription — narrationOverride fallback + override", () => {
  beforeEach(() => resetSpecStores());
  afterEach(() => {
    cleanup();
    resetSpecStores();
  });

  it("falls back to registry doc when the leaf has no narrationOverride", () => {
    // The default AES-128 spec carries no `narrationOverride` on any leaf,
    // so every frame's docs come from `registry.getDoc(stepType)`. Picking
    // the key-expansion frame because its registry doc has a stable, easy-
    // to-assert heading ("Key Expansion").
    const initial = matrixFromBytes(bytesFromHex(PLAINTEXT_HEX));
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: initial,
      initialAux: new Map([["key", bytesFromHex(KEY_HEX)]]),
    });
    const frame = findFrameByStepId(trace.frames, "key-expansion");

    const registryDoc = buildDefaultRegistry().getDoc(frame.stepType);
    if (!registryDoc) throw new Error("registry doc missing for aes.key-expansion");

    const { container } = render(() => <StepDescription frame={frame} />);
    const heading = container.querySelector(".step-description-name");
    expect(heading?.textContent).toBe(registryDoc.name);
  });

  it("prefers the leaf's narrationOverride over the registry doc when present", () => {
    // Build a one-leaf spec whose leaf carries a `narrationOverride`. Land
    // it via setSpecFromDocument so the live spec store points at it; then
    // mount StepDescription with a synthetic frame whose stepId matches.
    // The override's `name` should win over the registry's "Byte Substitution".
    const override: StepDocumentation = {
      name: "Custom Narration Name",
      summary: "summary used only for this leaf",
      detail: "detail body for the override",
    };
    const customSpec: CipherSpec = {
      id: "test.custom@1",
      name: "Test Custom",
      stateShape: "matrix4x4-bytes",
      inputs: {
        plaintext: { shape: "matrix4x4-bytes" },
        key: { byteLength: 16 },
      },
      steps: [
        {
          kind: "step",
          id: "custom-leaf",
          type: "aes.sub-bytes@1",
          params: { sbox: [] },
          narrationOverride: override,
        },
      ],
    };
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: customSpec,
    };
    setSpecFromDocument(doc);

    // Synthetic frame — stepId must equal the leaf's id so canonicalStepId
    // strips no suffix and findStep resolves the override-carrying leaf.
    const frame: TraceFrame = {
      index: 0,
      path: ["custom-leaf"],
      stepId: "custom-leaf",
      stepType: "aes.sub-bytes@1",
      params: { sbox: [] },
      stateBefore: matrixFromBytes(bytesFromHex(PLAINTEXT_HEX)),
      stateAfter: matrixFromBytes(bytesFromHex(PLAINTEXT_HEX)),
      auxRead: new Map(),
      auxWritten: new Map(),
    };

    const { container } = render(() => <StepDescription frame={frame} />);
    const heading = container.querySelector(".step-description-name");
    const summary = container.querySelector(".step-description-summary");
    expect(heading?.textContent).toBe("Custom Narration Name");
    expect(summary?.textContent).toBe("summary used only for this leaf");
    // The registry's name ("Byte Substitution") must NOT leak through.
    expect(heading?.textContent).not.toBe("Byte Substitution");
  });
});
