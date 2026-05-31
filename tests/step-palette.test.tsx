// @vitest-environment jsdom

/**
 * Slice 8 — palette + graph-insertion tests.
 *
 * Two layers:
 *   1. Palette render — does it list every non-padding registered step type,
 *      grouped by namespace, with correct draggable + data attributes?
 *   2. Drop pipeline — does triggering the GraphView's `drop` handler with a
 *      step-type payload insert a new leaf into the spec at the right anchor?
 *
 * We do NOT exercise the browser's real HTML5 drag-and-drop dance — jsdom's
 * `DragEvent` / `DataTransfer` support is partial and varies by version. The
 * unit boundary we test is the drop handler's reaction when fed an event
 * with a populated `dataTransfer`. Real DnD UX (palette → canvas with mouse
 * tracking) is left for the Playwright smoke gate.
 *
 * Strategy for the drop test:
 *   - Fire a synthetic `drop` event with a mock `dataTransfer` carrying the
 *     stepType MIME payload, dispatched at the SVG-side element whose
 *     `data-drop-anchor` attribute we want as the anchor.
 *   - Assert the spec store's new spec contains a leaf with the dropped
 *     stepType inserted in the right structural position.
 *
 * jsdom quirk: `new DragEvent(...)` doesn't accept a `dataTransfer` in init,
 * and dispatched events get a fresh empty DataTransfer. We synthesize a
 * plain Event of type "drop", attach our own `dataTransfer` via
 * `Object.defineProperty`, then dispatch — handlers read it the same way.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { PADDING_STEP_TYPES, findStep, findStepAndParent } from "@/core/spec-mutations";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { STEP_TYPE_DRAG_MIME, StepPalette } from "@/ui/components/StepPalette";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, insertStepIntoSpec, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

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

/**
 * Synthesize a minimal DataTransfer-shaped object the handler can read.
 * We only need `getData` (drop) and `types` (dragover); both come from a
 * plain object literal. setData/effectAllowed are no-ops because the test
 * never starts a real drag — it injects an already-populated payload.
 */
const mockDataTransfer = (payload: { readonly [mime: string]: string }) => ({
  getData: (mime: string) => payload[mime] ?? "",
  types: Object.keys(payload),
  setData: (_mime: string, _value: string) => {},
  effectAllowed: "" as DataTransfer["effectAllowed"],
  dropEffect: "" as DataTransfer["dropEffect"],
});

/**
 * Dispatch a `drop` Event at `target` carrying the given stepType in the
 * project's custom MIME payload. Mirrors what the browser would do after
 * a successful drag-from-palette gesture.
 */
const fireDropAt = (target: Element, stepType: string): void => {
  const event = new Event("drop", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", {
    value: mockDataTransfer({
      [STEP_TYPE_DRAG_MIME]: stepType,
      "text/plain": stepType,
    }),
  });
  // Walk the SVG tree so the drop handler's `closest("[data-drop-anchor]")`
  // sees the same DOM the browser would. dispatchEvent runs synchronously.
  target.dispatchEvent(event);
};

// ─── Palette render ────────────────────────────────────────────────────────

describe("StepPalette — render", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("lists every non-padding registered step type", () => {
    const { container } = render(() => <StepPalette />);
    // Every non-padding type the default registry knows about should appear
    // as a palette entry with `data-step-type` matching the registry key.
    const registry = buildDefaultRegistry();
    const expectedTypes = registry.types().filter((t) => !PADDING_STEP_TYPES.has(t));
    for (const stepType of expectedTypes) {
      const entry = container.querySelector(`[data-step-type="${stepType}"]`);
      expect(entry, `palette should list ${stepType}`).not.toBeNull();
    }
  });

  it("excludes padding overlay step types so they can't be silently stripped on selector flip", () => {
    const { container } = render(() => <StepPalette />);
    for (const stepType of PADDING_STEP_TYPES) {
      const entry = container.querySelector(`[data-step-type="${stepType}"]`);
      expect(entry, `palette should NOT list padding-overlay type ${stepType}`).toBeNull();
    }
  });

  it("groups entries by namespace (aes, generic, speck, serpent)", () => {
    const { container } = render(() => <StepPalette />);
    // Each non-empty group renders a `[data-testid="step-palette-group-<ns>"]`
    // section. AES, generic, speck, serpent are all populated today.
    expect(container.querySelector('[data-testid="step-palette-group-aes"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="step-palette-group-generic"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="step-palette-group-speck"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="step-palette-group-serpent"]')).not.toBeNull();
  });

  it("marks every entry draggable=true so the browser starts a real drag", () => {
    const { container } = render(() => <StepPalette />);
    const entries = container.querySelectorAll<HTMLElement>(".step-palette-entry");
    expect(entries.length).toBeGreaterThan(0);
    for (const e of entries) {
      // `draggable` is a reflected HTML boolean attribute; jsdom stores it
      // as a string on the attribute and exposes it on the property.
      expect(e.draggable).toBe(true);
    }
  });

  it("renders a state-shape chip on entries whose step type declares a shapeContract", () => {
    // Every shipped step type declares a contract (see
    // `tests/state-shape-contracts.test.ts`), so every entry should show
    // a chip. The chip's `data-shape` attribute mirrors the contract's
    // declared input.
    const { container } = render(() => <StepPalette />);
    const registry = buildDefaultRegistry();
    for (const stepType of registry.types()) {
      if (PADDING_STEP_TYPES.has(stepType)) continue;
      const contract = registry.getDoc(stepType)?.shapeContract;
      if (!contract) continue;
      const chip = container.querySelector(`[data-testid="step-palette-entry-shape-${stepType}"]`);
      expect(chip, `palette entry ${stepType} should show a shape chip`).not.toBeNull();
      expect(chip?.getAttribute("data-shape")).toBe(contract.input);
    }
  });
});

// ─── insertStepIntoSpec mutator (signal-level) ─────────────────────────────

describe("insertStepIntoSpec — store mutator", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("inserts a new leaf with empty params after the named anchor leaf", () => {
    const spec = useSpec();
    const before = spec();
    // The shipped AES-128 spec has `key-expansion` as the first top-level leaf.
    expect(findStep(before, "key-expansion")).not.toBeNull();
    insertStepIntoSpec("generic.byte-substitution@1", {
      kind: "after",
      stepId: "key-expansion",
    });
    const after = spec();
    // A new leaf with that stepType should now exist; its position is
    // directly after `key-expansion` in the top-level array.
    const located = findStepAndParent(after, "byte-substitution-1");
    expect(located, "new leaf should be findable by generated id").not.toBeNull();
    expect(located?.node.kind).toBe("step");
    if (located?.node.kind === "step") {
      expect(located.node.type).toBe("generic.byte-substitution@1");
      expect(located.node.params).toEqual({});
    }
    // Sibling-order assertion: index of new leaf is index of key-expansion + 1.
    const keyExpLoc = findStepAndParent(after, "key-expansion");
    expect(located?.indexInParent).toBe((keyExpLoc?.indexInParent ?? -1) + 1);
  });

  it("supports root-append for a drop on the empty canvas", () => {
    const spec = useSpec();
    const beforeLen = spec().steps.length;
    insertStepIntoSpec("generic.shift-rows@1", { kind: "root-append" });
    const after = spec();
    expect(after.steps.length).toBe(beforeLen + 1);
    const last = after.steps[after.steps.length - 1];
    expect(last?.kind).toBe("step");
    if (last?.kind === "step") {
      expect(last.type).toBe("generic.shift-rows@1");
    }
  });

  it("generates a unique id when the same step type is inserted multiple times", () => {
    const spec = useSpec();
    insertStepIntoSpec("generic.byte-substitution@1", { kind: "root-append" });
    insertStepIntoSpec("generic.byte-substitution@1", { kind: "root-append" });
    insertStepIntoSpec("generic.byte-substitution@1", { kind: "root-append" });
    const after = spec();
    expect(findStep(after, "byte-substitution-1")).not.toBeNull();
    expect(findStep(after, "byte-substitution-2")).not.toBeNull();
    expect(findStep(after, "byte-substitution-3")).not.toBeNull();
  });

  it("returns the generated id so the caller can route the trace focus", () => {
    const newId = insertStepIntoSpec("speck.round@1", { kind: "root-append" });
    expect(newId).toBe("round-1");
    const spec = useSpec();
    expect(findStep(spec(), "round-1")).not.toBeNull();
  });

  it("preserves the active padding overlay when inserting at root", () => {
    // Inserting at the top level shouldn't disturb the padding chain; the
    // spec returned from `insertStepIntoSpec` should still carry whatever
    // leaves the canonical spec had. Specifically: AES-128 default has
    // `key-expansion` at index 0; that should still be at index 0 after a
    // root-append.
    const spec = useSpec();
    const beforeFirst = spec().steps[0];
    insertStepIntoSpec("generic.shift-rows@1", { kind: "root-append" });
    const afterFirst = spec().steps[0];
    expect(afterFirst).toBe(beforeFirst);
  });

  it("inserts into a nested group when the anchor is a leaf inside that group", () => {
    // AES-128 spec has `round.1` as a group containing `round.1.sub-bytes`,
    // `round.1.shift-rows`, etc. Inserting after `round.1.shift-rows` should
    // land the new leaf inside `round.1`, not at the top level.
    insertStepIntoSpec("generic.byte-substitution@1", {
      kind: "after",
      stepId: "round.1.shift-rows",
    });
    const spec = useSpec();
    const located = findStepAndParent(spec(), "byte-substitution-1");
    expect(located).not.toBeNull();
    // The parent should be the round.1 group, not the top-level spec.
    expect(located?.parent?.id).toBe("round.1");
  });
});

// ─── Drop handler in GraphView ─────────────────────────────────────────────

describe("GraphView — palette drop integration", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("creates a new leaf in the spec when a drop fires over a leaf node", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    // Drop on the `key-expansion` leaf's `<g>` (has data-drop-anchor).
    const leaf = container.querySelector<SVGGElement>(
      'g.graph-leaf[data-drop-anchor="key-expansion"]',
    );
    expect(leaf, "graph should render the key-expansion leaf").not.toBeNull();
    if (!leaf) return;
    fireDropAt(leaf, "byte-substitute@1");
    const spec = useSpec();
    expect(findStep(spec(), "byte-substitute-1"), "new leaf should be inserted").not.toBeNull();
  });

  it("dropping on a container header inserts as the first child of that container", () => {
    // Rescoped 2026-05-15 (Slice 5 follow-up). The original Slice 8
    // semantic — "drop on container = insert after container in parent"
    // — was actively confusing: the dragged chip obscures the header
    // band so users couldn't tell their cursor was over it, and aux-
    // shape inserts at root level got auxOnlyRoot-lifted, severing the
    // state spine. New semantic: "drop on container header = enter the
    // container's body and land at position 0." Matches every other
    // DAG editor's drop-on-container behavior.
    //
    // The data-drop-anchor moved from the outer `<g>` to the header
    // `<rect>` (the drag-handle band), so the drop is dispatched on
    // the header element specifically. The body of the container has
    // no anchor — body drops resolve via gutters/leaves only.
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const header = container.querySelector<SVGRectElement>(
      'rect.graph-container-header[data-drop-anchor="round.1"]',
    );
    expect(header, "graph should render the round.1 header drop-anchor").not.toBeNull();
    if (!header) return;
    fireDropAt(header, "byte-substitute@1");
    const spec = useSpec();
    const newLeafLoc = findStepAndParent(spec(), "byte-substitute-1");
    expect(newLeafLoc, "new leaf should exist").not.toBeNull();
    // New leaf's parent should be round.1 (we entered the body), and
    // it should be at position 0 (first child) since the header drop
    // routes to `{ kind: "into-start", containerId }`.
    expect(newLeafLoc?.parent?.id).toBe("round.1");
    expect(newLeafLoc?.indexInParent).toBe(0);
  });

  it("ignores drops that carry a non-registered step type", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const spec = useSpec();
    const beforeLen = spec().steps.length;
    const leaf = container.querySelector<SVGGElement>(
      'g.graph-leaf[data-drop-anchor="key-expansion"]',
    );
    if (!leaf) throw new Error("test setup: key-expansion leaf missing");
    fireDropAt(leaf, "generic.nonexistent-type@99");
    // Spec should be unchanged — no leaf was added, no error thrown.
    expect(useSpec()().steps.length).toBe(beforeLen);
  });

  it("ignores drops without a step-type payload (e.g. random text from elsewhere)", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const before = useSpec()().steps.length;
    const leaf = container.querySelector<SVGGElement>(
      'g.graph-leaf[data-drop-anchor="key-expansion"]',
    );
    if (!leaf) throw new Error("test setup: key-expansion leaf missing");
    // Fire a drop event whose dataTransfer is empty for the step-type MIME.
    const event = new Event("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(event, "dataTransfer", {
      value: mockDataTransfer({}),
    });
    leaf.dispatchEvent(event);
    expect(useSpec()().steps.length).toBe(before);
  });
});
