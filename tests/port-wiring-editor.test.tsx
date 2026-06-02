// @vitest-environment jsdom

/**
 * Interaction tests for the port-wiring editor dropdown
 * (`src/ui/components/PortWiringEditor.tsx`, universal-port Phase 4d-bis).
 *
 * This is the testable rewire surface: the canvas click-to-arm gesture
 * (Slice E) can't be reliably exercised in jsdom (fireEvent bypasses the
 * hit-testing the port handles depend on — see memory
 * `jsdom_pointer_events_gap`), so the dropdown carries the headless
 * interaction coverage. The synthetic spec uses a genuinely MULTI-input leaf
 * (`xor@1`, inputCount 2 → `operand0`/`operand1`) so the "which source feeds
 * which input" property is actually exercised — AES is nearly all single-input
 * leaves, where a per-leaf (not per-port) bug would pass every test.
 */

import { findStep } from "@/core/spec-mutations";
import type { CipherSpec, StepNode } from "@/core/types";
import { PortWiringEditor } from "@/ui/components/PortWiringEditor";
import { __setSpecForTests, setMode, useSpec } from "@/ui/stores/spec";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const makeSpec = (steps: readonly StepNode[]): CipherSpec => ({
  id: "wiring-ui-test@1",
  name: "wiring-ui-test",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps,
});

/** Two top-scope sources, then a 2-operand xor reading both. */
const baseSpec = (): CipherSpec =>
  makeSpec([
    { kind: "step", id: "src-a", type: "not@1", params: {} },
    { kind: "step", id: "src-b", type: "not@1", params: {} },
    {
      kind: "step",
      id: "x",
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: { node: "src-a", port: "output" },
        operand1: { node: "src-b", port: "output" },
      },
    },
  ]);

const selectFor = (container: HTMLElement, port: string): HTMLSelectElement => {
  const sel = container.querySelector<HTMLSelectElement>(
    `select[aria-label="Rewire input port ${port}"]`,
  );
  if (!sel) throw new Error(`no select for input port "${port}"`);
  return sel;
};

const optionLabels = (sel: HTMLSelectElement): string[] =>
  Array.from(sel.querySelectorAll("option")).map((o) => o.textContent ?? "");

/** The active spec's binding for one input port of leaf `x`. */
const bindingOf = (port: string) => findStep(useSpec()(), "x")?.portInputs?.[port];

beforeEach(() => {
  setMode("encrypt");
});

afterEach(() => {
  cleanup();
});

describe("PortWiringEditor", () => {
  it("renders one select per input port (per-port, not per-leaf)", () => {
    __setSpecForTests(baseSpec());
    const { container } = render(() => <PortWiringEditor stepId="x" />);
    expect(selectFor(container, "operand0")).toBeTruthy();
    expect(selectFor(container, "operand1")).toBeTruthy();
    expect(container.querySelectorAll("select")).toHaveLength(2);
  });

  it("lists $input plus the preceding siblings, with the current binding selected", () => {
    __setSpecForTests(baseSpec());
    const { container } = render(() => <PortWiringEditor stepId="x" />);
    const sel = selectFor(container, "operand0");
    const labels = optionLabels(sel);
    // — unwired —, cipher input, src-a.output, src-b.output
    expect(labels).toContain("— unwired —");
    expect(labels).toContain("cipher input");
    expect(labels).toContain("src-a.output");
    expect(labels).toContain("src-b.output");
    // operand0 is bound to src-a.output → that option is selected.
    expect(sel.options[sel.selectedIndex]?.textContent).toBe("src-a.output");
  });

  it("rebinds ONE port without disturbing the others (Trap 1)", () => {
    __setSpecForTests(baseSpec());
    const { container } = render(() => <PortWiringEditor stepId="x" />);
    const op1 = selectFor(container, "operand1");
    // Find the option index for src-a.output and select it.
    const idx = Array.from(op1.options).findIndex((o) => o.textContent === "src-a.output");
    fireEvent.change(op1, { target: { value: String(idx) } });

    expect(bindingOf("operand1")).toEqual({ node: "src-a", port: "output" });
    // operand0 untouched.
    expect(bindingOf("operand0")).toEqual({ node: "src-a", port: "output" });
  });

  it("clears a port via the '— unwired —' option", () => {
    __setSpecForTests(baseSpec());
    const { container } = render(() => <PortWiringEditor stepId="x" />);
    const op0 = selectFor(container, "operand0");
    // Index 0 is always the unwired sentinel.
    fireEvent.change(op0, { target: { value: "0" } });

    expect(bindingOf("operand0")).toBeUndefined();
    // operand1 still wired.
    expect(bindingOf("operand1")).toEqual({ node: "src-b", port: "output" });
  });

  it("shows an explicit unresolvable option when the current binding is out of scope (Trap 2)", () => {
    // operand0 points at a node that doesn't exist — a stale binding.
    __setSpecForTests(
      makeSpec([
        { kind: "step", id: "src-a", type: "not@1", params: {} },
        {
          kind: "step",
          id: "x",
          type: "xor@1",
          params: { inputCount: 1 },
          portInputs: { operand0: { node: "ghost", port: "output" } },
        },
      ]),
    );
    const { container } = render(() => <PortWiringEditor stepId="x" />);
    const sel = selectFor(container, "operand0");
    const labels = optionLabels(sel);
    const unresolvable = labels.find((l) => l.includes("unresolvable"));
    expect(unresolvable).toBeDefined();
    expect(unresolvable).toContain("ghost.output");
    // And it is the SELECTED option (the select doesn't silently show option 0).
    expect(sel.options[sel.selectedIndex]?.textContent).toContain("unresolvable");
  });

  it("flags a byteLength-mismatched source with the coerce label", () => {
    // des.p-permutation emits 4 bytes on `state`; des.s-boxes' `state` input
    // wants 6 — a genuine concrete mismatch, so the source is offered but
    // tagged "coerce" (the runtime would right-pad it as a visible step).
    __setSpecForTests(
      makeSpec([
        { kind: "step", id: "src", type: "des.p-permutation@1", params: {} },
        {
          kind: "step",
          id: "sink",
          type: "des.s-boxes@1",
          params: {},
          portInputs: { state: { node: "src", port: "state" } },
        },
      ]),
    );
    const { container } = render(() => <PortWiringEditor stepId="sink" />);
    const sel = selectFor(container, "state");
    const srcOption = optionLabels(sel).find((l) => l.startsWith("src.state"));
    expect(srcOption).toBeDefined();
    expect(srcOption).toContain("size mismatch (coerces)");
  });

  it("renders nothing for a leaf that has no input ports", () => {
    // A leaf type with zero declared inputs (constant-load) → no wiring rows.
    __setSpecForTests(
      makeSpec([{ kind: "step", id: "k", type: "constant-load@1", params: { name: "H" } }]),
    );
    const { container } = render(() => <PortWiringEditor stepId="k" />);
    expect(container.querySelectorAll("select")).toHaveLength(0);
  });
});
