// @vitest-environment jsdom

/**
 * Component test for ConstantsPanel (scaffolding-suppression A1).
 *
 * Covers the two channels the A1 UX picks promised:
 *   - Edit: a byte-cell commit routes through `editCipherConstant`, mutating
 *     the active spec's `cipherConstants` (single source of truth).
 *   - Forward cross-ref: each constant lists its consuming `aux-load-bytes@1`
 *     leaves as clickable links; clicking selects the leaf.
 * Plus the inert case: no panel for a spec without `cipherConstants` (AES).
 */

import { ConstantsPanel } from "@/ui/components/ConstantsPanel";
import { ParamEditor } from "@/ui/components/ParamEditor";
import { __resetCipherForTests, setCipher } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetSpecForTests, setHash, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, useSelectedStepId } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetSpecForTests();
  __resetTraceForTests();
};

describe("ConstantsPanel (A1)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders nothing for a spec without cipherConstants (AES-128)", () => {
    setCipher("aes-128");
    const { container } = render(() => <ConstantsPanel />);
    expect(container.querySelector("#cipher-constants-panel")).toBeNull();
  });

  it("renders a row per constant for SHA-256 (K + H)", () => {
    setHash("sha-256");
    const { container } = render(() => <ConstantsPanel />);
    expect(container.querySelector("#cipher-constants-panel")).not.toBeNull();
    expect(container.querySelector('[data-constant-row="K"]')).not.toBeNull();
    expect(container.querySelector('[data-constant-row="H"]')).not.toBeNull();
  });

  it("lists consumer leaves under each constant (forward cross-ref)", () => {
    setHash("sha-256");
    const { container } = render(() => <ConstantsPanel />);
    const kRow = container.querySelector('[data-constant-row="K"]') as HTMLElement;
    const hRow = container.querySelector('[data-constant-row="H"]') as HTMLElement;
    const linkText = (row: HTMLElement): string[] =>
      Array.from(row.querySelectorAll("button.constant-consumer-link")).map(
        (b) => b.textContent ?? "",
      );
    const kConsumers = linkText(kRow);
    const hConsumers = linkText(hRow);
    // K is read once per compression round (64 fetch-K leaves).
    expect(kConsumers).toContain("round.0.fetch-K");
    expect(kConsumers).toContain("round.63.fetch-K");
    expect(kConsumers.length).toBe(64);
    // H is read once — by `init.fetch-H`, which bootstraps the per-block
    // fold's chainInput (block 0's running hash). Slice 2.11b retired the old
    // `final.fetch-H` consumer: the per-block final-add now adds the RUNNING
    // hash (the iterate chain), not the constant aux["H"].
    expect(hConsumers).toContain("init.fetch-H");
    expect(hConsumers).not.toContain("final.fetch-H");
    expect(hConsumers.length).toBe(1);
  });

  it("clicking a consumer link selects that leaf", () => {
    setHash("sha-256");
    const selected = useSelectedStepId();
    const { container } = render(() => <ConstantsPanel />);
    const kRow = container.querySelector('[data-constant-row="K"]') as HTMLElement;
    const firstLink = kRow.querySelector("button.constant-consumer-link") as HTMLButtonElement;
    fireEvent.click(firstLink);
    expect(selected()).toBe("round.0.fetch-K");
  });

  it("editing a byte cell mutates the active spec's constant (single source of truth)", () => {
    setHash("sha-256");
    const spec = useSpec();
    const { container } = render(() => <ConstantsPanel />);
    const kRow = container.querySelector('[data-constant-row="K"]') as HTMLElement;
    // Byte cells live in the .rcon-row inside the constant's <details>; jsdom
    // keeps closed-<details> content queryable.
    const firstCell = kRow.querySelector("input.byte-cell") as HTMLInputElement;
    expect(firstCell).not.toBeNull();
    // Default format is hex → "ab" parses to 0xab.
    fireEvent.input(firstCell, { target: { value: "ab" } });
    fireEvent.blur(firstCell);
    expect(spec().cipherConstants?.K?.[0]).toBe(0xab);
  });

  it("leaf inspector shows a 'reads constant' back-ref for an aux-load-bytes leaf reading a constant", () => {
    setHash("sha-256");
    // round.0.fetch-K is aux-load-bytes@1 with auxName "K" — a constant.
    const { container } = render(() => <ParamEditor stepId="round.0.fetch-K" />);
    const backref = container.querySelector("button.constant-backref-link");
    expect(backref).not.toBeNull();
    expect(backref?.textContent).toBe("K");
  });

  it("leaf inspector shows NO back-ref for an aux-load-bytes leaf reading a non-constant", () => {
    setHash("sha-256");
    // round.0.fetch-W reads aux["W"] — published by W-publish, NOT a
    // cipherConstant — so no back-ref link should render.
    const { container } = render(() => <ParamEditor stepId="round.0.fetch-W" />);
    expect(container.querySelector("button.constant-backref-link")).toBeNull();
  });
});
