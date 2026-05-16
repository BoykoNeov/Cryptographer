// @vitest-environment jsdom

/**
 * UI test for the duplicate-warning banner + Repair button surface
 * added to `SboxEditor`. Verifies the visible feedback path end to end:
 *   - banner is absent on a canonical (bijective) S-box,
 *   - banner appears when the table is edited into a non-permutation,
 *   - cells participating in a duplicate group carry the
 *     `.duplicate` class,
 *   - clicking "Repair to permutation" fires `onChange` with a fresh
 *     array that is a permutation of 0..255.
 *
 * The pure repair algorithm is exhaustively tested in
 * `sbox-validation.test.ts`; this test only checks the wiring.
 */

import { AES_SBOX } from "@/ciphers/aes-constants";
import { SboxEditor } from "@/ui/components/SboxEditor";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

describe("SboxEditor — duplicate warning + Repair button", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("renders no banner when the table is a valid permutation", () => {
    const { container } = render(() => <SboxEditor sbox={AES_SBOX} onChange={() => {}} />);
    expect(container.querySelector(".sbox-warning-banner")).toBeNull();
  });

  it("shows the banner when the table has duplicates", () => {
    // Sabotage two cells so the table is no longer a permutation.
    const sabotaged = AES_SBOX.slice();
    sabotaged[0x10] = sabotaged[0x00] ?? 0;

    const { container } = render(() => <SboxEditor sbox={sabotaged} onChange={() => {}} />);

    const banner = container.querySelector(".sbox-warning-banner");
    expect(banner).not.toBeNull();
    // The user needs to see how many cells they need to fix — "1
    // duplicate value" matches the redundant-count semantics
    // (k - 1 per collision group).
    expect(banner?.textContent ?? "").toMatch(/1 duplicate value/);
  });

  it("marks colliding cells with the .duplicate class", () => {
    // Two cells share value 0; the editor should highlight both.
    const sabotaged = AES_SBOX.slice();
    sabotaged[0x10] = sabotaged[0x00] ?? 0;

    const { container } = render(() => <SboxEditor sbox={sabotaged} onChange={() => {}} />);

    const duplicateCells = container.querySelectorAll("input.byte-cell.duplicate");
    // Exactly two cells should be flagged (the original at idx 0 and
    // the sabotaged copy at idx 0x10).
    expect(duplicateCells.length).toBe(2);
  });

  it("Repair button fires onChange with a permutation of 0..255", () => {
    // Use a controlled signal so we observe the post-repair state in
    // the same way the real spec store would — pass it back in via the
    // sbox prop on the next render.
    const sabotaged = AES_SBOX.slice();
    sabotaged[0x10] = sabotaged[0x00] ?? 0;

    const [sbox, setSbox] = createSignal<readonly number[]>(sabotaged);

    const { container } = render(() => (
      <SboxEditor sbox={sbox()} onChange={(next) => setSbox(next)} />
    ));

    // Banner should be visible pre-repair.
    expect(container.querySelector(".sbox-warning-banner")).not.toBeNull();

    const repairButton = container.querySelector("button.sbox-warning-repair") as HTMLButtonElement;
    expect(repairButton).not.toBeNull();
    fireEvent.click(repairButton);

    // After repair, the new sbox is a permutation.
    const repaired = sbox();
    expect(repaired.length).toBe(256);
    expect(new Set(repaired).size).toBe(256);

    // And the banner is gone on the next render pass.
    expect(container.querySelector(".sbox-warning-banner")).toBeNull();
  });
});
