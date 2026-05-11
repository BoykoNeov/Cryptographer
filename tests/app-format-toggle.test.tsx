// @vitest-environment jsdom

/**
 * Integration test for the App-level format toggle. Renders the whole App
 * shell, clicks the format buttons in the inputs row, and asserts that
 * the plaintext + key text fields rewrite themselves in the new format
 * without losing data.
 *
 * This is the most user-facing piece of Phase 3: the rest of the work
 * (formatters, store, cell components) only matters if the toggle
 * actually drives them. Worth testing with the full App in jsdom.
 */

import { App } from "@/ui/App";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const findInput = (container: HTMLElement, labelText: string): HTMLInputElement => {
  // The plaintext / key labels look like "plaintext (hex)" — match by the
  // first word so the test isn't tied to the format suffix.
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  if (!target) throw new Error(`label starting with "${labelText}" not found`);
  const input = target.querySelector("input");
  if (!input) throw new Error(`input under "${labelText}" label not found`);
  return input;
};

const findFormatButton = (container: HTMLElement, label: string): HTMLButtonElement => {
  const buttons = Array.from(container.querySelectorAll(".format-toggle button"));
  const target = buttons.find((b) => b.textContent?.trim() === label);
  if (!target) throw new Error(`format button "${label}" not found`);
  return target as HTMLButtonElement;
};

describe("App — byte format toggle integration", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
    __resetTraceForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
  });

  it("renders default plaintext + key in hex on first load", () => {
    const { container } = render(() => <App />);
    const pt = findInput(container, "plaintext");
    const key = findInput(container, "key");
    // FIPS-197 Appendix C.1 vectors.
    expect(pt.value).toBe("00112233445566778899aabbccddeeff");
    expect(key.value).toBe("000102030405060708090a0b0c0d0e0f");
  });

  it("clicking 'dec' rewrites the input fields to space-separated decimals", () => {
    const { container } = render(() => <App />);
    const pt = findInput(container, "plaintext");
    fireEvent.click(findFormatButton(container, "dec"));

    // 0x00 → "0", 0x11 → "17", … 0xff → "255".
    expect(pt.value).toBe("0 17 34 51 68 85 102 119 136 153 170 187 204 221 238 255");
  });

  it("clicking 'ASCII' renders printable bytes literal and the rest as escapes", () => {
    const { container } = render(() => <App />);
    const pt = findInput(container, "plaintext");
    fireEvent.click(findFormatButton(container, "ASCII"));

    // First two bytes (0x00, 0x11) are below 0x20 → both escape.
    // 0x22 is the printable `"`; 0x33 is the printable `'3'`. Spot-check
    // the prefix and a few of the printable bytes that follow.
    expect(pt.value.startsWith('\\x00\\x11"3')).toBe(true);
    expect(pt.value.includes("D")).toBe(true); // 0x44
    expect(pt.value.includes("U")).toBe(true); // 0x55
    expect(pt.value.endsWith("\\xff")).toBe(true); // last byte non-printable
  });

  it("hex → decimal → ASCII → hex round-trips without losing the original bytes", () => {
    const { container } = render(() => <App />);
    const pt = findInput(container, "plaintext");
    const original = pt.value;

    fireEvent.click(findFormatButton(container, "dec"));
    fireEvent.click(findFormatButton(container, "ASCII"));
    fireEvent.click(findFormatButton(container, "hex"));

    expect(pt.value).toBe(original);
  });

  it("preserves user-typed data across a format switch (not just the defaults)", () => {
    const { container } = render(() => <App />);
    const pt = findInput(container, "plaintext");

    // User overwrites the plaintext.
    fireEvent.input(pt, { target: { value: "deadbeefdeadbeefdeadbeefdeadbeef" } });
    expect(pt.value).toBe("deadbeefdeadbeefdeadbeefdeadbeef");

    fireEvent.click(findFormatButton(container, "dec"));
    // 0xde=222, 0xad=173, 0xbe=190, 0xef=239 — repeating 4 times.
    expect(pt.value).toBe("222 173 190 239 222 173 190 239 222 173 190 239 222 173 190 239");
  });

  it("leaves the raw text alone if the current input does not parse cleanly", () => {
    const { container } = render(() => <App />);
    const pt = findInput(container, "plaintext");

    // Invalid hex (odd length) — switching format should NOT clobber it.
    fireEvent.input(pt, { target: { value: "abc" } });
    fireEvent.click(findFormatButton(container, "dec"));

    expect(pt.value).toBe("abc");
  });

  it("activates the clicked button and deactivates the previous one", () => {
    const { container } = render(() => <App />);
    expect(findFormatButton(container, "hex").classList.contains("active")).toBe(true);
    expect(findFormatButton(container, "dec").classList.contains("active")).toBe(false);

    fireEvent.click(findFormatButton(container, "dec"));

    expect(findFormatButton(container, "hex").classList.contains("active")).toBe(false);
    expect(findFormatButton(container, "dec").classList.contains("active")).toBe(true);
  });
});
