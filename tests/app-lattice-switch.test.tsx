// @vitest-environment jsdom

/**
 * Switching between the two lattice transforms through the UI
 * (`docs/plans/refactored-petting-tide.md`, P1).
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE BUG: THE SAME ONE ML-KEM FOUND, ONE FAMILY OVER
 *
 * The NTT was the lattice family's only member, so its dropdown wired straight
 * to `setLattice` — a variant switch was unreachable, so no input swap was
 * needed. ML-DSA's transform made it reachable, and the first switch in a
 * browser left ML-KEM's 512-byte polynomial in the field, where the 1024-byte
 * transform rejected it. `tests/app-ml-kem.test.tsx` records the identical
 * omission in the public-key family; every headless KAT stayed green both
 * times, because none of them touches the App's handler.
 *
 * The fix (`changeLattice` in `App.tsx`) is mode-aware: forward wants a
 * polynomial and inverse wants its transform, so the swap is taken at the
 * current direction — asserted separately below rather than assumed.
 *
 * Driven via real <select>/<input> events, not the store setters, because the
 * handler is the thing under test.
 */

import { DEFAULT_NTT_INPUT, DEFAULT_NTT_OUTPUT } from "@/ciphers/ntt-3329-256";
import { DEFAULT_ML_DSA_NTT_INPUT, DEFAULT_ML_DSA_NTT_OUTPUT } from "@/ciphers/ntt-8380417-256";
import { App } from "@/ui/App";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/**
 * Compare two long hex strings and, on failure, report only their lengths and
 * first bytes. These fields hold 1–4 KB of hex; a plain `toBe` would print (and
 * first compute) a full diff of two mostly-different multi-kilobyte strings,
 * which is unreadable at best. A run of this file while it still used `toBe`
 * also stalled for over five minutes — not proven to be the diff, but the
 * cheaper failure is worth having either way.
 */
const expectHex = (actual: string, expected: string, what: string): void => {
  const brief = (h: string): string => `${h.length / 2} bytes, ${h.slice(0, 24)}…`;
  expect(actual === expected, `${what}: got ${brief(actual)} want ${brief(expected)}`).toBe(true);
};

const findSelectByLabel = (container: HTMLElement, labelText: string): HTMLSelectElement => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  const select = target?.querySelector("select");
  if (!select) throw new Error(`select under "${labelText}" not found`);
  return select;
};

const findInputByLabel = (container: HTMLElement, labelText: string): HTMLInputElement => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  const input = target?.querySelector("input");
  if (!input) throw new Error(`input under "${labelText}" not found`);
  return input;
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetTraceForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
};

const pickTransform = (container: HTMLElement, value: string): void => {
  fireEvent.change(findSelectByLabel(container, "transform"), { target: { value } });
};

describe("App — switching lattice transform swaps a default input, keeps a typed one", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("forward: ML-KEM's 512-byte polynomial becomes ML-DSA's 1024-byte one, and back", () => {
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "lattice" } });
    expectHex(
      findInputByLabel(container, "polynomial").value,
      hex(DEFAULT_NTT_INPUT),
      "polynomial",
    );

    pickTransform(container, "ntt-8380417-256");
    expectHex(
      findInputByLabel(container, "polynomial").value,
      hex(DEFAULT_ML_DSA_NTT_INPUT),
      "polynomial",
    );

    pickTransform(container, "ntt-3329-256");
    expectHex(
      findInputByLabel(container, "polynomial").value,
      hex(DEFAULT_NTT_INPUT),
      "polynomial",
    );
  });

  it("inverse: the swap is taken at the CURRENT direction", async () => {
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "lattice" } });
    // Flipping direction copies the shown OUTPUT into the input (so the inverse
    // undoes what was just computed), so let the forward run land first —
    // otherwise the previous algorithm's output is what gets copied. Waits on
    // the RESULT, not a fixed sleep: the run sits behind a 200 ms debounce, and
    // a fixed sleep is the race app-url-share.test.tsx's boot tests lost under
    // full-suite load.
    await waitFor(
      () => {
        const shown = container.querySelector(".inputs-result code")?.textContent ?? "";
        expect(shown === hex(DEFAULT_NTT_OUTPUT), "forward result not shown yet").toBe(true);
      },
      { timeout: 10000 },
    );
    fireEvent.change(findSelectByLabel(container, "mode"), { target: { value: "decrypt" } });
    expectHex(
      findInputByLabel(container, "transformed polynomial").value,
      hex(DEFAULT_NTT_OUTPUT),
      "transformed polynomial",
    );

    pickTransform(container, "ntt-8380417-256");
    expectHex(
      findInputByLabel(container, "transformed polynomial").value,
      hex(DEFAULT_ML_DSA_NTT_OUTPUT),
      "transformed polynomial",
    );
  });

  it("a polynomial the user typed survives the switch (the sacred-input policy)", () => {
    const { container } = render(() => <App />);
    fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "lattice" } });
    fireEvent.input(findInputByLabel(container, "polynomial"), { target: { value: "0001" } });

    pickTransform(container, "ntt-8380417-256");
    expect(findInputByLabel(container, "polynomial").value).toBe("0001");
  });
});
