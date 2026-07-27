// @vitest-environment jsdom

/**
 * The generator's seed reaches the app through `aux["seed"]`.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHY THIS FILE EXISTS, AND WHAT `tests/chacha20-csprng-kat.test.ts` CANNOT
 * COVER.
 *
 * The CSPRNG's block function lives INSIDE the iterate, and port flow cannot
 * cross a container scope — the runtime seeds a body's scope with only that
 * iterate's own `in`/`chain` ports, so `$input` is unreachable from in there.
 * The seed therefore travels through aux, published by a single line in
 * `App.tsx`:
 *
 *     if (isPrng(algorithm())) initialAux.set(PRNG_SEED_AUX, …)
 *
 * That one line is what makes the generator work in the real app. **The KAT
 * cannot cover it**, because the KAT constructs its own `initialAux` by hand
 * (deliberately — it is testing the spec, and reproducing the publish keeps it
 * honest about what the app must do). The consequence is that deleting the
 * `App.tsx` line leaves every one of the KAT's assertions green, and the whole
 * suite with them, while the app throws on Run for every generator whose body
 * sits inside a container.
 *
 * That is exactly the shape `feedback_tests_must_import_the_guard` describes: a
 * test that re-creates the mechanism it is meant to guard is not a test of it.
 * This file drives the real `<App />` — its own input parsing, its own aux
 * assembly, its own Run path — so the publish is exercised rather than
 * imitated.
 *
 * The assertion is the strongest one available: with the default all-zero seed,
 * the output must be RFC 8439 Appendix A.1's published block-function vector. A
 * seed that failed to arrive would not merely differ, it would throw — but
 * pinning the published bytes also catches a seed that arrived mangled.
 */

import { App } from "@/ui/App";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetIvForTests } from "@/ui/stores/iv";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const findSelectByLabel = (container: HTMLElement, labelText: string): HTMLSelectElement => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  if (!target) throw new Error(`label starting with "${labelText}" not found`);
  const select = target.querySelector("select");
  if (!select) throw new Error(`select under "${labelText}" label not found`);
  return select;
};

const findInputByLabel = (container: HTMLElement, labelText: string): HTMLInputElement | null => {
  const labels = Array.from(container.querySelectorAll("label"));
  const target = labels.find((l) => l.textContent?.trim().startsWith(labelText));
  if (!target) return null;
  return target.querySelector("input");
};

const findButton = (container: HTMLElement, text: string): HTMLButtonElement => {
  const target = Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent?.trim() === text,
  );
  if (!target) throw new Error(`button "${text}" not found`);
  return target as HTMLButtonElement;
};

const readResultHex = (container: HTMLElement): string =>
  (container.querySelector(".result code")?.textContent ?? "").replace(/\s+/g, "");

const readError = (container: HTMLElement): string =>
  container.querySelector(".error")?.textContent ?? "";

/**
 * Select a generator. Routed via the `kind` selector first, since
 * `__resetCipherForTests` leaves the category on "cipher".
 */
const useGenerator = (container: HTMLElement, value: string): void => {
  fireEvent.change(findSelectByLabel(container, "kind"), { target: { value: "prng" } });
  fireEvent.change(findSelectByLabel(container, "generator"), { target: { value } });
  // Auto-rerun is debounced 200 ms, which a synchronous test never reaches —
  // click Run explicitly, the way `tests/app-chacha20-stream.test.tsx` does.
  fireEvent.click(findButton(container, "run"));
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetTraceForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetCipherModeForTests();
  __resetIvForTests();
  __resetCipherForTests();
  __resetSpecForTests();
};

/**
 * RFC 8439 §A.1's first block-function vector (key = 0, nonce = 0, counter = 0),
 * first 16 bytes. The app's default CSPRNG seed is all-zero, so this is
 * literally what a user sees on first Run.
 */
const A1_PREFIX = "76b8e0ada0f13d90405d6ae55386bd28";

describe("PRNG seed reaches the spec through aux", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("the CSPRNG produces RFC 8439 §A.1's vector from the app's default seed", () => {
    // THE test. The block function reads `aux["seed"]` from inside the iterate;
    // if `App.tsx` stopped publishing it, `aux-load-bytes@1` would throw and
    // this would surface as an error rather than a stream.
    const { container } = render(() => <App />);
    useGenerator(container, "chacha20-csprng");

    expect(readError(container), "the app reported an error instead of generating").toBe("");
    expect(readResultHex(container).slice(0, 32)).toBe(A1_PREFIX);
  });

  it("emits exactly the requested number of bytes, ragged tail included", () => {
    // The default is 42 — deliberately not a multiple of the 64-byte block, so
    // first paint exercises the partial-final-block path.
    const { container } = render(() => <App />);
    useGenerator(container, "chacha20-csprng");
    expect(readResultHex(container).length).toBe(42 * 2);
  });

  it("still runs the LCGs, which reach their seed a different way", () => {
    // The LCGs bootstrap `chainInput` from `port($input)` at top level rather
    // than from aux, so they would survive the publish being deleted. Asserting
    // them here keeps the publish from being made LCG-shaped by mistake — it is
    // gated on `isPrng`, covering the whole family, not on one variant.
    const { container } = render(() => <App />);
    useGenerator(container, "minstd-rand0");
    expect(readError(container)).toBe("");
    // Seed 1 ⇒ first word 16807 = 0x000041a7.
    expect(readResultHex(container).slice(0, 8)).toBe("000041a7");
  });

  it("rejects a seed of the wrong width for the ACTIVE generator", () => {
    // The seed widths differ across the family (4 bytes vs 32), so the
    // validation is a per-variant table lookup. Switching from an LCG to the
    // CSPRNG swaps the default seed; typing a 4-byte seed under the CSPRNG must
    // be named as a width error rather than silently coerced by the runtime
    // into a valid-looking stream from the wrong starting value.
    const { container } = render(() => <App />);
    useGenerator(container, "chacha20-csprng");

    const field = findInputByLabel(container, "seed");
    if (!field) throw new Error("seed field not found");
    fireEvent.input(field, { target: { value: "00000001" } });
    fireEvent.blur(field);
    fireEvent.click(findButton(container, "run"));

    expect(readError(container)).toContain("32-byte seed");
  });
});
