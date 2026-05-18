// @vitest-environment jsdom

/**
 * RoundKeyPanel — component + pure-detection test. Two layers:
 *
 *   1. `detectRoundKeySequences` — the aux-walking logic exercised in
 *      isolation across happy path + edge cases (empty, single-entry,
 *      mixed lengths, non-Uint8Array, multiple prefixes).
 *
 *   2. `<RoundKeyPanel />` rendered against a real AES-128 trace, asserting:
 *      - 11 round-key cells render in one ribbon
 *      - the current-frame outline lands on the right `K_i` for a step
 *        whose `auxRead` contains `roundKey.<n>`
 *      - byte-format toggle re-renders cell text (the TinyMatrix path
 *        re-reads via `useByteFormat`)
 *      - hidden when `finalAux` has no qualifying sequences
 *
 * Uses the live AES-128 spec rather than a hand-built fixture so the test
 * pins the integration with `runSpec` + the real key-expansion executor.
 * Cheap (~50ms) and means a future refactor of the runtime, aux shape, or
 * AES key-expansion executor surfaces here instead of in the browser.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { Aux, AuxValue, MatrixState } from "@/core/types";
import { RoundKeyPanel, detectRoundKeySequences } from "@/ui/components/RoundKeyPanel";
import { __resetByteFormatForTests, setByteFormat } from "@/ui/stores/format";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = () => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
  return trace;
};

describe("detectRoundKeySequences — pure aux-walk", () => {
  it("returns empty for an empty aux map", () => {
    expect(detectRoundKeySequences(new Map())).toEqual([]);
  });

  it("requires at least 2 entries — a single `prefix.0` doesn't qualify as a schedule", () => {
    // A panel with one key is a "key", not a "schedule." If the user only
    // has roundKey.0 in aux (incomplete spec, single-step debug, etc.) the
    // panel should stay hidden rather than render a one-cell ribbon.
    const aux: Aux = new Map([["roundKey.0", new Uint8Array(16)]]);
    expect(detectRoundKeySequences(aux)).toEqual([]);
  });

  it("groups multiple `prefix.N` entries into one sorted sequence", () => {
    // Out-of-order insertion → entries come back sorted by index.
    const aux: Aux = new Map([
      ["roundKey.2", new Uint8Array(16).fill(0x02)],
      ["roundKey.0", new Uint8Array(16).fill(0x00)],
      ["roundKey.1", new Uint8Array(16).fill(0x01)],
    ]);
    const out = detectRoundKeySequences(aux);
    expect(out.length).toBe(1);
    expect(out[0]?.prefix).toBe("roundKey");
    expect(out[0]?.byteLength).toBe(16);
    expect(out[0]?.entries.map((e) => e.index)).toEqual([0, 1, 2]);
  });

  it("rejects a group whose entries have inconsistent byte length", () => {
    // Mixed lengths under one prefix can't render as a uniform ribbon and
    // are almost certainly two unrelated aux buffers that happen to share
    // a naming prefix. Reject the whole group.
    const aux: Aux = new Map([
      ["mixed.0", new Uint8Array(16)],
      ["mixed.1", new Uint8Array(8)],
    ]);
    expect(detectRoundKeySequences(aux)).toEqual([]);
  });

  it("filters out non-Uint8Array values (numbers, States, etc.)", () => {
    // `aux[count]` (a `number`), `aux[blockIndex]` (a `number`), and
    // `aux[blocks]` (a `readonly State[]`) are common entries the panel
    // must ignore. Only Uint8Array values qualify.
    const aux: Aux = new Map<string, AuxValue>([
      ["counter.0", 42],
      ["counter.1", 43],
      ["roundKey.0", new Uint8Array(2)],
      ["roundKey.1", new Uint8Array(2)],
    ]);
    const out = detectRoundKeySequences(aux);
    expect(out.length).toBe(1);
    expect(out[0]?.prefix).toBe("roundKey");
  });

  it("returns multiple sequences sorted alphabetically by prefix", () => {
    // Deterministic render order across re-runs. Future ciphers with
    // multiple schedules (e.g. tweak + round-key) get a stable layout.
    const aux: Aux = new Map([
      ["zeta.0", new Uint8Array(4)],
      ["zeta.1", new Uint8Array(4)],
      ["alpha.0", new Uint8Array(16)],
      ["alpha.1", new Uint8Array(16)],
    ]);
    const out = detectRoundKeySequences(aux);
    expect(out.map((s) => s.prefix)).toEqual(["alpha", "zeta"]);
  });
});

describe("<RoundKeyPanel /> against a real AES-128 trace", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
    __resetTraceForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
  });

  it("renders 11 round-key cells in one ribbon", () => {
    seedAes128Trace();
    const { container } = render(() => <RoundKeyPanel frame={null} />);
    const ribbons = container.querySelectorAll(".round-key-ribbon");
    expect(ribbons.length).toBe(1);
    const cells = container.querySelectorAll(".round-key-cell");
    // AES-128: 11 round keys (K_0 through K_10).
    expect(cells.length).toBe(11);
    // Header reports the shape "11 × 16B" so the user can read the
    // schedule's structure at a glance.
    expect(ribbons[0]?.querySelector(".round-key-ribbon-shape")?.textContent).toContain("11 × 16B");
  });

  it("outlines the K_i whose name appears in the frame's auxRead", () => {
    const trace = seedAes128Trace();
    // Pick any frame that reads `roundKey.3` (round 3's AddRoundKey of the
    // first block — the body of AES iterate-bodies suffixes the stepId with
    // `:b0` but the aux name stays `roundKey.3`).
    const frame = trace.frames.find((f) => Array.from(f.auxRead.keys()).includes("roundKey.3"));
    expect(frame).toBeDefined();
    const { container } = render(() => <RoundKeyPanel frame={frame ?? null} />);
    const cells = container.querySelectorAll(".round-key-cell");
    // Exactly one cell carries the current-outline class — K_3.
    const outlined = Array.from(cells).filter((c) =>
      c.classList.contains("round-key-cell-current"),
    );
    expect(outlined.length).toBe(1);
    // The `title` attribute carries the full aux name so power users can
    // see exactly which auxName they're looking at — used here as a
    // selector to assert the right K_i lit up.
    expect(outlined[0]?.getAttribute("title")).toBe("roundKey.3");
  });

  it("highlights nothing when the current frame consumes no roundKey aux", () => {
    const trace = seedAes128Trace();
    // The very first frame (input pad / key-expansion) writes aux but does
    // not consume any roundKey.N. The panel should render but no cell gets
    // the current-outline class.
    const frame = trace.frames[0];
    expect(frame).toBeDefined();
    const { container } = render(() => <RoundKeyPanel frame={frame ?? null} />);
    const outlined = container.querySelectorAll(".round-key-cell-current");
    expect(outlined.length).toBe(0);
  });

  it("re-renders cell text on byte-format toggle", () => {
    seedAes128Trace();
    const { container } = render(() => <RoundKeyPanel frame={null} />);
    // K_0 is the master key bytes (FIPS-197 Appendix B: 00 01 02 … 0f).
    // The first `.tiny-cell` in the document is K_0's [0,0] cell = 0x00.
    const firstTinyCell = container.querySelector(".tiny-cell");
    expect(firstTinyCell?.textContent).toBe("00");
    setByteFormat("decimal");
    // After format change, the SAME element re-renders to "0".
    expect(container.querySelector(".tiny-cell")?.textContent).toBe("0");
  });

  it("renders nothing when the finalAux has no qualifying sequences", () => {
    // Don't seed a trace; useTraceFinalAux returns null on early boot.
    // The Show guard at the top of RoundKeyPanel hides the section
    // entirely — no orphan empty container in the DOM.
    const { container } = render(() => <RoundKeyPanel frame={null} />);
    expect(container.querySelector(".round-key-panel")).toBeNull();
  });
});

// ─── Cipher-agnostic claim: empirical coverage at the COMPONENT layer ────
//
// `detectRoundKeySequences`'s pure tests cover the 16-byte and other-length
// branches in isolation. These two integration tests pin the component-layer
// render path for the high-count case (Serpent's 33-cell ribbon) and the
// fallback-strip case (Speck32/64's 2-byte subkeys). Without them the
// "cipher-agnostic by construction" headline claim would be only
// theoretically true — a Solid-reactivity bug specific to the fallback
// branch, or a DOM-quantity bug at N=33, would slip through unnoticed.

const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const SERPENT128_PT = "00112233445566778899aabbccddeeff";

const seedSerpent128Trace = () => {
  const trace = runSpec(serpent128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SERPENT128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
  });
  setTrace(trace);
  return trace;
};

describe("<RoundKeyPanel /> against a real Serpent-128 trace (high-count)", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
    __resetTraceForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
  });

  it("renders 33 round-key cells in one ribbon at 16B each", () => {
    seedSerpent128Trace();
    const { container } = render(() => <RoundKeyPanel frame={null} />);
    const ribbons = container.querySelectorAll(".round-key-ribbon");
    expect(ribbons.length).toBe(1);
    // Serpent: 33 round keys (K_0 through K_32, one more than the 32-round
    // count to cover the final post-whitening AddRoundKey).
    expect(container.querySelectorAll(".round-key-cell").length).toBe(33);
    expect(ribbons[0]?.querySelector(".round-key-ribbon-shape")?.textContent).toContain("33 × 16B");
  });

  it("uses the TinyMatrix render path (not the fallback strip) for 16-byte keys", () => {
    seedSerpent128Trace();
    const { container } = render(() => <RoundKeyPanel frame={null} />);
    // All 33 cells take the TinyMatrix branch — 16 × 33 = 528 tiny cells.
    // The fallback strip class must be entirely absent.
    expect(container.querySelectorAll(".tiny-matrix").length).toBe(33);
    expect(container.querySelectorAll(".round-key-cell-strip").length).toBe(0);
  });
});

const SPECK32_64_KEY = "1918111009080100";
const SPECK32_64_PT = "6574694c";

const seedSpeck32_64Trace = () => {
  const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SPECK32_64_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SPECK32_64_KEY)]]),
  });
  setTrace(trace);
  return trace;
};

describe("<RoundKeyPanel /> against a real Speck32/64 trace (fallback-strip path)", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
    __resetTraceForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
  });

  it("renders 22 subkey cells in one ribbon at 2B each", () => {
    seedSpeck32_64Trace();
    const { container } = render(() => <RoundKeyPanel frame={null} />);
    const ribbons = container.querySelectorAll(".round-key-ribbon");
    expect(ribbons.length).toBe(1);
    // Speck32/64: 22 round subkeys, each `wordBits/8 = 16/8 = 2` bytes.
    expect(container.querySelectorAll(".round-key-cell").length).toBe(22);
    expect(ribbons[0]?.querySelector(".round-key-ribbon-shape")?.textContent).toContain("22 × 2B");
  });

  it("takes the byteLength !== 16 fallback branch (strip cells, no TinyMatrix)", () => {
    // The whole point of this test: pin the *alternate* render branch in
    // `RoundKeyCell`. Pure detection's mixed-length test catches the
    // sequence-detection logic; this catches a Solid-reactivity or shape-
    // dispatch bug specific to the fallback path that pure tests can't see.
    seedSpeck32_64Trace();
    const { container } = render(() => <RoundKeyPanel frame={null} />);
    // 22 cells use the strip branch.
    expect(container.querySelectorAll(".round-key-cell-strip").length).toBe(22);
    // And TinyMatrix never gets used for 2-byte subkeys.
    expect(container.querySelectorAll(".tiny-matrix").length).toBe(0);
    // Each strip carries exactly 2 byte cells.
    const firstStrip = container.querySelector(".round-key-cell-strip");
    expect(firstStrip?.querySelectorAll(".round-key-cell-byte").length).toBe(2);
  });
});

// Discarded-export sanity: the `MatrixState` synthesis path inside
// RoundKeyCell relies on the buffer being readable as a column-major 16B
// matrix. Pin the type-import here so a future tightening of `MatrixState`
// (e.g. requiring a non-aliased buffer) is visible at the test file.
const _matrixStateTypeFootprint: MatrixState = {
  shape: "matrix4x4-bytes",
  bytes: new Uint8Array(16),
};
void _matrixStateTypeFootprint;
