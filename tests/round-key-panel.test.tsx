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
import { desSpec } from "@/ciphers/des";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { Aux, AuxValue } from "@/core/types";
import {
  RoundKeyPanel,
  __resetRoundKeyPanelOverrideForTests,
  detectRoundKeySequences,
} from "@/ui/components/RoundKeyPanel";
import { __resetByteFormatForTests, setByteFormat } from "@/ui/stores/format";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = () => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
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
    __resetRoundKeyPanelOverrideForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetRoundKeyPanelOverrideForTests();
  });

  it("renders 11 round-key cells in one ribbon", () => {
    const trace = seedAes128Trace();
    // Since the key-schedule decomposition (K1c) the frame that WRITES the
    // whole schedule is the `key-schedule.publish` tail (its auxWritten holds
    // every roundKey.N) — a "relevant" frame, so the panel body auto-expands
    // and the ribbon is visible without a click. (frame[0] is now the
    // `key-schedule.load-key` frame, which is not schedule-relevant.)
    const publishFrame = trace.frames.find((f) => f.stepId === "key-schedule.publish") ?? null;
    const { container } = render(() => <RoundKeyPanel frame={publishFrame} />);
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
    const trace = seedAes128Trace();
    const publishFrame = trace.frames.find((f) => f.stepId === "key-schedule.publish") ?? null;
    const { container } = render(() => <RoundKeyPanel frame={publishFrame} />);
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
    // Serpent's round body is port-native since B3 → the spec requires ported dispatch.
  });
  setTrace(trace);
  return trace;
};

describe("<RoundKeyPanel /> against a real Serpent-128 trace (high-count)", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetRoundKeyPanelOverrideForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetRoundKeyPanelOverrideForTests();
  });

  // K3a (2026-06-02): Serpent's key schedule was decomposed, so the round-key
  // writes happen at the `key-schedule.publish` tail (its auxWritten holds
  // every roundKey.N) rather than the old monolithic `serpent.key-expansion@1`
  // frame[0]. The panel's `isRelevantFrame` gate fires only on a frame "about"
  // the schedule — select the publish frame so it opens. Same retarget the
  // Speck (K2a) and AES (K1a) blocks above already use.
  const publishFrame = (trace: ReturnType<typeof seedSerpent128Trace>) =>
    trace.frames.find((f) => f.stepId === "key-schedule.publish") ?? null;

  it("renders 33 round-key cells in one ribbon at 16B each", () => {
    const trace = seedSerpent128Trace();
    const { container } = render(() => <RoundKeyPanel frame={publishFrame(trace)} />);
    const ribbons = container.querySelectorAll(".round-key-ribbon");
    expect(ribbons.length).toBe(1);
    // Serpent: 33 round keys (K_0 through K_32, one more than the 32-round
    // count to cover the final post-whitening AddRoundKey).
    expect(container.querySelectorAll(".round-key-cell").length).toBe(33);
    expect(ribbons[0]?.querySelector(".round-key-ribbon-shape")?.textContent).toContain("33 × 16B");
  });

  it("uses the TinyMatrix render path (not the fallback strip) for 16-byte keys", () => {
    const trace = seedSerpent128Trace();
    const { container } = render(() => <RoundKeyPanel frame={publishFrame(trace)} />);
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
    // Speck rounds are port-native since B2 → the spec requires ported dispatch.
  });
  setTrace(trace);
  return trace;
};

describe("<RoundKeyPanel /> against a real Speck32/64 trace (fallback-strip path)", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetRoundKeyPanelOverrideForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetRoundKeyPanelOverrideForTests();
  });

  // K2a (2026-06-01): the round-key panel's `expanded()` gate fires only on a
  // frame "about" the schedule (auxRead or auxWritten of a roundKey.*). Pre-K2a
  // that was frame[0] (the monolithic `speck.key-schedule@1` writing all 22
  // keys). Post-decomposition the writes happen at the publish tail leaf, and
  // the rounds consume specific roundKey.{i} entries — use the publish frame
  // here so the panel opens.
  const publishOrFirstRound = (trace: ReturnType<typeof seedSpeck32_64Trace>) =>
    trace.frames.find((f) => f.stepId === "key-schedule.publish") ?? null;

  it("renders 22 subkey cells in one ribbon at 2B each", () => {
    const trace = seedSpeck32_64Trace();
    const { container } = render(() => <RoundKeyPanel frame={publishOrFirstRound(trace)} />);
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
    const trace = seedSpeck32_64Trace();
    const { container } = render(() => <RoundKeyPanel frame={publishOrFirstRound(trace)} />);
    // 22 cells use the strip branch.
    expect(container.querySelectorAll(".round-key-cell-strip").length).toBe(22);
    // And TinyMatrix never gets used for 2-byte subkeys.
    expect(container.querySelectorAll(".tiny-matrix").length).toBe(0);
    // Each strip carries exactly 2 byte cells.
    const firstStrip = container.querySelector(".round-key-cell-strip");
    expect(firstStrip?.querySelectorAll(".round-key-cell-byte").length).toBe(2);
  });
});

// ─── DES (Phase 5d of `docs/plans/des-feistel.md`) ─────────────────────
//
// DES round keys are 48 bits = 6 bytes each. The existing fallback-strip
// path (byteLength !== 16) handles them as-is — six side-by-side hex
// cells per K_i, 16 keys total. Phase 5d verifies that the existing
// shape covers DES correctly so the bit-grouped affordance the plan
// originally proposed isn't actually needed at MVP. If a future browser
// smoke shows users want the 8-groups-of-6-bits unfold, that's an
// additive follow-up gated by user feedback rather than this phase.

const DES_KEY = new Uint8Array([0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]);
const DES_PT = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

const seedDesTrace = () => {
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(DES_PT),
    initialAux: new Map<string, AuxValue>([["key", DES_KEY]]),
  });
  setTrace(trace);
  return trace;
};

describe("<RoundKeyPanel /> against a real DES trace (fallback-strip path, 6B keys)", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetRoundKeyPanelOverrideForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetRoundKeyPanelOverrideForTests();
  });

  it("renders 16 round-key cells in one ribbon at 6B each", () => {
    const trace = seedDesTrace();
    const { container } = render(() => <RoundKeyPanel frame={trace.frames[0] ?? null} />);
    const ribbons = container.querySelectorAll(".round-key-ribbon");
    expect(ribbons.length).toBe(1);
    // DES: 16 round keys (K_0..K_15), each 48 bits packed into 6 bytes.
    expect(container.querySelectorAll(".round-key-cell").length).toBe(16);
    expect(ribbons[0]?.querySelector(".round-key-ribbon-shape")?.textContent).toContain("16 × 6B");
  });

  it("each K_i ribbon cell renders 6 byte cells via the strip branch (no TinyMatrix)", () => {
    const trace = seedDesTrace();
    const { container } = render(() => <RoundKeyPanel frame={trace.frames[0] ?? null} />);
    // All 16 ribbons use the strip fallback (byteLength !== 16 path).
    expect(container.querySelectorAll(".round-key-cell-strip").length).toBe(16);
    // No TinyMatrix anywhere — DES K_i is 6 bytes, never 16.
    expect(container.querySelectorAll(".tiny-matrix").length).toBe(0);
    // Each strip carries exactly 6 byte cells.
    const firstStrip = container.querySelector(".round-key-cell-strip");
    expect(firstStrip?.querySelectorAll(".round-key-cell-byte").length).toBe(6);
  });

  it("outlines the current K_i when scrubbed onto an xor-K frame that reads it", () => {
    const trace = seedDesTrace();
    // round.3.xor-K consumes roundKey.2 (encrypt round r uses K_{r-1}).
    const frame = trace.frames.find(
      (f) => f.stepId.startsWith("round.3.xor-K") && f.auxRead.has("roundKey.2"),
    );
    expect(frame).toBeDefined();
    const { container } = render(() => <RoundKeyPanel frame={frame ?? null} />);
    const currentCells = container.querySelectorAll(".round-key-cell-current");
    expect(currentCells.length).toBe(1);
    // The outlined cell's title should reference roundKey.2.
    expect(currentCells[0]?.getAttribute("title")).toBe("roundKey.2");
  });
});

// ─── Collapsible behavior (Option B from 2026-05-18 smoke) ─────────────
//
// The panel ships with a click-to-toggle header so the ribbon doesn't
// crowd ParamEditor on frames that aren't about the schedule. Default
// expanded on key-relevant frames (consumers + producers of `prefix.N`
// aux), default collapsed on others. User click overrides the default
// until the next spec change.

describe("<RoundKeyPanel /> collapsible header", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetRoundKeyPanelOverrideForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
    __resetTraceForTests();
    __resetRoundKeyPanelOverrideForTests();
  });

  it("auto-expands on the key-schedule publish frame (which writes the schedule)", () => {
    const trace = seedAes128Trace();
    // The `key-schedule.publish` tail's auxWritten contains every `roundKey.N`
    // (K1c), so isRelevantFrame returns true → default expanded.
    const publishFrame = trace.frames.find((f) => f.stepId === "key-schedule.publish") ?? null;
    const { container } = render(() => <RoundKeyPanel frame={publishFrame} />);
    expect(container.querySelector(".round-key-panel-body")).not.toBeNull();
    expect(container.querySelectorAll(".round-key-cell").length).toBe(11);
    // Header chevron points down (▼) when expanded.
    expect(container.querySelector(".round-key-panel-chevron")?.textContent).toBe("▼");
  });

  it("auto-expands on an AddRoundKey frame (which reads a schedule key)", () => {
    const trace = seedAes128Trace();
    // Byte-native AES-128 (Slice B1; merged in F3): the round key is read
    // internally by the `xor-with-aux@1` AddRoundKey leaf (`round.3.add-round-key`),
    // whose frame carries `auxRead: roundKey.3`. The panel auto-expands on any
    // frame that reads a schedule key, so this AddRoundKey frame is the trigger.
    const frame = trace.frames.find(
      (f) => f.stepType === "xor-with-aux@1" && f.auxRead.has("roundKey.3"),
    );
    expect(frame).toBeDefined();
    const { container } = render(() => <RoundKeyPanel frame={frame ?? null} />);
    expect(container.querySelector(".round-key-panel-body")).not.toBeNull();
    expect(container.querySelectorAll(".round-key-cell").length).toBe(11);
  });

  it("auto-collapses on a non-relevant frame (SubBytes, ShiftRows, etc.)", () => {
    const trace = seedAes128Trace();
    const frame = trace.frames.find((f) => f.stepType === "byte-substitute@1");
    expect(frame).toBeDefined();
    const { container } = render(() => <RoundKeyPanel frame={frame ?? null} />);
    // Header is rendered (sequences exist) but body is gone.
    expect(container.querySelector(".round-key-panel-header")).not.toBeNull();
    expect(container.querySelector(".round-key-panel-body")).toBeNull();
    expect(container.querySelectorAll(".round-key-cell").length).toBe(0);
    // Chevron points right (▶) when collapsed.
    expect(container.querySelector(".round-key-panel-chevron")?.textContent).toBe("▶");
  });

  it("clicking the header toggles collapsed → expanded", () => {
    const trace = seedAes128Trace();
    const subBytesFrame = trace.frames.find((f) => f.stepType === "byte-substitute@1");
    expect(subBytesFrame).toBeDefined();
    const { container } = render(() => <RoundKeyPanel frame={subBytesFrame ?? null} />);
    // Default collapsed.
    expect(container.querySelector(".round-key-panel-body")).toBeNull();
    // Click the header.
    fireEvent.click(container.querySelector(".round-key-panel-header") as Element);
    // Now expanded.
    expect(container.querySelector(".round-key-panel-body")).not.toBeNull();
    expect(container.querySelectorAll(".round-key-cell").length).toBe(11);
  });

  it("clicking the header toggles expanded → collapsed", () => {
    const trace = seedAes128Trace();
    const publishFrame = trace.frames.find((f) => f.stepId === "key-schedule.publish");
    expect(publishFrame).toBeDefined();
    const { container } = render(() => <RoundKeyPanel frame={publishFrame ?? null} />);
    // Default expanded (the schedule-writing publish frame).
    expect(container.querySelector(".round-key-panel-body")).not.toBeNull();
    // Click the header to hide.
    fireEvent.click(container.querySelector(".round-key-panel-header") as Element);
    // Now collapsed.
    expect(container.querySelector(".round-key-panel-body")).toBeNull();
  });

  it("does not render any header chrome when no schedule exists (panel fully hidden)", () => {
    // No trace seeded → useTraceFinalAux returns null → no sequences →
    // outer Show short-circuits the whole panel including the header.
    const { container } = render(() => <RoundKeyPanel frame={null} />);
    expect(container.querySelector(".round-key-panel")).toBeNull();
    expect(container.querySelector(".round-key-panel-header")).toBeNull();
  });
});

// (The `MatrixState` type-footprint pin was removed in Phase 5 Slice 5.1
// (2026-05-30) with the MatrixState shape — RoundKeyCell now renders round
// keys via TinyMatrix's raw-bytes prop, no MatrixState synthesis.)
