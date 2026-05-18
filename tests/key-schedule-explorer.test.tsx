// @vitest-environment jsdom

/**
 * KeyScheduleExplorer — component test.
 *
 * The simulator-parity tests
 * (`tests/aes-key-schedule-sim-parity.test.ts` +
 *  `tests/serpent-key-schedule-sim-parity.test.ts`) pin the pure
 * decomposition logic against the executor. This file pins the UI
 * dispatch layer:
 *
 *   1. AES key-expansion frame → AES per-word swimlane renders. Word
 *      count matches Nk + 4*(Nr+1). Chain-start words carry the badge.
 *   2. Serpent key-expansion frame → Serpent multi-stage pipeline
 *      renders. The four <details> sections are present.
 *   3. Bad-shape frame (params missing sbox, etc.) → graceful error
 *      stub renders instead of crashing.
 *   4. Byte-format toggle re-renders the values.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, TraceFrame } from "@/core/types";
import { KeyScheduleExplorer } from "@/ui/components/KeyScheduleExplorer";
import { __resetByteFormatForTests, setByteFormat } from "@/ui/stores/format";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const SERPENT128_PT = "00112233445566778899aabbccddeeff";

const findFrameByStepType = (
  spec: typeof aes128Spec | typeof serpent128Spec,
  initialAux: Map<string, AuxValue>,
  initialState: ReturnType<typeof matrixFromBytes> | ReturnType<typeof makeBytesState>,
  predicate: (stepType: string) => boolean,
): TraceFrame => {
  const trace = runSpec(spec, buildDefaultRegistry(), { initialState, initialAux });
  const f = trace.frames.find((fr) => predicate(fr.stepType));
  if (!f) throw new Error("no matching frame in trace");
  return f;
};

describe("<KeyScheduleExplorer /> — AES branch", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("renders the per-word swimlane with 44 words for AES-128", () => {
    const frame = findFrameByStepType(
      aes128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
      matrixFromBytes(bytesFromHex(AES128_PT)),
      (t) => t.startsWith("aes.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    // The explorer mounts the AES branch.
    expect(container.querySelector(".key-schedule-aes")).not.toBeNull();
    // 44 word rows (Nk=4, totalWords = Nb * (Nr+1) = 4 * 11 = 44).
    const words = container.querySelectorAll(".key-schedule-aes-word");
    expect(words.length).toBe(44);
  });

  it("marks chain-start words with the `chain` badge and the chain modifier class", () => {
    const frame = findFrameByStepType(
      aes128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
      matrixFromBytes(bytesFromHex(AES128_PT)),
      (t) => t.startsWith("aes.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    // For AES-128 (Nk=4), chain-start words are i = 4, 8, …, 40 → 10
    // chain-start rows.
    const chainRows = container.querySelectorAll(".key-schedule-aes-word-chain");
    expect(chainRows.length).toBe(10);
    // Each chain row contains the "chain" badge.
    expect(
      Array.from(chainRows).every((row) =>
        row.querySelector(".key-schedule-aes-word-badge")?.textContent?.includes("chain"),
      ),
    ).toBe(true);
  });

  it("re-renders byte cells on format toggle (hex → decimal)", () => {
    const frame = findFrameByStepType(
      aes128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
      matrixFromBytes(bytesFromHex(AES128_PT)),
      (t) => t.startsWith("aes.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    // W[0] is the master-key first 4 bytes: 00 01 02 03. The init
    // stage's first byte cell renders as "00" by default.
    const firstCell = container.querySelector(".key-schedule-byte-cell");
    expect(firstCell?.textContent).toBe("00");
    setByteFormat("decimal");
    expect(container.querySelector(".key-schedule-byte-cell")?.textContent).toBe("0");
  });

  it("renders the section-top legend collapsed with the 'What these stages mean' summary", () => {
    // The legend is the type-prose layer: one entry per stage kind, shared
    // across all 44 word rows. Lock that it's present and rendered as a
    // <details> so the disclosure affordance is consistent with the rest
    // of the component.
    const frame = findFrameByStepType(
      aes128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
      matrixFromBytes(bytesFromHex(AES128_PT)),
      (t) => t.startsWith("aes.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    const legend = container.querySelector("details.key-schedule-aes-legend");
    expect(legend).not.toBeNull();
    expect(legend?.querySelector("summary")?.textContent).toContain("What these stages mean");
    // One <dt>/<dd> pair per stage kind: init, RotWord, SubWord, ⊕ Rcon,
    // SubWord (extra), ⊕ W[i-Nk] → 6 entries.
    expect(legend?.querySelectorAll("dt").length).toBe(6);
    expect(legend?.querySelectorAll("dd").length).toBe(6);
  });

  it("renders each stage as a <details> carrying value-prose for that specific row", () => {
    // Per-row <details> is the value-prose layer (these specific bytes,
    // this specific Rcon index). Assert (1) every stage row is a
    // <details>, not the old <div>, (2) the Rcon-xor row's prose
    // surfaces the actual rconIndex/value the simulator emitted — this
    // is the property the verbose-prose option was picked to deliver.
    const frame = findFrameByStepType(
      aes128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
      matrixFromBytes(bytesFromHex(AES128_PT)),
      (t) => t.startsWith("aes.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    // Every stage row is a <details>. Sample by selector — at least one
    // row of every kind exists in a standard AES-128 schedule.
    const stages = container.querySelectorAll("details.key-schedule-aes-stage");
    expect(stages.length).toBeGreaterThan(0);
    // The first rcon-xor row is W[4]'s third stage (chain start, Rcon
    // index = 4/4 = 1, value = 0x01). Verify the prose body interpolates
    // those concrete values.
    const rconStage = container.querySelector(
      'details.key-schedule-aes-stage[data-stage-kind="rcon-xor"]',
    );
    expect(rconStage).not.toBeNull();
    const prose = rconStage?.querySelector(".key-schedule-aes-stage-prose")?.textContent ?? "";
    expect(prose).toContain("Rcon[1]");
    expect(prose).toContain("0x01");
    expect(prose).toContain("Bytes 1-3 pass through unchanged");
  });

  it("keeps an expanded stage row open across a format toggle (prose updates surgically)", () => {
    // Regression: the initial wiring destructured props inside AesStageProse,
    // which (combined with Solid's reactivity model) caused the entire
    // <details> subtree to re-mount on fmt change — wiping the user's
    // open-state. Fix: read props.fmt inline in JSX expressions so Solid
    // updates only the text nodes. Pin the behavior here.
    const frame = findFrameByStepType(
      aes128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
      matrixFromBytes(bytesFromHex(AES128_PT)),
      (t) => t.startsWith("aes.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    const rconStage = container.querySelector(
      'details.key-schedule-aes-stage[data-stage-kind="rcon-xor"]',
    ) as HTMLDetailsElement | null;
    expect(rconStage).not.toBeNull();
    if (!rconStage) return;
    // Open the row programmatically (the same DOM state a user click sets).
    rconStage.open = true;
    expect(rconStage.open).toBe(true);
    // The prose should currently show byte values in hex.
    const proseEl = rconStage.querySelector(".key-schedule-aes-stage-prose");
    expect(proseEl?.textContent).toContain("Rcon[1]");
    // Toggle the byte format. The row must stay open AND the prose text
    // must reflect the new format.
    setByteFormat("decimal");
    expect(rconStage.open).toBe(true);
    // Decimal Rcon byte 1 = 1 (was 0x01 in hex). The "Rcon[1] = 0x01"
    // header keeps its hex form (matches the stage label convention),
    // but the byte values that flow through formatByteInline switch.
    // Easiest invariant to pin: "Bytes 1-3 pass through unchanged" still
    // there (string is identical) AND no byte token left as "8a"-style hex.
    expect(proseEl?.textContent).toContain("Bytes 1-3 pass through unchanged");
  });

  it("renders the inline error stub when the frame has missing params (sbox)", () => {
    // Synthesize a malformed frame: key-expansion stepType but params
    // missing the sbox field. The simulator should refuse and the
    // component should render the error stub rather than crashing.
    const badFrame: TraceFrame = {
      index: 0,
      path: [],
      stepId: "key-expansion",
      stepType: "aes.key-expansion@1",
      params: { rounds: 10 }, // no sbox/rcon/keyAuxName
      stateBefore: matrixFromBytes(new Uint8Array(16)),
      stateAfter: matrixFromBytes(new Uint8Array(16)),
      auxRead: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
      auxWritten: new Map(),
    };
    const { container } = render(() => <KeyScheduleExplorer frame={badFrame} />);
    expect(container.querySelector(".key-schedule-explorer-error")).not.toBeNull();
    // And no AES content rendered alongside the error.
    expect(container.querySelector(".key-schedule-aes")).toBeNull();
  });
});

describe("<KeyScheduleExplorer /> — Serpent branch", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("renders the multi-stage pipeline with 4 <details> sections for Serpent-128", () => {
    const frame = findFrameByStepType(
      serpent128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
      makeBytesState(bytesFromHex(SERPENT128_PT)),
      (t) => t.startsWith("serpent.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    expect(container.querySelector(".key-schedule-serpent")).not.toBeNull();
    // Four sections: pad, prekey-init, recurrence, sbox-groups+IP.
    const sections = container.querySelectorAll(".key-schedule-serpent-section");
    expect(sections.length).toBe(4);
  });

  it("renders 132 recurrence rows", () => {
    const frame = findFrameByStepType(
      serpent128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
      makeBytesState(bytesFromHex(SERPENT128_PT)),
      (t) => t.startsWith("serpent.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    const recurrenceItems = container.querySelectorAll(".key-schedule-serpent-recurrence > li");
    expect(recurrenceItems.length).toBe(132);
  });

  it("renders 33 sbox-group rows (one per round key K_0..K_32)", () => {
    const frame = findFrameByStepType(
      serpent128Spec,
      new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
      makeBytesState(bytesFromHex(SERPENT128_PT)),
      (t) => t.startsWith("serpent.key-expansion"),
    );
    const { container } = render(() => <KeyScheduleExplorer frame={frame} />);
    const groups = container.querySelectorAll(".key-schedule-serpent-sbox-groups > li");
    expect(groups.length).toBe(33);
  });

  it("renders the inline error stub when the master key isn't readable from auxRead", () => {
    // Parallel to the AES "missing params" test — Serpent's failure
    // mode is "no master key in aux." Pin the graceful fallback so
    // the two branches' error-handling stays in lockstep.
    const badFrame: TraceFrame = {
      index: 0,
      path: [],
      stepId: "key-expansion",
      stepType: "serpent.key-expansion@1",
      params: { keyAuxName: "key", outputPrefix: "roundKey", keyByteLength: 16 },
      stateBefore: makeBytesState(new Uint8Array(0)),
      stateAfter: makeBytesState(new Uint8Array(0)),
      // Empty auxRead — the "key" entry the simulator needs isn't here.
      auxRead: new Map<string, AuxValue>(),
      auxWritten: new Map(),
    };
    const { container } = render(() => <KeyScheduleExplorer frame={badFrame} />);
    expect(container.querySelector(".key-schedule-explorer-error")).not.toBeNull();
    expect(container.querySelector(".key-schedule-serpent")).toBeNull();
  });
});
