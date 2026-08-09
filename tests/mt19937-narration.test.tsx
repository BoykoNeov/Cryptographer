// @vitest-environment jsdom
/**
 * MT19937 monolith narration — the two disclosure-row narrators.
 *
 * These exist because `mt19937.seed@1` and `mt19937.twist@1` are opaque single
 * frames. A static description alone asks the learner to take 624 steps on
 * faith; the rows carry the REAL words this run produced. So what these tests
 * check is not "prose rendered" but **that the prose reports the frame's own
 * values** — a narrator that recomputed the algorithm, or printed constants,
 * would pass a render test and defeat the purpose.
 *
 * Both narrators are driven through the real runtime rather than a synthetic
 * frame, so what is asserted is what the app actually shows.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { MT_SEED_ID, MT_TWIST_ID, buildMt19937Spec } from "@/ciphers/mt19937";
import { runSpec } from "@/core/runtime";
import type { AuxValue, TraceFrame } from "@/core/types";
import { initGenrand } from "@/steps/mt19937-seed";
import { twist } from "@/steps/mt19937-twist";
import { render } from "@solidjs/testing-library";
import "@/ui/narration/index";
import { mt19937SeedNarration, mt19937TwistNarration } from "@/ui/narration/mt19937";
import { lookupNarration } from "@/ui/narration/registry";
import { describe, expect, it } from "vitest";

const DEFAULT_SEED = 5489;

const seedBytes = (seed: number): Uint8Array =>
  new Uint8Array([(seed >>> 24) & 0xff, (seed >>> 16) & 0xff, (seed >>> 8) & 0xff, seed & 0xff]);

/** Run the real spec and pull out one frame by step id. */
const frameFor = (stepId: string, seed = DEFAULT_SEED): TraceFrame => {
  const trace = runSpec(buildMt19937Spec(16), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: seedBytes(seed) },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  const frame = trace.frames.find((f) => f.stepId === stepId);
  if (frame === undefined) throw new Error(`no frame for ${stepId}`);
  return frame;
};

/**
 * Byte values render as `[9a, 49, 04, 3d]`, so a naive whitespace strip leaves
 * the commas and brackets in and every hex comparison fails. Strip those too —
 * but nothing else, so adjacent VALUES cannot accidentally join into a match.
 */
const hexNormalize = (s: string): string => s.toLowerCase().replace(/[\s,[\]]/g, "");

/** Render every unit's prose and return the concatenated text. */
const proseText = (units: ReturnType<typeof mt19937SeedNarration>): string => {
  if (units === null) throw new Error("narrator declined");
  return units
    .map((u) => {
      const { container } = render(() => <u.Prose fmt="hex" />);
      return `${u.label}\n${container.textContent ?? ""}`;
    })
    .join("\n");
};

describe("mt19937.seed@1 narration", () => {
  it("reports the state words THIS run produced, not recomputed ones", () => {
    const units = mt19937SeedNarration(frameFor(MT_SEED_ID));
    const text = hexNormalize(proseText(units));
    const mt = initGenrand(DEFAULT_SEED);

    // mt[0] is the seed verbatim; mt[1] and mt[2] come from the recurrence.
    // Asserting the HEX of the real words is what proves the rows read the
    // frame rather than printing prose about an algorithm.
    for (const i of [0, 1, 2]) {
      const hex = (mt[i] as number).toString(16).padStart(8, "0");
      // Rendered as byte groups, so compare on the whitespace-stripped text.
      expect(text).toContain(hex);
    }
  });

  it("shows BOTH ends of the state, so a damaged middle cannot hide", () => {
    const units = mt19937SeedNarration(frameFor(MT_SEED_ID));
    const text = hexNormalize(proseText(units));
    const mt = initGenrand(DEFAULT_SEED);
    for (const i of [621, 622, 623]) {
      expect(text).toContain((mt[i] as number).toString(16).padStart(8, "0"));
    }
  });

  it("tracks a different seed", () => {
    // The strongest check that nothing is hardcoded: same rows, other numbers.
    const units = mt19937SeedNarration(frameFor(MT_SEED_ID, 1));
    const text = hexNormalize(proseText(units));
    const mt = initGenrand(1);
    expect(text).toContain((mt[1] as number).toString(16).padStart(8, "0"));
    // And NOT the default seed's words.
    const other = initGenrand(DEFAULT_SEED);
    expect(text).not.toContain((other[1] as number).toString(16).padStart(8, "0"));
  });

  it("names the loop index as the reason it is one step", () => {
    const text = proseText(mt19937SeedNarration(frameFor(MT_SEED_ID)));
    expect(text).toContain("loop counter");
    // And the seeding-convention trap, which is the family's documented hazard.
    expect(text).toContain("init_by_array");
  });

  it("declines on a frame whose ports are the wrong shape", () => {
    const bogus = { portInputs: new Map(), portOutputs: new Map() } as unknown as TraceFrame;
    expect(mt19937SeedNarration(bogus)).toBeNull();
  });
});

describe("mt19937.twist@1 narration", () => {
  it("shows the splice operands and the resulting word from this run", () => {
    const units = mt19937TwistNarration(frameFor(MT_TWIST_ID));
    const text = hexNormalize(proseText(units));
    const before = initGenrand(DEFAULT_SEED);
    const after = twist(before);

    // The two words spliced, the word 397 along, and the new mt[0].
    for (const w of [before[0], before[1], before[397], after[0]]) {
      expect(text).toContain((w as number).toString(16).padStart(8, "0"));
    }
  });

  it("reports whether the twist constant was applied, matching the low bit", () => {
    const units = mt19937TwistNarration(frameFor(MT_TWIST_ID));
    if (units === null) throw new Error("declined");
    const before = initGenrand(DEFAULT_SEED);
    const y = (((before[0] as number) & 0x80000000) | ((before[1] as number) & 0x7fffffff)) >>> 0;
    const applied = (y & 1) === 1;

    const label = units.find((u) => u.key === "twist")?.label ?? "";
    // The label states the branch taken; it must agree with the actual bit.
    expect(label).toContain(applied ? "XORed in" : "skipped");
  });

  it("shows the in-place wrap with the OLD and NEW word at index 227", () => {
    // 227 + 397 = 624 = 0 mod 624, so mt[227] is the first word built from a
    // word this same loop already rewrote. Showing both values is the only way
    // a reader can see that the loop is not parallel.
    const units = mt19937TwistNarration(frameFor(MT_TWIST_ID));
    const text = hexNormalize(proseText(units));
    const before = initGenrand(DEFAULT_SEED);
    const after = twist(before);
    expect(text).toContain((before[227] as number).toString(16).padStart(8, "0"));
    expect(text).toContain((after[227] as number).toString(16).padStart(8, "0"));
  });

  it("attributes the weakness to GF(2) linearity", () => {
    const text = proseText(mt19937TwistNarration(frameFor(MT_TWIST_ID)));
    expect(text).toContain("linear over GF(2)");
    expect(text).toContain("0x9908b0df");
  });

  it("declines on a frame whose ports are the wrong shape", () => {
    const bogus = { portInputs: new Map(), portOutputs: new Map() } as unknown as TraceFrame;
    expect(mt19937TwistNarration(bogus)).toBeNull();
  });
});

describe("the registry actually dispatches to them", () => {
  it("looks up both monolith step types", () => {
    // A narrator that is written but never REGISTERED renders nothing in the
    // app, and no other test in this file would notice — every one of them
    // calls the fn directly.
    //
    // Imported statically at the top of this file rather than dynamically
    // here: a `await import("@/ui/narration/index")` inside the test pulls the
    // whole narration barrel (every `.tsx` narrator) through the transform on
    // a cold cache, which took 21s once and tripped the test timeout. Static
    // imports are transformed during collection, where the budget is.
    expect(lookupNarration("mt19937.seed@1")).toBeDefined();
    expect(lookupNarration("mt19937.twist@1")).toBeDefined();
  });
});
