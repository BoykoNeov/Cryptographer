/**
 * MINSTD known-answer tests — the app's first pseudo-random generators.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ORACLE, AND WHY IT IS THE STRONGEST ONE IN THE REPO.
 *
 * `node:crypto` has no random-number generator whose sequence is reproducible
 * from a seed, so there is no live oracle here — the same position Salsa20 is
 * in. What MINSTD has instead is better: **a conformance requirement in an ISO
 * standard.**
 *
 * ISO/IEC 14882 (C++) §rand.predef specifies both generators shipped here and
 * states, normatively, the value each must produce on its 10000th consecutive
 * invocation from the default seed of 1:
 *
 *     std::minstd_rand0  (a = 16807)  →  1043618065
 *     std::minstd_rand   (a = 48271)  →  399268537
 *
 * Those two literals are the anchor of this file. They are not derived from
 * this codebase, not transcribed from a blog, and not recomputed by anything
 * that shares a line of code with the spec under test. They occupy the same
 * role FIPS-197 §C.1 does for AES-128.
 *
 * Everything else is chained to them:
 *
 *   1. `refStream` below is an independent reference — eight lines of `BigInt`
 *      arithmetic written from the recurrence, sharing no registry, no runtime,
 *      no port, and no `Uint8Array` with the spec.
 *   2. `refStream` is pinned against both ISO values (test group 1). If the
 *      reference were wrong, that test fails.
 *   3. The spec, run through the real runtime, is pinned against `refStream`
 *      (test group 2). If the wiring were wrong, that test fails.
 *
 * The 10000th value is reached through the reference, not the runtime,
 * deliberately: at 4 bytes per word it would take a 40,000-byte request and
 * ~10,000 traced iterations to reach it through the spec — far past the app's
 * trace-legibility ceiling and slow enough to matter in CI. Step 3 is what
 * connects the short traced runs to the long reference run.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * SEEDING CONVENTION — the thing most likely to be silently wrong.
 *
 * Generators differ from one another mainly in how they seed, and a mismatched
 * convention yields a stream that is perfectly self-consistent and matches
 * nothing else in the world. Written down explicitly, therefore:
 *
 *     x_0 = the seed, verbatim. No scrambling, no `init_by_array`, no discarded
 *     warm-up outputs. The first word emitted is `a · seed mod m`.
 *
 * Both ISO values above are under seed = 1, which is `std::minstd_rand`'s
 * `default_seed`. This is the same class of trap as ChaCha20's counter starting
 * at 1 while Salsa20's starts at 0 — two things this repo has already been
 * bitten by.
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  ANSI_C_MODULUS,
  LCG_ITERATE_ID,
  LCG_MULTIPLIER_ID,
  LCG_PARAMS,
  LCG_STATE_ID,
  LCG_WORD_BYTES,
  type LcgParams,
  type LcgVariant,
  MINSTD_MODULUS,
  buildLcgSpec,
  readLcgOutputLength,
} from "@/ciphers/lcg";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Independent reference ────────────────────────────────────────────────

/**
 * The recurrence, in plain `BigInt`. Deliberately shares nothing with the spec
 * under test — no registry lookup, no port binding, no byte array. A wiring bug
 * in the spec cannot reach in here and make both agree.
 *
 * Takes the (a, c, m) triple rather than reading `LCG_PARAMS` itself, so the
 * perturbation tests below can drive it with constants that appear nowhere in
 * the app.
 */
const refWords = (p: LcgParams, seed: number, count: number): bigint[] => {
  const m = BigInt(p.m);
  let x = BigInt(seed);
  const out: bigint[] = [];
  for (let i = 0; i < count; i++) {
    x = (BigInt(p.a) * x + BigInt(p.c)) % m;
    out.push(x);
  }
  return out;
};

/** Shorthand for the multiplicative form, whose modulus is always MINSTD's. */
const mult = (a: number): LcgParams => ({ a, c: 0, m: MINSTD_MODULUS });

/** The reference expressed as a byte stream: each word big-endian, the whole
 *  thing cut to `byteLength`. This is what the spec is expected to produce. */
const refStream = (p: LcgParams, seed: number, byteLength: number): Uint8Array => {
  const words = refWords(p, seed, Math.ceil(byteLength / LCG_WORD_BYTES));
  const out = new Uint8Array(words.length * LCG_WORD_BYTES);
  words.forEach((w, i) => {
    const v = Number(w);
    out[i * 4] = (v >>> 24) & 0xff;
    out[i * 4 + 1] = (v >>> 16) & 0xff;
    out[i * 4 + 2] = (v >>> 8) & 0xff;
    out[i * 4 + 3] = v & 0xff;
  });
  return out.subarray(0, byteLength);
};

// ─── Runtime harness ──────────────────────────────────────────────────────

const seedBytes = (seed: number): Uint8Array =>
  new Uint8Array([(seed >>> 24) & 0xff, (seed >>> 16) & 0xff, (seed >>> 8) & 0xff, seed & 0xff]);

const run = (spec: CipherSpec, seed: number): Uint8Array => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: seedBytes(seed) },
    // Generators are keyless in the symmetric sense; the spec declares
    // `key.byteLength: 0` and nothing reads this entry.
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");
  return trace.finalState.bytes;
};

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** The two multiplicative variants. The mixed ANSI C one has its own sections
 *  at the bottom of this file — it shares a builder, not an oracle. */
type MinstdVariant = "minstd-rand0" | "minstd-rand";
const VARIANTS: readonly MinstdVariant[] = ["minstd-rand0", "minstd-rand"];

// ─── 1. The ISO anchor ────────────────────────────────────────────────────

describe("MINSTD — the ISO/IEC 14882 §rand.predef conformance values", () => {
  // These two literals are the only values in this file that come from outside
  // the repository. Everything else is checked against them.
  const ISO_10000TH: Record<MinstdVariant, bigint> = {
    "minstd-rand0": 1043618065n,
    "minstd-rand": 399268537n,
  };

  for (const variant of VARIANTS) {
    it(`${variant}: the 10000th value from seed 1 is ${ISO_10000TH[variant]}`, () => {
      const words = refWords(LCG_PARAMS[variant], 1, 10000);
      expect(words[9999]).toBe(ISO_10000TH[variant]);
    });
  }

  it("the two variants differ from the first word — the multiplier is the whole generator", () => {
    // Guards against both rows of LCG_PARAMS accidentally holding the same
    // constant, which would leave every other test in this file green while the
    // selector offered the same generator twice.
    expect(refWords(LCG_PARAMS["minstd-rand0"], 1, 1)[0]).toBe(16807n);
    expect(refWords(LCG_PARAMS["minstd-rand"], 1, 1)[0]).toBe(48271n);
  });
});

// ─── 2. The spec reproduces the reference ─────────────────────────────────

describe("MINSTD — the port-graph spec reproduces the reference stream", () => {
  for (const variant of VARIANTS) {
    // 40 is a whole number of words; 41 and 42 are not, so they exercise the
    // short final block and the trim that matches it.
    for (const byteLength of [4, 40, 41, 42]) {
      it(`${variant}: ${byteLength} bytes from seed 1`, () => {
        const actual = run(buildLcgSpec(variant, byteLength), 1);
        expect(actual).toHaveLength(byteLength);
        expect(toHex(actual)).toBe(toHex(refStream(LCG_PARAMS[variant], 1, byteLength)));
      });
    }
  }

  it("minstd_rand0's first words are the published Lehmer sequence", () => {
    // A literal anchor independent of `refStream`'s loop: this opening run —
    // 16807, 282475249, 1622650073, … — is the most widely republished
    // fingerprint of this generator, so a transposition inside `refWords`
    // cannot pass here.
    const stream = run(buildLcgSpec("minstd-rand0", 20), 1);
    const words: number[] = [];
    for (let i = 0; i < 5; i++) {
      words.push(
        ((stream[i * 4] as number) << 24) |
          ((stream[i * 4 + 1] as number) << 16) |
          ((stream[i * 4 + 2] as number) << 8) |
          (stream[i * 4 + 3] as number),
      );
    }
    expect(words).toEqual([16807, 282475249, 1622650073, 984943658, 1144108930]);
  });

  it("a longer request extends a shorter one rather than changing it", () => {
    // The stream is a single sequence, not a per-request quantity: asking for
    // more bytes must not disturb the ones already produced. This is what would
    // break if the iteration count leaked into the state in any way.
    const short = run(buildLcgSpec("minstd-rand0", 41), 1);
    const long = run(buildLcgSpec("minstd-rand0", 64), 1);
    expect(toHex(long.subarray(0, 41))).toBe(toHex(short));
  });
});

// ─── 3. The seed is the only thing that picks the sequence ────────────────

describe("MINSTD — seeding", () => {
  it("different seeds give different streams", () => {
    const a = run(buildLcgSpec("minstd-rand0", 32), 1);
    const b = run(buildLcgSpec("minstd-rand0", 32), 2);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("seed 0 is a fixed point — the generator emits zeros forever", () => {
    // Not a curiosity: 0 is the one value outside the multiplicative group mod
    // a prime, so `a·0 mod m` is 0 at every step. A generator whose entire
    // output collapses on one unlucky starting value is the teaching point, and
    // pinning it here keeps that behaviour from being "fixed" into a silent
    // reseed later.
    const out = run(buildLcgSpec("minstd-rand0", 32), 0);
    expect(toHex(out)).toBe("00".repeat(32));
  });

  it("the seed is used verbatim — the first word is a·seed mod m", () => {
    // The seeding convention, asserted rather than described. A future change
    // that scrambles or discards warm-up outputs breaks here, loudly, instead
    // of silently decoupling the app from the ISO anchor above.
    const out = run(buildLcgSpec("minstd-rand0", 4), 7);
    const first =
      ((out[0] as number) << 24) |
      ((out[1] as number) << 16) |
      ((out[2] as number) << 8) |
      (out[3] as number);
    expect(first).toBe((16807 * 7) % MINSTD_MODULUS);
  });
});

// ─── 4. The editable constants are live ───────────────────────────────────

describe("MINSTD — the published constants are real parameters, not decoration", () => {
  /** Rewrite one `constant-load@1` leaf inside the iterate body. */
  const withMultiplier = (spec: CipherSpec, bytes: number[]): CipherSpec => {
    const iterate = spec.steps.find((n) => n.id === LCG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    const children: StepNode[] = iterate.children.map((child) =>
      child.kind === "step" && child.id === LCG_MULTIPLIER_ID
        ? { ...child, params: { bytes } }
        : child,
    );
    return {
      ...spec,
      steps: spec.steps.map((n) => (n.id === LCG_ITERATE_ID ? { ...iterate, children } : n)),
    };
  };

  it("editing the multiplier changes the stream", () => {
    // The pedagogical claim of the whole family: these constants are the
    // experiment surface. If the trace's multiplier chip were decorative — the
    // real value baked into an executor — this test would pass identical
    // streams and every other test here would still be green.
    const base = buildLcgSpec("minstd-rand0", 32);
    const edited = withMultiplier(base, [0, 0, 0, 3]); // a = 3
    expect(toHex(run(edited, 1))).not.toBe(toHex(run(base, 1)));
    // And it must be the *right* different: a = 3 from seed 1 gives 3, 9, 27…
    expect(toHex(run(edited, 1))).toBe(toHex(refStream(mult(3), 1, 32)));
  });

  it("a = 1 stops the generator — every word is the seed", () => {
    // The most legible degenerate case, and one a learner can reach in two
    // keystrokes: multiplying by 1 makes the recurrence the identity.
    const edited = withMultiplier(buildLcgSpec("minstd-rand0", 16), [0, 0, 0, 1]);
    expect(toHex(run(edited, 5))).toBe("00000005".repeat(4));
  });
});

// ─── 5. The untrimmed-feedback wiring, measured not assumed ───────────────

describe("MINSTD — chainFeedback reads the UNTRIMMED state", () => {
  it("is byte-indistinguishable from feeding back the trimmed word, as claimed", () => {
    // `ciphers/lcg.ts` claims this wiring choice is semantic rather than
    // behavioural — only the FINAL block is ever short, and the final
    // iteration's feedback is discarded. That claim is worth exactly as much as
    // its evidence, so here is the perturbation: rebind `chainFeedback` to the
    // trimmed `emit` node and assert the streams match at lengths that are and
    // are not multiples of the word.
    //
    // If this test ever FAILS, the topology has changed such that a non-final
    // block can be short — and at that point the untrimmed binding stops being
    // a matter of honesty and becomes load-bearing. That is precisely when a
    // silent regression would otherwise slip through.
    for (const byteLength of [40, 41, 42, 43]) {
      const honest = buildLcgSpec("minstd-rand0", byteLength);
      const iterate = honest.steps.find((n) => n.id === LCG_ITERATE_ID);
      if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
      const perturbed: CipherSpec = {
        ...honest,
        steps: honest.steps.map((n) =>
          n.id === LCG_ITERATE_ID
            ? { ...iterate, chainFeedback: { node: "emit", port: "output" } }
            : n,
        ),
      };
      expect(toHex(run(perturbed, 1)), `at ${byteLength} bytes`).toBe(toHex(run(honest, 1)));
    }
  });

  it("the state leaf is the node the feedback names", () => {
    // Guards the wiring itself, which the behavioural test above cannot: it
    // passes under BOTH bindings by construction.
    const spec = buildLcgSpec("minstd-rand0", 41);
    const iterate = spec.steps.find((n) => n.id === LCG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    expect(iterate.chainFeedback).toEqual({ node: LCG_STATE_ID, port: "output" });
  });
});

// ─── 6. Output length round-trips ─────────────────────────────────────────

describe("MINSTD — the requested length is recoverable from the spec", () => {
  it("readLcgOutputLength recovers what buildLcgSpec was given", () => {
    // Without this, loading a saved or shared document would silently reset the
    // output-length control to its default while the spec kept the saved value.
    for (const n of [1, 4, 41, 256]) {
      expect(readLcgOutputLength(buildLcgSpec("minstd-rand0", n))).toBe(n);
    }
  });

  it("returns undefined for a spec with no request leaf", () => {
    const spec = buildLcgSpec("minstd-rand0", 32);
    const stripped: CipherSpec = { ...spec, steps: spec.steps.filter((n) => n.id !== "request") };
    expect(readLcgOutputLength(stripped)).toBeUndefined();
  });

  it("rejects a zero-length request rather than producing an empty trace", () => {
    // `zero-fill@1` throws on byteLength < 1. A zero-width request would give
    // the iterate a count of 0, so `bodyOutput` would never resolve — failing
    // at the param check names the real problem.
    expect(() => run(buildLcgSpec("minstd-rand0", 0), 1)).toThrow(/byteLength/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// THE ANSI C GENERATOR — the mixed form
// ═══════════════════════════════════════════════════════════════════════════
//
// No ISO conformance clause exists for this one, so it is anchored on the two
// most widely republished facts about it, both from seed 1:
//
//   states:  1103527590, 377401575, 662824084, 1147902781, 2035015474
//   rand():  16838, 5758, 10113, 17515, 31051
//
// The second set is derived from the first by `(state / 65536) % 32768`, which
// is what the C standard's sample `rand()` returns. THIS APP EMITS THE STATES,
// deliberately — the division is C's workaround for the low-bit weakness, and
// performing it would hide the defect the variant exists to show. Pinning both
// sequences is what makes that an intentional relationship rather than a
// discrepancy nobody checked.

/** The word at index `i` of an emitted stream, big-endian, as a number. */
const wordAt = (stream: Uint8Array, i: number): number =>
  ((stream[i * 4] as number) * 0x1000000 +
    ((stream[i * 4 + 1] as number) << 16) +
    ((stream[i * 4 + 2] as number) << 8) +
    (stream[i * 4 + 3] as number)) >>>
  0;

describe("ANSI C LCG — the published opening sequence", () => {
  const OPENING_STATES = [1103527590, 377401575, 662824084, 1147902781, 2035015474];
  const OPENING_RANDS = [16838, 5758, 10113, 17515, 31051];

  it("the traced spec produces the published states from seed 1", () => {
    const stream = run(buildLcgSpec("ansi-c-lcg", 20), 1);
    expect([0, 1, 2, 3, 4].map((i) => wordAt(stream, i))).toEqual(OPENING_STATES);
  });

  it("C's rand() values follow from those states by the standard's own extraction", () => {
    // Not a restatement of the line above: it asserts the RELATIONSHIP between
    // what this app shows and what a C program prints. If the app ever started
    // emitting the extracted value instead of the state, the test above would
    // fail and this one would silently become a tautology — so it derives the
    // rand() values from the RUNTIME's output, not from the literals.
    const stream = run(buildLcgSpec("ansi-c-lcg", 20), 1);
    const rands = [0, 1, 2, 3, 4].map((i) => Math.floor(wordAt(stream, i) / 65536) % 32768);
    expect(rands).toEqual(OPENING_RANDS);
  });

  it("the parameters are the C standard's, not glibc's or anyone else's", () => {
    expect(LCG_PARAMS["ansi-c-lcg"]).toEqual({ a: 1103515245, c: 12345, m: ANSI_C_MODULUS });
    expect(ANSI_C_MODULUS).toBe(2 ** 31);
  });

  for (const byteLength of [4, 40, 41, 42]) {
    it(`reproduces the independent reference at ${byteLength} bytes`, () => {
      const actual = run(buildLcgSpec("ansi-c-lcg", byteLength), 1);
      expect(actual).toHaveLength(byteLength);
      expect(toHex(actual)).toBe(toHex(refStream(LCG_PARAMS["ansi-c-lcg"], 1, byteLength)));
    });
  }

  it("seed 0 is NOT a fixed point — this is what the increment buys", () => {
    // The sharpest behavioural contrast with MINSTD, where seed 0 emits zeros
    // forever. Here 0 → c → …, so the generator carries on normally. Asserting
    // it here (against MINSTD's fixed-point test above) makes the increment's
    // purpose a checked claim rather than a remark in the narration.
    const out = run(buildLcgSpec("ansi-c-lcg", 16), 0);
    expect(toHex(out)).not.toBe("00".repeat(16));
    expect(wordAt(out, 0)).toBe(12345);
  });
});

// ─── The low-bit weakness, measured through the app ───────────────────────

describe("ANSI C LCG — the power-of-two modulus kills the low bits", () => {
  /** Bit 0 of each emitted word — the LSB of bytes 3, 7, 11, … */
  const bitZeroes = (stream: Uint8Array, words: number): number[] =>
    Array.from({ length: words }, (_, i) => (stream[i * 4 + 3] as number) & 1);

  it("bit 0 alternates with period 2, as the narration claims", () => {
    // The teaching claim of this whole variant, asserted against the RUNTIME's
    // bytes rather than against the BigInt reference — otherwise the test would
    // only prove the reference agrees with itself.
    const stream = run(buildLcgSpec("ansi-c-lcg", 64), 1);
    const bits = bitZeroes(stream, 16);
    expect(bits).toEqual([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]);
  });

  it("MINSTD's prime modulus does NOT produce that pattern", () => {
    // The contrast is what makes the claim "a property of the power-of-two
    // modulus" rather than "a property of this particular generator". Without
    // it, the test above would pass on an implementation where every generator
    // happened to alternate.
    const stream = run(buildLcgSpec("minstd-rand0", 64), 1);
    const bits = bitZeroes(stream, 16);
    const alternating = bits.every(
      (b, i) => b === (i % 2 === 0 ? bits[0] : 1 - (bits[0] as number)),
    );
    expect(alternating, `MINSTD bit 0 was ${bits.join("")}`).toBe(false);
  });

  it("swapping in MINSTD's prime modulus removes the alternation", () => {
    // The experiment the narration invites a learner to run, executed. This is
    // the strongest form of the claim: same generator, same seed, one constant
    // changed, and the defect disappears.
    const base = buildLcgSpec("ansi-c-lcg", 64);
    const iterate = base.steps.find((n) => n.id === LCG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    const patched: CipherSpec = {
      ...base,
      steps: base.steps.map((n) =>
        n.id === LCG_ITERATE_ID
          ? {
              ...iterate,
              children: iterate.children.map((child) =>
                child.kind === "step" && child.id === "modu"
                  ? { ...child, params: { bytes: [0x7f, 0xff, 0xff, 0xff] } }
                  : child,
              ),
            }
          : n,
      ),
    };
    const bits = bitZeroes(run(patched, 1), 16);
    expect(bits).not.toEqual([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]);
  });
});

// ─── The increment is a live parameter ────────────────────────────────────

describe("ANSI C LCG — the increment is a real parameter, not decoration", () => {
  /** Rewrite the `incr` leaf inside the iterate body. */
  const withIncrement = (spec: CipherSpec, bytes: number[]): CipherSpec => {
    const iterate = spec.steps.find((n) => n.id === LCG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    const children: StepNode[] = iterate.children.map((child) =>
      child.kind === "step" && child.id === "incr" ? { ...child, params: { bytes } } : child,
    );
    return {
      ...spec,
      steps: spec.steps.map((n) => (n.id === LCG_ITERATE_ID ? { ...iterate, children } : n)),
    };
  };

  it("editing c changes the stream to the matching reference", () => {
    // Proves `add-mod@1` reads its `b` port rather than carrying a baked-in
    // constant — the mirror of the multiplier test for MINSTD.
    const base = buildLcgSpec("ansi-c-lcg", 32);
    const edited = withIncrement(base, [0, 0, 0, 7]); // c = 7
    expect(toHex(run(edited, 1))).not.toBe(toHex(run(base, 1)));
    expect(toHex(run(edited, 1))).toBe(
      toHex(refStream({ a: 1103515245, c: 7, m: ANSI_C_MODULUS }, 1, 32)),
    );
  });

  it("c = 0 degenerates the mixed form into a multiplicative one", () => {
    // The forms are one constant apart, and this says so in bytes: with c = 0
    // the ANSI C spec must agree with the plain recurrence that has no
    // increment at all.
    const edited = withIncrement(buildLcgSpec("ansi-c-lcg", 32), [0, 0, 0, 0]);
    expect(toHex(run(edited, 1))).toBe(
      toHex(refStream({ a: 1103515245, c: 0, m: ANSI_C_MODULUS }, 1, 32)),
    );
  });
});

// ─── The mixed form's structure ───────────────────────────────────────────

describe("ANSI C LCG — the spec's shape", () => {
  const childIds = (variant: LcgVariant): string[] => {
    const spec = buildLcgSpec(variant, 32);
    const iterate = spec.steps.find((n) => n.id === LCG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    return iterate.children.map((c) => c.id);
  };

  it("carries the increment and the add-mod leaf; MINSTD carries neither", () => {
    // `c = 0` is a FORM, not a value: a multiplicative generator does not add
    // zero, it does not add at all. If the builder ever started emitting an
    // `incr` of zero for MINSTD the streams would stay correct and the trace
    // would quietly grow two frames that teach the wrong thing.
    expect(childIds("ansi-c-lcg")).toEqual(["mult", "incr", "modu", "prod", "state", "emit"]);
    expect(childIds("minstd-rand0")).toEqual(["mult", "modu", "state", "emit"]);
  });

  it("chainFeedback names the add-mod leaf, not the mod-mul", () => {
    // The one wire that would produce a plausible-but-wrong generator: feeding
    // back `prod` drops the increment from the recurrence while still emitting
    // it, so the output would look right for exactly one word.
    const spec = buildLcgSpec("ansi-c-lcg", 32);
    const iterate = spec.steps.find((n) => n.id === LCG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    expect(iterate.chainFeedback).toEqual({ node: LCG_STATE_ID, port: "output" });

    // And the perturbation, so the assertion above is known to matter: rebind
    // the feedback to the product and the stream must change.
    const perturbed: CipherSpec = {
      ...spec,
      steps: spec.steps.map((n) =>
        n.id === LCG_ITERATE_ID
          ? { ...iterate, chainFeedback: { node: "prod", port: "output" } }
          : n,
      ),
    };
    expect(toHex(run(perturbed, 1))).not.toBe(toHex(run(spec, 1)));
  });
});

// ─── The MINSTD specs did not move ────────────────────────────────────────

describe("MINSTD — byte-identical across the mixed-form generalization", () => {
  // Spec-only saves are byte-stable so URL-share hashes are deterministic
  // (CLAUDE.md, "Persistence"). Generalizing `buildLcgSpec` to emit both forms
  // touched every narration function in the file, and a single reworded
  // sentence would change every previously-shared MINSTD link without changing
  // one byte of output — invisible to every other test here.
  //
  // These digests were taken from the shipped P1 builder BEFORE the
  // generalization. Do not regenerate them to make this test pass: a failure
  // means old links now resolve to a different document, which is a decision to
  // take deliberately, not a chore to clear.
  const PINNED: Record<string, string> = {
    "minstd-rand0/40": "a5039119ef628db118b765dd67ebde48",
    "minstd-rand/40": "2521fae41f28c4a663e91de1a8c8332f",
    "minstd-rand0/42": "78c9068f5c38c3b07ce32b6743ba6070",
    "minstd-rand/42": "13aca7235bec69a0ced6a807f79e3218",
  };

  for (const [key, digest] of Object.entries(PINNED)) {
    it(`${key} serializes to the same bytes as it did in P1`, () => {
      const [variant, len] = key.split("/") as [LcgVariant, string];
      const json = JSON.stringify(buildLcgSpec(variant, Number(len)));
      expect(createHash("sha256").update(json).digest("hex").slice(0, 32)).toBe(digest);
    });
  }
});
