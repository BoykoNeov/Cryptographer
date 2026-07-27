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

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  MCG_ITERATE_ID,
  MCG_MULTIPLIER,
  MCG_MULTIPLIER_ID,
  MCG_STATE_ID,
  MCG_WORD_BYTES,
  MINSTD_MODULUS,
  type McgVariant,
  buildMcgSpec,
  readMcgOutputLength,
} from "@/ciphers/lcg";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Independent reference ────────────────────────────────────────────────

/**
 * The recurrence, in plain `BigInt`. Deliberately shares nothing with the spec
 * under test — no registry lookup, no port binding, no byte array. A wiring bug
 * in the spec cannot reach in here and make both agree.
 */
const refWords = (a: number, seed: number, count: number): bigint[] => {
  const m = BigInt(MINSTD_MODULUS);
  let x = BigInt(seed);
  const out: bigint[] = [];
  for (let i = 0; i < count; i++) {
    x = (BigInt(a) * x) % m;
    out.push(x);
  }
  return out;
};

/** The reference expressed as a byte stream: each word big-endian, the whole
 *  thing cut to `byteLength`. This is what the spec is expected to produce. */
const refStream = (a: number, seed: number, byteLength: number): Uint8Array => {
  const words = refWords(a, seed, Math.ceil(byteLength / MCG_WORD_BYTES));
  const out = new Uint8Array(words.length * MCG_WORD_BYTES);
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

const VARIANTS: readonly McgVariant[] = ["minstd-rand0", "minstd-rand"];

// ─── 1. The ISO anchor ────────────────────────────────────────────────────

describe("MINSTD — the ISO/IEC 14882 §rand.predef conformance values", () => {
  // These two literals are the only values in this file that come from outside
  // the repository. Everything else is checked against them.
  const ISO_10000TH: Record<McgVariant, bigint> = {
    "minstd-rand0": 1043618065n,
    "minstd-rand": 399268537n,
  };

  for (const variant of VARIANTS) {
    it(`${variant}: the 10000th value from seed 1 is ${ISO_10000TH[variant]}`, () => {
      const words = refWords(MCG_MULTIPLIER[variant], 1, 10000);
      expect(words[9999]).toBe(ISO_10000TH[variant]);
    });
  }

  it("the two variants differ from the first word — the multiplier is the whole generator", () => {
    // Guards against both rows of MCG_MULTIPLIER accidentally holding the same
    // constant, which would leave every other test in this file green while the
    // selector offered the same generator twice.
    expect(refWords(MCG_MULTIPLIER["minstd-rand0"], 1, 1)[0]).toBe(16807n);
    expect(refWords(MCG_MULTIPLIER["minstd-rand"], 1, 1)[0]).toBe(48271n);
  });
});

// ─── 2. The spec reproduces the reference ─────────────────────────────────

describe("MINSTD — the port-graph spec reproduces the reference stream", () => {
  for (const variant of VARIANTS) {
    // 40 is a whole number of words; 41 and 42 are not, so they exercise the
    // short final block and the trim that matches it.
    for (const byteLength of [4, 40, 41, 42]) {
      it(`${variant}: ${byteLength} bytes from seed 1`, () => {
        const actual = run(buildMcgSpec(variant, byteLength), 1);
        expect(actual).toHaveLength(byteLength);
        expect(toHex(actual)).toBe(toHex(refStream(MCG_MULTIPLIER[variant], 1, byteLength)));
      });
    }
  }

  it("minstd_rand0's first words are the published Lehmer sequence", () => {
    // A literal anchor independent of `refStream`'s loop: this opening run —
    // 16807, 282475249, 1622650073, … — is the most widely republished
    // fingerprint of this generator, so a transposition inside `refWords`
    // cannot pass here.
    const stream = run(buildMcgSpec("minstd-rand0", 20), 1);
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
    const short = run(buildMcgSpec("minstd-rand0", 41), 1);
    const long = run(buildMcgSpec("minstd-rand0", 64), 1);
    expect(toHex(long.subarray(0, 41))).toBe(toHex(short));
  });
});

// ─── 3. The seed is the only thing that picks the sequence ────────────────

describe("MINSTD — seeding", () => {
  it("different seeds give different streams", () => {
    const a = run(buildMcgSpec("minstd-rand0", 32), 1);
    const b = run(buildMcgSpec("minstd-rand0", 32), 2);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("seed 0 is a fixed point — the generator emits zeros forever", () => {
    // Not a curiosity: 0 is the one value outside the multiplicative group mod
    // a prime, so `a·0 mod m` is 0 at every step. A generator whose entire
    // output collapses on one unlucky starting value is the teaching point, and
    // pinning it here keeps that behaviour from being "fixed" into a silent
    // reseed later.
    const out = run(buildMcgSpec("minstd-rand0", 32), 0);
    expect(toHex(out)).toBe("00".repeat(32));
  });

  it("the seed is used verbatim — the first word is a·seed mod m", () => {
    // The seeding convention, asserted rather than described. A future change
    // that scrambles or discards warm-up outputs breaks here, loudly, instead
    // of silently decoupling the app from the ISO anchor above.
    const out = run(buildMcgSpec("minstd-rand0", 4), 7);
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
    const iterate = spec.steps.find((n) => n.id === MCG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    const children: StepNode[] = iterate.children.map((child) =>
      child.kind === "step" && child.id === MCG_MULTIPLIER_ID
        ? { ...child, params: { bytes } }
        : child,
    );
    return {
      ...spec,
      steps: spec.steps.map((n) => (n.id === MCG_ITERATE_ID ? { ...iterate, children } : n)),
    };
  };

  it("editing the multiplier changes the stream", () => {
    // The pedagogical claim of the whole family: these constants are the
    // experiment surface. If the trace's multiplier chip were decorative — the
    // real value baked into an executor — this test would pass identical
    // streams and every other test here would still be green.
    const base = buildMcgSpec("minstd-rand0", 32);
    const edited = withMultiplier(base, [0, 0, 0, 3]); // a = 3
    expect(toHex(run(edited, 1))).not.toBe(toHex(run(base, 1)));
    // And it must be the *right* different: a = 3 from seed 1 gives 3, 9, 27…
    expect(toHex(run(edited, 1))).toBe(toHex(refStream(3, 1, 32)));
  });

  it("a = 1 stops the generator — every word is the seed", () => {
    // The most legible degenerate case, and one a learner can reach in two
    // keystrokes: multiplying by 1 makes the recurrence the identity.
    const edited = withMultiplier(buildMcgSpec("minstd-rand0", 16), [0, 0, 0, 1]);
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
      const honest = buildMcgSpec("minstd-rand0", byteLength);
      const iterate = honest.steps.find((n) => n.id === MCG_ITERATE_ID);
      if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
      const perturbed: CipherSpec = {
        ...honest,
        steps: honest.steps.map((n) =>
          n.id === MCG_ITERATE_ID
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
    const spec = buildMcgSpec("minstd-rand0", 41);
    const iterate = spec.steps.find((n) => n.id === MCG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    expect(iterate.chainFeedback).toEqual({ node: MCG_STATE_ID, port: "output" });
  });
});

// ─── 6. Output length round-trips ─────────────────────────────────────────

describe("MINSTD — the requested length is recoverable from the spec", () => {
  it("readMcgOutputLength recovers what buildMcgSpec was given", () => {
    // Without this, loading a saved or shared document would silently reset the
    // output-length control to its default while the spec kept the saved value.
    for (const n of [1, 4, 41, 256]) {
      expect(readMcgOutputLength(buildMcgSpec("minstd-rand0", n))).toBe(n);
    }
  });

  it("returns undefined for a spec with no request leaf", () => {
    const spec = buildMcgSpec("minstd-rand0", 32);
    const stripped: CipherSpec = { ...spec, steps: spec.steps.filter((n) => n.id !== "request") };
    expect(readMcgOutputLength(stripped)).toBeUndefined();
  });

  it("rejects a zero-length request rather than producing an empty trace", () => {
    // `zero-fill@1` throws on byteLength < 1. A zero-width request would give
    // the iterate a count of 0, so `bodyOutput` would never resolve — failing
    // at the param check names the real problem.
    expect(() => run(buildMcgSpec("minstd-rand0", 0), 1)).toThrow(/byteLength/);
  });
});
