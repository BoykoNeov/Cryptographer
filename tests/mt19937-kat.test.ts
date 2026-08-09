/**
 * MT19937 known-answer tests — the PRNG family's fifth generator, and the one
 * that is neither weak nor safe.
 *
 * Plan: `docs/plans/validated-growing-dongarra.md` (P4 of the family plan
 * `docs/plans/iterative-dancing-ocean.md`).
 *
 * This file opens with a **wiring spike** rather than a vector, because the
 * MT19937 spec depends on one piece of topology no shipped spec uses, and the
 * cheapest possible refutation of it is worth more than a narrator written on
 * top of a design that cannot run. See the block comment above it.
 */

import { port } from "@/ciphers/block-cipher-core";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec } from "@/core/types";
import { MT_N, initGenrand } from "@/steps/mt19937-seed";
import { twist } from "@/steps/mt19937-twist";
import { describe, expect, it } from "vitest";

const run = (spec: CipherSpec, input: Uint8Array): Uint8Array => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: input },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");
  return trace.finalState.bytes;
};

// ─── 0. The wiring spike ──────────────────────────────────────────────────
//
// MT19937's spec needs two things from the port-mode `iterate` that no shipped
// spec asks for, and both are cheaper to refute here — with primitives that
// already exist — than to discover after three executors and a narrator:
//
//  1. **An iterate with NO cross-iteration carry at all.** Every other
//     port-mode iterate in the app threads a value through the loop (CBC's
//     chain, CTR's counter, SHA-256's running H, the LCGs' `x`). MT's
//     extraction is a pure MAP over the state array: output word `i` depends
//     on state word `i` and nothing else.
//
//  2. **A SIBLING leaf reading the iterate's `out` port.** Every shipped trim
//     (CTR/CFB/OFB/ChaCha/Salsa/LCG) lives INSIDE the body, keyed on the
//     iterate's per-block `in` port. MT cannot do that: `in` is always a full
//     4-byte state word, so no short reference exists to trim against. The
//     ragged tail therefore has to be cut off AFTER the loop — which means a
//     top-level `truncate-to-reference@1` consuming `port(loop, "out")`.
//
// The spike stands in a `not@1` for the tempering chain and a `constant-load@1`
// for the twisted state; the shape is otherwise exactly the shipped design.

describe("MT19937 wiring spike — the topology the spec depends on", () => {
  /** Three 4-byte "state words", standing in for the twisted MT state. */
  const STATE = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
  /** A deliberately ragged request: 10 bytes is 2.5 words. */
  const REQUESTED = 10;

  const spikeSpec = (): CipherSpec => ({
    id: "mt19937-wiring-spike@1",
    name: "wiring spike",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      // Stands in for `mt19937.twist@1`'s 2496-byte output.
      { kind: "step", id: "twist", type: "constant-load@1", params: { bytes: [...STATE] } },
      // The requested length, exactly as every other generator carries it.
      { kind: "step", id: "request", type: "zero-fill@1", params: { byteLength: REQUESTED } },
      // Round UP to a whole number of words: ceil(10/4) * 4 = 12.
      {
        kind: "step",
        id: "words",
        type: "byte-slice@1",
        params: { sourceByteLength: STATE.length, offset: 0, length: 12 },
        portInputs: { input: port("twist", "output") },
      },
      {
        kind: "iterate",
        id: "loop",
        label: "spike",
        seedInput: port("words", "output"),
        blockByteLength: 4,
        // NO chainInput, NO chainFeedback — property (1) under test.
        bodyOutput: port("temper", "output"),
        outputPorts: ["out"],
        children: [
          {
            kind: "step",
            id: "temper",
            type: "not@1",
            params: {},
            portInputs: { input: port("loop", "in") },
          },
        ],
      },
      {
        // Property (2) under test: a SIBLING of the iterate, reading its `out`.
        kind: "step",
        id: "emit",
        type: "truncate-to-reference@1",
        params: {},
        portInputs: { input: port("loop", "out"), reference: port("request", "output") },
      },
    ],
    outputFrom: port("emit", "output"),
  });

  it("runs a port-mode iterate that carries nothing between iterations", () => {
    // If the runtime required a chain, this would throw rather than assert.
    const out = run(spikeSpec(), new Uint8Array([0, 0, 0, 1]));
    expect(out).toBeInstanceOf(Uint8Array);
  });

  it("lets a sibling leaf read the iterate's `out` port, and trims the ragged tail there", () => {
    const out = run(spikeSpec(), new Uint8Array([0, 0, 0, 1]));
    // Every one of the 12 state bytes is NOTted by the body; the emit step then
    // cuts the concatenation back to the 10 bytes actually requested.
    const expected = Uint8Array.from(STATE.map((b) => (~b >>> 0) & 0xff)).subarray(0, REQUESTED);
    expect(out.length).toBe(REQUESTED);
    expect(Array.from(out)).toEqual(Array.from(expected));
  });
});

// ─── The oracle ───────────────────────────────────────────────────────────
//
// `node:crypto` has no seedable generator, so there is no live oracle — the
// position MINSTD and Salsa20 are in. What MT19937 has instead is a
// CONFORMANCE REQUIREMENT plus a second implementation, captured together in
// `temp/mt19937/oracle.py` with two deliberately independent anchors, so a
// disagreement says WHICH half is wrong:
//
//   A. our `init_genrand` pushed into `np.random.MT19937`'s state (`pos = 624`
//      forces a twist before the first draw) and read via `random_raw()` —
//      numpy's C twist+temper under our seeding.
//   B. CPython's `random.Random(int)`, which seeds via `init_by_array` over the
//      integer's little-endian 32-bit words, reproducing the published
//      `mt19937ar.out` vector with NO trust in our seeding at all.
//
// Anchor B and the same key array pushed through numpy agree exactly, which is
// what makes B an independent check on twist+temper rather than a restatement.
//
// **A recalled constant was wrong, and this caught it.** The published
// `mt19937ar.out` opens `1067595299 955945823 477289528 …`, not the
// `936293355 441322842` an earlier draft of this work carried from memory. Only
// the ISO value below survived independent derivation — which is the whole
// reason the repo rule (`feedback_crypto_verification`) says to pin the first
// vector against a running reference rather than against recollection.

/** ISO/IEC 14882 §rand.predef: the 10000th consecutive value of a
 *  default-constructed `std::mt19937` — i.e. seeded `init_genrand(5489)`.
 *  Independently reproduced by anchor A above. */
const ISO_10000TH = 4123659995;

/** `std::mt19937`'s `default_seed`, and the app's default. */
const DEFAULT_SEED = 5489;

/**
 * The tempering transform, written from the published definition
 * (Matsumoto & Nishimura 1998 §3) and sharing nothing with the spec under
 * test — no registry, no runtime, no port, no `Uint8Array`. The spec's
 * twelve-leaf chain is pinned against THIS once the builder lands.
 */
const temper = (y0: number): number => {
  let y = y0 >>> 0;
  y = (y ^ (y >>> 11)) >>> 0;
  y = (y ^ ((y << 7) & 0x9d2c5680)) >>> 0;
  y = (y ^ ((y << 15) & 0xefc60000)) >>> 0;
  y = (y ^ (y >>> 18)) >>> 0;
  return y >>> 0;
};

/**
 * The whole generator at the executor level: seed, then twist-and-temper on
 * demand. Used for long runs — reaching the 10000th output through the traced
 * runtime would mean a 40 KB request and ~10,000 iterations of frames, far past
 * the app's legibility ceiling. Exactly `tests/lcg-kat.test.ts`'s posture.
 */
const refStream = (seed: number, count: number): number[] => {
  let state = initGenrand(seed);
  const out: number[] = [];
  let i = MT_N; // force a twist before the first draw, as the reference does
  while (out.length < count) {
    if (i >= MT_N) {
      state = twist(state);
      i = 0;
    }
    out.push(temper(state[i] as number));
    i++;
  }
  return out;
};

// ─── 1. The ISO anchor, and the per-stage vectors ─────────────────────────

describe("MT19937 — the external oracle", () => {
  it("reproduces ISO/IEC 14882 §rand.predef's 10000th value of std::mt19937", () => {
    expect(refStream(DEFAULT_SEED, 10000)[9999]).toBe(ISO_10000TH);
  });

  it("initializes the state to init_genrand(5489), checked at BOTH ends", () => {
    // Both ends, because a recurrence bug that damages the middle still leaves
    // mt[0] — which is the seed verbatim — looking perfectly correct.
    const mt = initGenrand(DEFAULT_SEED);
    expect(Array.from(mt.subarray(0, 4))).toEqual([5489, 1301868182, 2938499221, 2950281878]);
    expect(Array.from(mt.subarray(621))).toEqual([2369854699, 2844269403, 79981964]);
  });

  it("twists the state into the words numpy's own twist produces", () => {
    // Read back out of numpy AFTER forcing a refill, so these words come from
    // numpy's C implementation rather than being a restatement of ours.
    const twisted = twist(initGenrand(DEFAULT_SEED));
    expect(Array.from(twisted.subarray(0, 4))).toEqual([
      2601187879, 3919438689, 2270374771, 3254473187,
    ]);
    expect(Array.from(twisted.subarray(621))).toEqual([2903063865, 3505442042, 3518038711]);
  });

  it("tempers the twisted state into the published opening sequence", () => {
    expect(refStream(DEFAULT_SEED, 8)).toEqual([
      3499211612, 581869302, 3890346734, 3586334585, 545404204, 4161255391, 3922919429, 949333985,
    ]);
  });

  it("keeps seeding and tempering separable — the untempered words differ", () => {
    // If tempering were accidentally an identity, the test above would still
    // pass whenever the twist happened to be right. Pin the pre-temper words
    // too, so the two stages cannot cover for each other.
    const twisted = twist(initGenrand(DEFAULT_SEED));
    expect(Array.from(twisted.subarray(0, 4))).not.toEqual([
      3499211612, 581869302, 3890346734, 3586334585,
    ]);
    expect(temper(twisted[0] as number)).toBe(3499211612);
  });
});

// ─── 2. Perturbation — proving the vectors are live ───────────────────────
//
// Every mutated constant below appears nowhere in the app, and each mutation
// must break the anchors above. Without this, a suite pinning the right numbers
// against a hardcoded stream would look identical to one pinning them against
// real arithmetic (`feedback_crypto_verification`; the CFB/OFB/LCG precedent).

describe("MT19937 — perturbation", () => {
  it("dropping the final `y ^= y >> 18` breaks the opening sequence", () => {
    const damaged = (y0: number): number => {
      let y = y0 >>> 0;
      y = (y ^ (y >>> 11)) >>> 0;
      y = (y ^ ((y << 7) & 0x9d2c5680)) >>> 0;
      y = (y ^ ((y << 15) & 0xefc60000)) >>> 0;
      return y >>> 0; // the fourth step deliberately omitted
    };
    const twisted = twist(initGenrand(DEFAULT_SEED));
    const got = Array.from(twisted.subarray(0, 4)).map(damaged);
    expect(got).not.toEqual(refStream(DEFAULT_SEED, 4));
  });

  it("corrupting the 0x9d2c5680 mask breaks the opening sequence", () => {
    const damaged = (y0: number): number => {
      let y = y0 >>> 0;
      y = (y ^ (y >>> 11)) >>> 0;
      y = (y ^ ((y << 7) & 0x9d2c5600)) >>> 0; // bit 7 cleared
      y = (y ^ ((y << 15) & 0xefc60000)) >>> 0;
      y = (y ^ (y >>> 18)) >>> 0;
      return y >>> 0;
    };
    const twisted = twist(initGenrand(DEFAULT_SEED));
    const got = Array.from(twisted.subarray(0, 4)).map(damaged);
    expect(got).not.toEqual(refStream(DEFAULT_SEED, 4));
  });

  it("the mask's LOW 7 bits are don't-cares — a perturbation there must be a no-op", () => {
    // Found by writing the test above with `0x9d2c5681` and watching it pass.
    // `y << 7` has its low 7 bits zero by construction, so those mask bits can
    // never contribute. This is not a weakness of the test; it is the exact
    // structural fact the next test turns into an argument.
    const damaged = (y0: number): number => {
      let y = y0 >>> 0;
      y = (y ^ (y >>> 11)) >>> 0;
      y = (y ^ ((y << 7) & 0x9d2c56ff)) >>> 0; // all seven low bits set
      y = (y ^ ((y << 15) & 0xefc60000)) >>> 0;
      y = (y ^ (y >>> 18)) >>> 0;
      return y >>> 0;
    };
    const twisted = twist(initGenrand(DEFAULT_SEED));
    expect(Array.from(twisted.subarray(0, 4)).map(damaged)).toEqual(refStream(DEFAULT_SEED, 4));
  });
});

// ─── 2b. Why `shift-bits-left@1` exists ───────────────────────────────────
//
// The step could have been spelled `rotate-bits-left@1` + `and@1`, because for
// MT19937's two published masks a rotation gives an IDENTICAL answer. This
// suite pins both halves of that: the coincidence is real (so the shortcut is
// tempting), and it is a property of those two constants only (so taking it
// would break the moment a learner edits a mask — which this app exists to let
// them do). Source-side rationale: `src/steps/shift-bits-left.ts`.

describe("MT19937 — shift vs rotate, and why the coincidence is not a licence", () => {
  const shl = (y: number, n: number): number => ((y >>> 0) << n) >>> 0;
  const rol = (y: number, n: number): number => (((y >>> 0) << n) | ((y >>> 0) >>> (32 - n))) >>> 0;

  it("agrees with a rotation under MT19937's OWN masks", () => {
    // 0x9d2c5680's low 7 bits and 0xefc60000's low 15 bits are clear, and those
    // are exactly the positions a rotation wraps into. So the mask deletes
    // precisely the bits the two operations disagree about.
    for (const y of [0xffffffff, 0x9e3779b9, 1, 0x80000001, 0x0f0f0f0f]) {
      expect((shl(y, 7) & 0x9d2c5680) >>> 0).toBe((rol(y, 7) & 0x9d2c5680) >>> 0);
      expect((shl(y, 15) & 0xefc60000) >>> 0).toBe((rol(y, 15) & 0xefc60000) >>> 0);
    }
  });

  it("DIVERGES from a rotation the moment a mask keeps a low bit", () => {
    // One edited mask bit is all it takes. This is what a learner editing the
    // constant in the app would hit, and why the trace must show the operation
    // the algorithm specifies rather than one that happens to agree with it.
    const edited = 0x9d2c56ff; // the seven low bits a shift can never reach
    expect((shl(0xffffffff, 7) & edited) >>> 0).not.toBe((rol(0xffffffff, 7) & edited) >>> 0);
  });

  it("a wrong twist offset (m = 396 instead of 397) breaks the state", () => {
    const mt = initGenrand(DEFAULT_SEED);
    const wrong = Uint32Array.from(mt);
    for (let i = 0; i < MT_N; i++) {
      const y =
        (((wrong[i] as number) & 0x80000000) | ((wrong[(i + 1) % MT_N] as number) & 0x7fffffff)) >>>
        0;
      wrong[i] =
        ((wrong[(i + 396) % MT_N] as number) ^ (y >>> 1) ^ ((y & 1) === 1 ? 0x9908b0df : 0)) >>> 0;
    }
    expect(Array.from(wrong.subarray(0, 4))).not.toEqual(Array.from(twist(mt).subarray(0, 4)));
  });

  it("a wrong init multiplier breaks the state from the SECOND word on", () => {
    const wrong = new Uint32Array(MT_N);
    wrong[0] = DEFAULT_SEED;
    for (let i = 1; i < MT_N; i++) {
      const prev = wrong[i - 1] as number;
      wrong[i] = (Math.imul(1812433254, prev ^ (prev >>> 30)) + i) >>> 0;
    }
    const right = initGenrand(DEFAULT_SEED);
    // Word 0 is the seed verbatim under any multiplier — which is exactly why
    // the vector above checks both ends of the array rather than just the head.
    expect(wrong[0]).toBe(right[0]);
    expect(wrong[1]).not.toBe(right[1]);
  });
});

// ─── 3. The teaching claim: tempering is invertible ───────────────────────
//
// This is why MT19937 is worth shipping at all, and why tempering is the one
// stage decomposed into visible leaves. The LCGs fail both "passes statistical
// tests" and "unpredictable"; the ChaCha20 CSPRNG passes both; MT19937 is the
// app's only generator that SEPARATES them. Asserted against emitted words
// rather than left as prose.

describe("MT19937 — the output function is a bijection, so the state leaks", () => {
  /** Undo `y ^= y >> shift`: the top `shift` bits were never modified, so each
   *  pass recovers another `shift` bits downward. */
  const unshiftRight = (y: number, shift: number): number => {
    let out = y >>> 0;
    for (let done = shift; done < 32; done += shift) {
      out = (y ^ (out >>> shift)) >>> 0;
    }
    return out >>> 0;
  };

  /** Undo `y ^= (y << shift) & mask`: the mirror, working bottom-up. */
  const unshiftLeft = (y: number, shift: number, mask: number): number => {
    let out = y >>> 0;
    for (let done = shift; done < 32; done += shift) {
      out = (y ^ (((out << shift) >>> 0) & mask)) >>> 0;
    }
    return out >>> 0;
  };

  const untemper = (y: number): number => {
    let x = y >>> 0;
    x = unshiftRight(x, 18);
    x = unshiftLeft(x, 15, 0xefc60000);
    x = unshiftLeft(x, 7, 0x9d2c5680);
    x = unshiftRight(x, 11);
    return x >>> 0;
  };

  it("recovers the internal state word from a SINGLE emitted word", () => {
    const twisted = twist(initGenrand(DEFAULT_SEED));
    const emitted = refStream(DEFAULT_SEED, 8);
    for (let i = 0; i < 8; i++) {
      expect(untemper(emitted[i] as number)).toBe(twisted[i] as number);
    }
  });

  it("recovers the WHOLE state from 624 consecutive outputs, and predicts the rest", () => {
    // The attack in three lines: untemper 624 outputs to recover the state
    // vector, then run the generator's own twist forward to predict output 625
    // onward. No search, no statistics, and no knowledge of the seed.
    const observed = refStream(DEFAULT_SEED, MT_N + 8);
    const recovered = Uint32Array.from(observed.slice(0, MT_N).map(untemper));
    const predicted = twist(recovered);
    expect(Array.from(predicted.subarray(0, 8)).map(temper)).toEqual(
      observed.slice(MT_N, MT_N + 8),
    );
  });

  it("attributes the leak to the OUTPUT FUNCTION, not to a short period", () => {
    // The contrast that makes the lesson transferable. What breaks MT19937 is
    // that its output function is invertible and its state is emitted whole —
    // NOT that its period is short. Its period is 2^19937 − 1, astronomically
    // longer than the LCGs' ~2^31, and it is still fully predictable. Period
    // length and unpredictability are independent properties, which is exactly
    // what a learner meeting only the LCGs and the CSPRNG could not learn.
    const twisted = twist(initGenrand(DEFAULT_SEED));
    const a = temper(twisted[0] as number);
    const b = temper(twisted[1] as number);
    expect(a).not.toBe(b); // a bijection keeps distinct states distinct
    expect(untemper(a)).toBe(twisted[0] as number);
    expect(untemper(b)).toBe(twisted[1] as number);
  });
});
