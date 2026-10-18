/**
 * ml-dsa.ntt / ml-dsa.intt — the number-theoretic transform over
 * `Z_8380417[X]/(X²⁵⁶+1)`, one frame each (FIPS 204 Algorithms 41 and 42).
 *
 * One input port `input`: any whole number of polynomials, each 256 × 4-byte
 * big-endian coefficients in `[0, q)`. One output port `output`, the same
 * length: each polynomial transformed (or transformed back) on its own.
 *
 * ## What kind of monolith this is — a cross-reference
 *
 * The transform is not hidden and it is not unshowable. It is one dropdown
 * away, fully traced, under **Lattice → NTT mod 8380417**: eight layers, 128
 * butterflies each, the ζ table advancing on the chain. This collapses it to a
 * single frame for VOLUME, the reason ML-KEM's hashes give: one signing attempt
 * runs 5 forward and 16 inverse transforms, and at ~1,800 frames apiece that is
 * about 38,000 frames of butterflies per attempt before a single bound has been
 * checked. (Measured in the plan, not guessed.)
 *
 * So the description names the selector entry, and the test suite pins this
 * executor against that entry's traced spec on the same inputs — the one-frame
 * form cannot drift from the one a learner watches.
 *
 * ## Why it is written out here rather than built from the spec
 *
 * The traced transform is a SPEC — a tree of butterfly leaves the runtime
 * walks. Running that tree from inside an executor would need a runtime inside
 * a step. Algorithms 41 and 42 are a dozen lines each, so they are written out
 * directly, verbatim from FIPS 204, and cross-checked rather than shared. That
 * makes the agreement between the two a real test: they are two
 * implementations of one definition, not one implementation called twice.
 *
 * ## The modulus is fixed, on purpose
 *
 * The ζ table is the powers of 1753 modulo 8380417, so it is meaningless at any
 * other modulus. This step therefore takes no `modulus` port: a learner who
 * edits q elsewhere should not be able to wire a q that silently disagrees
 * with the table baked in here. The traced selector entry is where the
 * transform is editable.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. No params.
 */

import {
  ML_DSA_N_INV_256,
  ML_DSA_POLY_BYTES,
  ML_DSA_Q,
  ML_DSA_ZETAS,
} from "../ciphers/mldsa-constants";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

const q = ML_DSA_Q;

/** `x mod q` into `[0, q)`. Products stay below 2⁴⁷, exact in a double. */
const mod = (x: number): number => ((x % q) + q) % q;

const zeta = (k: number): number => ML_DSA_ZETAS[k] as number;

/** FIPS 204 Algorithm 41, in place over 256 coefficients. */
const forward = (w: number[]): void => {
  let m = 0;
  for (let len = 128; len >= 1; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      m += 1;
      const z = zeta(m);
      for (let j = start; j < start + len; j++) {
        const t = mod(z * (w[j + len] as number));
        w[j + len] = mod((w[j] as number) - t);
        w[j] = mod((w[j] as number) + t);
      }
    }
  }
};

/** FIPS 204 Algorithm 42, in place, including the final `256⁻¹` scaling. */
const inverse = (w: number[]): void => {
  let m = 256;
  for (let len = 1; len < 256; len <<= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      m -= 1;
      const z = q - zeta(m);
      for (let j = start; j < start + len; j++) {
        const t = w[j] as number;
        w[j] = mod(t + (w[j + len] as number));
        w[j + len] = mod(z * mod(t - (w[j + len] as number)));
      }
    }
  }
  for (let j = 0; j < 256; j++) w[j] = mod(ML_DSA_N_INV_256 * (w[j] as number));
};

const readPoly = (bytes: Uint8Array, offset: number, step: string): number[] => {
  const out: number[] = [];
  for (let i = 0; i < 256; i++) {
    const b = offset + 4 * i;
    const v =
      (bytes[b] as number) * 2 ** 24 +
      (bytes[b + 1] as number) * 2 ** 16 +
      (bytes[b + 2] as number) * 2 ** 8 +
      (bytes[b + 3] as number);
    if (v >= q) {
      throw new Error(`${step}: coefficient ${offset / 4 + i} is ${v}, not a residue below ${q}`);
    }
    out.push(v);
  }
  return out;
};

const writePoly = (out: Uint8Array, offset: number, w: readonly number[]): void => {
  w.forEach((v, i) => {
    const b = offset + 4 * i;
    out[b] = (v >>> 24) & 0xff;
    out[b + 1] = (v >>> 16) & 0xff;
    out[b + 2] = (v >>> 8) & 0xff;
    out[b + 3] = v & 0xff;
  });
};

const transformAll =
  (step: string, transform: (w: number[]) => void): PortedExecutor =>
  (inputs, _params, _ctx) => {
    const input = inputs.get("input");
    if (input === undefined) throw new Error(`${step}: missing required input port "input"`);
    if (input.length === 0 || input.length % ML_DSA_POLY_BYTES !== 0) {
      throw new Error(
        `${step}: input is ${input.length} bytes, not a whole number of ${ML_DSA_POLY_BYTES}-byte polynomials`,
      );
    }
    const out = new Uint8Array(input.length);
    for (let offset = 0; offset < input.length; offset += ML_DSA_POLY_BYTES) {
      const w = readPoly(input, offset, step);
      transform(w);
      writePoly(out, offset, w);
    }
    return new Map([["output", out]]);
  };

export const mlDsaNttPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const mlDsaNtt: PortedExecutor = transformAll("ml-dsa.ntt", forward);
export const mlDsaIntt: PortedExecutor = transformAll("ml-dsa.intt", inverse);

const SHARED_DETAIL = `## One frame here, eight layers under Lattice

This is the whole transform collapsed to a single step. It is not hidden: select
**NTT mod 8380417** under **Lattice** to watch the same transform run layer by
layer — 128 butterflies per layer, the twiddle factors advancing as it goes.

It collapses here because ML-DSA needs a lot of them. One signing attempt runs
21 transforms, and drawn out in full that is tens of thousands of butterflies
before a single check on the candidate signature. The two are pinned to agree
on every input the tests feed them.

## Any number of polynomials

Feed it one polynomial (1024 bytes) or a whole vector of them; each is
transformed on its own. A vector of four comes out as four transformed
polynomials, in the same order.

## The modulus is built in

The twiddle factors are powers of 1753 modulo 8380417, so they only make sense
at that modulus. This step therefore has no modulus input to edit; the traced
version under Lattice is where the transform can be taken apart.`;

export const mlDsaNttDoc: StepDocumentation = {
  name: "NTT mod 8380417 (one frame)",
  summary:
    "Transforms each polynomial so that multiplying two of them becomes 256 independent products — the whole eight-layer transform, collapsed to one step.",
  detail: `# NTT mod 8380417

Turns a polynomial into its transformed form: 256 numbers, one per root of
\`X²⁵⁶ + 1\`. In this form two polynomials multiply position by position — one
product per coefficient instead of 256 × 256.

${SHARED_DETAIL}`,
  params: new Map(),
  references: [
    "FIPS 204 Algorithm 41 — NTT",
    "FIPS 204 Appendix B — the ζ table",
    "Lattice → NTT mod 8380417 — the same transform, traced",
  ],
};

export const mlDsaInttDoc: StepDocumentation = {
  name: "Inverse NTT mod 8380417 (one frame)",
  summary:
    "Transforms each polynomial back from the transformed domain — the whole eight-layer inverse, collapsed to one step.",
  detail: `# Inverse NTT mod 8380417

Undoes the transform: takes 256 transformed values and returns the polynomial
they came from. It runs the butterflies in the opposite order and finishes by
multiplying every coefficient by \`256⁻¹ = 8347681\`.

${SHARED_DETAIL}`,
  params: new Map(),
  references: [
    "FIPS 204 Algorithm 42 — NTT⁻¹",
    "FIPS 204 Appendix B — the ζ table",
    "Lattice → NTT mod 8380417 — the same transform, traced",
  ],
};
