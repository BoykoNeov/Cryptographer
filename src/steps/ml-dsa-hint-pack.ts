/**
 * ml-dsa.hint-pack / ml-dsa.hint-unpack — store the hint as a list of
 * POSITIONS rather than a bit per coefficient (FIPS 204 Algorithms 20 and 21,
 * `HintBitPack` and `HintBitUnpack`).
 *
 * hint-pack: input ports `h` (k polynomials, every coefficient 0 or 1) and
 * `omega` (ω). Output `output`: `ω + k` bytes.
 *
 * hint-unpack: input ports `input` (the `ω + k` bytes) and `omega`. Outputs
 * `output` (the k polynomials) and `valid` (one byte, 1 or 0).
 *
 * ## The format
 *
 * A hint is nearly all zeros — at most ω = 80 ones among 1024 coefficients —
 * so storing a bit for each would waste 128 bytes on zeros. Instead:
 *
 * - bytes `0 … ω−1` list the POSITIONS of the ones, polynomial by polynomial,
 *   each position one byte (0…255 within its polynomial), and zeros after the
 *   last one;
 * - byte `ω + i` is a running total: how many positions belong to polynomials
 *   0 … i.
 *
 * So ML-DSA-44's hint is always 84 bytes, however many ones it has.
 *
 * ## Unpacking must reject — as a flag, never a throw
 *
 * A signature arrives from outside, and its hint bytes may be anything.
 * HintBitUnpack refuses (FIPS's ⊥) in three cases, and all three matter:
 *
 * 1. a running total goes DOWN or past ω;
 * 2. positions within one polynomial are not strictly increasing — which also
 *    rules out listing the same position twice;
 * 3. a byte after the last listed position is NOT zero — the one usually
 *    forgotten.
 *
 * Cases 2 and 3 exist to make the encoding UNIQUE: without them one hint could
 * be written several ways, and an attacker could produce a second valid
 * signature from a first one by rewriting its hint. ("Strong unforgeability".)
 * Node's verifier rejects all three, and the oracle test checks each against
 * it.
 *
 * Refusal is a `valid = 0` flag with an all-zero `output`, not an exception: a
 * malformed signature is an ordinary input to a verifier, whose job is to say
 * "invalid", not to crash.
 *
 * ## Why ω is on a port
 *
 * ω sets the length of the packed hint and the count check in signing. One
 * wire, three readers, so they cannot disagree about how long a signature is.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { coeffNumbers, flagByte, packNumbers } from "../core/ml-dsa-arith";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { readScalarPort, readZqVecParams, requireZqPort, zqElementCount } from "../core/zq-vector";

const PACK = "ml-dsa.hint-pack";
const UNPACK = "ml-dsa.hint-unpack";
const N = 256;

export const mlDsaHintPackPortContract: PortContract = {
  inputs: new Map([
    ["h", { layout: "raw" }],
    ["omega", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const mlDsaHintUnpackPortContract: PortContract = {
  inputs: new Map([
    ["input", { layout: "raw" }],
    ["omega", { layout: "raw" }],
  ]),
  outputs: new Map([
    ["output", { layout: "raw" }],
    ["valid", { layout: "raw", byteLength: 1 }],
  ]),
};

/** HintBitPack over a flat list of 0/1 values, k·256 long. */
export const hintBitPack = (h: readonly number[], omega: number): Uint8Array => {
  const k = h.length / N;
  const y = new Uint8Array(omega + k);
  let index = 0;
  for (let i = 0; i < k; i++) {
    for (let j = 0; j < N; j++) {
      if (h[i * N + j] !== 0) {
        if (index >= omega) {
          throw new Error(
            `${PACK}: the hint has more than ω = ${omega} ones; a signature has no room for them (the signing loop rejects such a candidate first)`,
          );
        }
        y[index++] = j;
      }
    }
    y[omega + i] = index;
  }
  return y;
};

/**
 * HintBitUnpack. Returns the hint, or the reason it was refused. Exported so
 * the narrator can say WHICH of the three rules a malformed hint broke.
 */
export const hintBitUnpack = (
  y: Uint8Array,
  omega: number,
): { h: number[]; error: string | null } => {
  const k = y.length - omega;
  const h = new Array<number>(k * N).fill(0);
  const refuse = (error: string) => ({ h: new Array<number>(k * N).fill(0), error });
  let index = 0;
  for (let i = 0; i < k; i++) {
    const end = y[omega + i] as number;
    if (end < index || end > omega) {
      return refuse(
        `polynomial ${i}'s running total is ${end}, ${end < index ? `below the previous ${index}` : `past ω = ${omega}`}`,
      );
    }
    const first = index;
    while (index < end) {
      if (index > first && (y[index - 1] as number) >= (y[index] as number)) {
        return refuse(
          `polynomial ${i}'s positions are not strictly increasing (${y[index - 1]} then ${y[index]})`,
        );
      }
      h[i * N + (y[index] as number)] = 1;
      index++;
    }
  }
  for (let i = index; i < omega; i++) {
    if (y[i] !== 0) {
      return refuse(`byte ${i}, after the last listed position, is ${y[i]} rather than 0`);
    }
  }
  return { h, error: null };
};

export const mlDsaHintPack: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, PACK);
  const hBytes = requireZqPort(inputs, "h", PACK);
  const n = zqElementCount(hBytes, p, "h", PACK);
  if (n % N !== 0)
    throw new Error(`${PACK}: ${n} coefficients is not a whole number of polynomials`);
  const omega = readScalarPort(inputs, "omega", PACK);
  if (omega > 255)
    throw new Error(`${PACK}: ω = ${omega} does not fit the one-byte running totals`);
  const h = coeffNumbers(hBytes, p);
  h.forEach((bit, i) => {
    if (bit > 1)
      throw new Error(`${PACK}: hint coefficient ${i} is ${bit}; a hint is one bit, 0 or 1`);
  });
  return new Map([["output", hintBitPack(h, omega)]]);
};

export const mlDsaHintUnpack: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, UNPACK);
  const y = requireZqPort(inputs, "input", UNPACK);
  const omega = readScalarPort(inputs, "omega", UNPACK);
  if (y.length <= omega) {
    throw new Error(
      `${UNPACK}: ${y.length} bytes cannot hold ω = ${omega} positions plus one total per polynomial`,
    );
  }
  const { h, error } = hintBitUnpack(y, omega);
  return new Map([
    ["output", packNumbers(h, p)],
    ["valid", flagByte(error === null)],
  ]);
};

export const mlDsaHintPackDoc: StepDocumentation = {
  name: "HintBitPack — the hint as a list of positions",
  summary:
    "Stores the hint compactly: the positions of its ones, then a running count per polynomial — always ω + k bytes.",
  detail: `# HintBitPack

A hint is almost all zeros: at most ω ones among all the coefficients. So rather
than a bit for every coefficient, the signature stores *where the ones are*:

- the first ω bytes list the **positions** of the ones (0 … 255 within their
  polynomial), polynomial by polynomial, with zeros filling the rest;
- the last k bytes are **running totals**: byte \`ω + i\` says how many of the
  listed positions belong to polynomials 0 through i.

For ML-DSA-44 that is always 80 + 4 = **84 bytes**, whether the hint has three
ones or eighty.

## More than ω ones cannot be stored

There are only ω slots. A hint with more ones has nowhere to go, so the step
refuses it — and the signing loop never asks, because it throws such a
candidate away first.

## ω is wired, not set here

ω arrives on a port, so the same constant fixes this format's length, the
unpacker's, and the count check in signing.`,
  params: new Map([
    ["coeffBytes", "How many bytes each incoming hint coefficient occupies. 4."],
    ["littleEndian", "Byte order within one incoming hint coefficient. False (big-endian)."],
  ]),
  references: ["FIPS 204 Algorithm 20 — HintBitPack"],
};

export const mlDsaHintUnpackDoc: StepDocumentation = {
  name: "HintBitUnpack — read the hint back, or refuse it",
  summary:
    "Rebuilds the hint from its list of positions, and reports the signature invalid if the bytes break any of the format's three rules.",
  detail: `# HintBitUnpack

The reverse of HintBitPack — with a job the packer does not have: the bytes
come from a signature someone else made, and they might be anything.

## Three ways to be malformed

1. A running total **goes down**, or exceeds ω.
2. Within one polynomial, the positions are **not strictly increasing**
   (which also catches a position listed twice).
3. A byte **after the last listed position is not zero.**

Any of these and the hint is refused: the \`valid\` output is 0 and the hint
output is all zeros. This is not an error in the program — a malformed
signature is a perfectly normal thing for a verifier to be handed, and its job
is to answer "invalid".

## Why rules 2 and 3 exist

Rule 1 is about making sense of the bytes at all. Rules 2 and 3 are about
making the encoding **unique**: without them the same hint could be written in
several different ways, and anyone holding one valid signature could produce a
second, different, valid signature on the same message by rewriting its hint.
Rule 3 is the one implementations most often forget.`,
  params: new Map([
    ["coeffBytes", "How many bytes each outgoing hint coefficient occupies. 4."],
    ["littleEndian", "Byte order within one outgoing hint coefficient. False (big-endian)."],
  ]),
  references: [
    "FIPS 204 Algorithm 21 — HintBitUnpack",
    "FIPS 204 Algorithm 21 notes — the uniqueness checks that protect strong unforgeability",
  ],
};
