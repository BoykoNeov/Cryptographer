/**
 * ml-kem.sample-ntt — `SampleNTT` (FIPS 203 Algorithm 7): expand a 34-byte seed
 * into a uniformly random polynomial, already in the transformed domain.
 *
 * Input ports: `input` (`ρ ‖ j ‖ i`) and `modulus` (q). Output ports: `output`,
 * a 256-coefficient polynomial in the app's port representation, and `squeezes`,
 * the number of 168-byte SHAKE128 blocks this particular draw consumed.
 *
 * ## The rejection loop, and why the block count is an output port
 *
 * Candidates are read three bytes at a time and unpacked into two 12-bit
 * numbers. A 12-bit number runs to 4095 but `q` is 3329, so roughly one
 * candidate in six is out of range and is **discarded**. Since the discards
 * depend on the hash output, the number of bytes a draw consumes is a **random
 * variable with no fixed bound**.
 *
 * That is the whole trap this step is written around. Squeezing a hardcoded
 * number of blocks and slicing coefficients out of it produces a matrix that is
 * silently wrong on some seeds — a wrong public key that fails only for the
 * seeds you did not happen to test. It is the same failure class as an
 * undersized RSA square-and-multiply unroll, which this project has already
 * shipped once. So the loop condition here is the **accepted-coefficient count**
 * and nothing else, and blocks are squeezed on demand.
 *
 * `squeezes` exists so that property is *observable* rather than asserted in a
 * comment. Measured over the 162 matrix draws of an 18-seed fixture: 160 draws
 * take three blocks and two take four. A test that only checked "more than two
 * blocks" would therefore be vacuous — three is simply the modal cost — which is
 * why `tests/ml-kem-monoliths.test.ts` asserts that the count VARIES.
 *
 * It is also the honest thing to show a learner: this is the one step in the app
 * whose cost depends on the value it is hashing rather than on its size.
 *
 * ## Why the output is already transformed
 *
 * Nothing here transforms anything — the bytes are simply *declared* to be a
 * polynomial's NTT representation. That is legitimate because the matrix `A` is
 * uniformly random and the transform is a bijection: a uniformly random element
 * of the transformed domain is exactly as good as transforming a uniformly
 * random polynomial, and it saves nine forward transforms per key generation.
 * `A` is never needed in any other form.
 *
 * ## The two index bytes are appended OUTSIDE this step
 *
 * `A[i][j]` is drawn from `ρ ‖ j ‖ i` in key generation and from `ρ ‖ i ‖ j` in
 * encryption — that byte swap IS the transpose, and it is the entire difference
 * between the two. Applying it in both places, or in neither, gives a key
 * generation that passes its tests and an encryption that does not. A fact that
 * load-bearing belongs on the canvas as a visible join, not inside an executor.
 *
 * See `ml-kem-hash-g.ts` for the cross-reference-monolith note covering this
 * family, and `src/ciphers/keccak-compute.ts` for why the sponge here is the
 * same one the SHAKE128 trace walks.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { shake128Reader } from "../ciphers/keccak-compute";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { readZqModulus, readZqVecParams, requireZqPort, writeCoeff } from "../core/zq-vector";

const STEP = "ml-kem.sample-ntt";

/** A polynomial is 256 coefficients — FIPS 203's `n`. */
const COEFF_COUNT = 256;

/** The `squeezes` port is a big-endian count; two bytes so a pathological seed
 *  reports honestly instead of wrapping. */
const SQUEEZE_COUNT_BYTES = 2;

export const mlKemSampleNttPortContract: PortContract = {
  inputs: new Map([
    ["input", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: (params: Json) => {
    const { coeffBytes } = readZqVecParams(params, STEP);
    return new Map([
      ["output", { layout: "raw" as const, byteLength: COEFF_COUNT * coeffBytes }],
      ["squeezes", { layout: "raw" as const, byteLength: SQUEEZE_COUNT_BYTES }],
    ]);
  },
};

export const mlKemSampleNtt: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const input = requireZqPort(inputs, "input", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  const qn = Number(q);

  const nextBlock = shake128Reader(input);
  const out = new Uint8Array(COEFF_COUNT * p.coeffBytes);

  let accepted = 0;
  let squeezes = 0;
  // Annotated because `new Uint8Array(n)` narrows to `Uint8Array<ArrayBuffer>`
  // while the squeeze returns the `ArrayBufferLike` default, and this variable
  // is assigned from both.
  let block: Uint8Array = new Uint8Array(0);
  let pos = 0;

  // The loop condition is the ACCEPTED count. Everything else — how many bytes
  // were read, how many blocks were squeezed — falls out of it. Inverting that
  // (loop over a fixed byte budget, hope 256 coefficients fit) is the bug this
  // step's header describes.
  while (accepted < COEFF_COUNT) {
    if (pos + 3 > block.length) {
      // Any leftover one or two bytes are DISCARDED rather than carried across
      // the block boundary: Algorithm 7 reads the stream in three-byte groups
      // from the start of each squeeze. The rate, 168, is divisible by 3, so on
      // the shipped parameters this never actually drops a byte — but a learner
      // who edits the rate would otherwise get a silently different stream.
      block = nextBlock();
      squeezes += 1;
      pos = 0;
    }
    const c0 = block[pos] as number;
    const c1 = block[pos + 1] as number;
    const c2 = block[pos + 2] as number;
    pos += 3;

    // Three bytes carry two 12-bit candidates: the low nibble of the middle
    // byte belongs to the first, the high nibble to the second.
    const d1 = c0 + 256 * (c1 % 16);
    const d2 = (c1 >> 4) + 16 * c2;

    if (d1 < qn) writeCoeff(out, accepted++, BigInt(d1), p);
    if (d2 < qn && accepted < COEFF_COUNT) writeCoeff(out, accepted++, BigInt(d2), p);
  }

  const count = new Uint8Array(SQUEEZE_COUNT_BYTES);
  count[0] = (squeezes >>> 8) & 0xff;
  count[1] = squeezes & 0xff;
  return new Map([
    ["output", out],
    ["squeezes", count],
  ]);
};

export const mlKemSampleNttDoc: StepDocumentation = {
  name: "Sample a matrix polynomial (rejection sampling)",
  summary:
    "Expands a 34-byte seed into 256 uniformly random coefficients by squeezing SHAKE128 and throwing away every candidate that is too big.",
  detail: `# Sample a matrix polynomial

Turns a 34-byte seed into a whole polynomial of uniformly random coefficients.

The seed is squeezed through **SHAKE128**, and the output stream is read three
bytes at a time. Each group of three carries two 12-bit numbers:

\`\`\`
c₀ c₁ c₂  →  d₁ = c₀ + 256·(c₁ mod 16)
             d₂ = ⌊c₁/16⌋ + 16·c₂
\`\`\`

## Why some candidates are thrown away

Twelve bits reach 4095, but the modulus is 3329. Keeping an out-of-range number
by reducing it — \`d mod q\` — would make the small values more likely than the
large ones, and "uniformly random" is precisely what the matrix has to be.

So anything ≥ 3329 is **discarded**, and about one candidate in six is. There is
no way to know in advance how many will be: it depends on the hash output.

## The step's cost depends on its value, not its size

Everything else in this app takes the same amount of work every time. This does
not. Watch the squeeze counter on this step across the nine matrix entries —
most draws need three 168-byte blocks, some need four.

That is why the loop asks *"do I have 256 coefficients yet?"* and never *"have I
used my three blocks?"*. Squeezing a fixed number of blocks would work almost
always and produce a silently wrong public key the rest of the time.

## Already transformed

The coefficients come out labelled as a polynomial in the **transformed** (NTT)
domain, without anything being transformed. That is allowed here and nowhere
else: the matrix is meant to be uniformly random, the transform is a
one-to-one relabelling, and random-then-transform is the same as random. It
saves nine full transforms per key generation, and the matrix is never wanted in
any other form.

## The seed's last two bytes

The seed is the public value ρ followed by two index bytes saying which matrix
entry this is. Their ORDER is what distinguishes the matrix from its transpose —
key generation and encryption append them the other way round from each other.
You can see that join happening just above this step; it is deliberately not
hidden in here, because getting it right in one place and wrong in the other is
an error that only shows up when two different implementations try to talk.`,
  params: new Map([
    ["coeffBytes", "How many bytes each sampled coefficient occupies on the way out. 2 here."],
    [
      "littleEndian",
      "Byte order within one outgoing coefficient. It does not affect how the SHAKE128 stream is unpacked, whose 12-bit layout is fixed by the specification.",
    ],
  ]),
  references: [
    "FIPS 203 Algorithm 7 — SampleNTT",
    "FIPS 203 §4.1 — XOF is SHAKE128",
    "FIPS 202 §6.2 — SHAKE128, and the 168-byte rate",
  ],
};
