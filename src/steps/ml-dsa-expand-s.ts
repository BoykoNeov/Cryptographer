/**
 * ml-dsa.expand-s — expand the 64-byte secret seed ρ′ into the two secret
 * vectors s1 and s2, every coefficient in `[−η, η]` (FIPS 204 Algorithm 33,
 * `ExpandS`, over Algorithm 31, `RejBoundedPoly`).
 *
 * Two input ports: `input` (ρ′) and `modulus` (q, so a negative coefficient can
 * be written as `q − x`). Two output ports: `s1` (l polynomials) and `s2`
 * (k polynomials).
 *
 * ## Where each polynomial's randomness comes from
 *
 * Polynomial number `r` (0 … l+k−1) squeezes SHAKE256 over `ρ′ ‖ r`, with `r`
 * written as **two bytes, little-endian** — not one byte, as ExpandA's indices
 * are, and not big-endian, as this app's ports are. The first l polynomials are
 * s1, the next k are s2.
 *
 * ## The rejection rule, per half-byte
 *
 * Each squeezed byte supplies two candidates, its low nibble first. For η = 2
 * a nibble below 15 becomes `2 − (nibble mod 5)`, which is uniform on
 * `{−2, …, 2}` because 15 is a multiple of 5; 15 itself is rejected. For η = 4
 * a nibble below 9 becomes `4 − nibble`. Those are the only two η FIPS 204
 * defines, and the step refuses any other rather than invent a rule.
 *
 * Contrast ML-KEM, which makes its noise by a centred binomial (`zq-cbd@1`):
 * a bell curve. Here the distribution is FLAT on `[−η, η]`, which is what the
 * signature's security argument needs.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { byteStream, shake256Reader } from "../ciphers/keccak-compute";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readZqBitWidth,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
} from "../core/zq-vector";

const STEP = "ml-dsa.expand-s";
const N = 256;

const readShape = (params: Json): { k: number; l: number; eta: number } => {
  const eta = readZqBitWidth(params, STEP, "eta", 4);
  if (eta !== 2 && eta !== 4) {
    throw new Error(
      `${STEP}: params.eta must be 2 or 4 — the only two FIPS 204 defines a sampling rule for — got ${eta}`,
    );
  }
  return {
    k: readZqBitWidth(params, STEP, "k", 16),
    l: readZqBitWidth(params, STEP, "l", 16),
    eta,
  };
};

export const mlDsaExpandSPortContract: PortContract = {
  inputs: new Map([
    ["input", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: (params: Json) => {
    const { coeffBytes } = readZqVecParams(params, STEP);
    const { k, l } = readShape(params);
    return new Map([
      ["s1", { layout: "raw" as const, byteLength: l * N * coeffBytes }],
      ["s2", { layout: "raw" as const, byteLength: k * N * coeffBytes }],
    ]);
  },
};

/** CoeffFromHalfByte (Algorithm 15): a value in [−η, η], or null to reject. */
const coeffFromHalfByte = (b: number, eta: number): number | null => {
  if (eta === 2) return b < 15 ? 2 - (b % 5) : null;
  return b < 9 ? 4 - b : null;
};

/** `RejBoundedPoly(seed)` — 256 accepted coefficients in [−η, η]. */
export const rejBoundedPoly = (seed: Uint8Array, eta: number): number[] => {
  const stream = byteStream(shake256Reader(seed));
  const out: number[] = [];
  while (out.length < N) {
    const z = stream.next();
    // Low nibble first, then high — and the high one is still tried even when
    // the low one was rejected, but not once 256 are in hand.
    const z0 = coeffFromHalfByte(z % 16, eta);
    const z1 = coeffFromHalfByte(z >> 4, eta);
    if (z0 !== null) out.push(z0);
    if (z1 !== null && out.length < N) out.push(z1);
  }
  return out;
};

export const mlDsaExpandS: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const { k, l, eta } = readShape(params);
  const rhoPrime = requireZqPort(inputs, "input", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);

  const sample = (r: number): Uint8Array => {
    const seed = new Uint8Array(rhoPrime.length + 2);
    seed.set(rhoPrime);
    // Two bytes, LITTLE-endian — see the header.
    seed[rhoPrime.length] = r & 0xff;
    seed[rhoPrime.length + 1] = (r >> 8) & 0xff;
    const out = new Uint8Array(N * p.coeffBytes);
    rejBoundedPoly(seed, eta).forEach((c, i) => {
      writeCoeff(out, i, ((BigInt(c) % q) + q) % q, p);
    });
    return out;
  };

  const s1 = new Uint8Array(l * N * p.coeffBytes);
  const s2 = new Uint8Array(k * N * p.coeffBytes);
  for (let r = 0; r < l; r++) s1.set(sample(r), r * N * p.coeffBytes);
  for (let r = 0; r < k; r++) s2.set(sample(l + r), r * N * p.coeffBytes);
  return new Map([
    ["s1", s1],
    ["s2", s2],
  ]);
};

export const mlDsaExpandSDoc: StepDocumentation = {
  name: "ExpandS — the secret vectors from a seed",
  summary:
    "Expands a 64-byte secret seed into the secret vectors s1 and s2, every coefficient a small number between −η and η.",
  detail: `# ExpandS

Turns the 64-byte secret seed ρ′ into the two secret vectors of the private
key: **s1** (l polynomials) and **s2** (k polynomials). Every coefficient is a
small number in \`−η … η\` — for ML-DSA-44, η = 2, so one of −2, −1, 0, 1, 2.

## How each polynomial is drawn

Polynomial number \`r\` squeezes **SHAKE256** over ρ′ followed by \`r\` written
as two bytes, least significant first. s1 takes numbers 0 … l−1 and s2 the next
k. Every byte of output gives two candidates, low half first:

\`\`\`
η = 2:   half-byte b < 15   →   2 − (b mod 5)        b = 15 is thrown away
η = 4:   half-byte b < 9    →   4 − b                b ≥ 9 is thrown away
\`\`\`

Fifteen values fold onto five evenly (three each), which is why 15 — and only
15 — has to be discarded: keeping it would make one outcome slightly more
likely than the rest.

## Flat, not a bell curve

ML-KEM makes its secrets by adding and subtracting coin flips, which piles
values up near zero. These are **uniform**: −2 is exactly as likely as 0.

## Small, and stored the long way round

A sampled −1 travels the wire as \`q − 1\` = 8,380,416, like every negative
number here. It is still a tiny number; read anything near q as a small
negative one.

## The same sponge as Hash → SHAKE256

This step's SHAKE256 is the one the traced **Hash → SHAKE256** entry walks,
collapsed to one frame per call.`,
  params: new Map([
    ["coeffBytes", "How many bytes each sampled coefficient occupies on the way out. 4."],
    ["littleEndian", "Byte order within one outgoing coefficient. False (big-endian)."],
    ["k", "How many polynomials in s2. 4 for ML-DSA-44."],
    ["l", "How many polynomials in s1. 4 for ML-DSA-44."],
    [
      "eta",
      "The range of the secret coefficients, −η … η. 2 for ML-DSA-44; FIPS 204 defines only 2 and 4.",
    ],
  ]),
  references: [
    "FIPS 204 Algorithm 33 — ExpandS",
    "FIPS 204 Algorithm 31 — RejBoundedPoly",
    "FIPS 204 Algorithm 15 — CoeffFromHalfByte",
    "FIPS 202 §6.2 — SHAKE256",
  ],
};
