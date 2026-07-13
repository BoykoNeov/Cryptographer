/**
 * rotate-lanes — port-native "rotate each fixed-width lane by its own offset"
 * primitive (SHA-3 / Keccak, 2026-07-13).
 *
 * **Why this primitive exists.** Keccak-f's ρ step rotates each of the 25
 * 64-bit lanes LEFT by a lane-specific amount (FIPS 202 §3.2.2, Table 2). The
 * existing `rotate-bits-right@1` rotates EVERY word by the SAME amount and
 * assembles each word big-endian — neither fits ρ, which needs
 *   - **per-lane** offsets (25 distinct rotation amounts), and
 *   - **little-endian** lane bytes (Keccak's state is a little-endian bit
 *     string — see FIPS 202 §3.1.2), and
 *   - a **left** rotation.
 * Expressing ρ as 25 separate `rotate-bits-right@1` leaves (with byte-reversal
 * wrappers to fix the endianness) would be a wall of table constants with no
 * pedagogical payoff. This one leaf carries the whole ρ permutation, with the
 * offsets visible as a param.
 *
 * **What it does.** Reads the `input` port as a packed array of lanes, each
 * `wordBits/8` bytes wide, and rotates lane `i` LEFT by `offsets[i]` bit
 * positions (a circular shift — bits that fall off the top wrap to the bottom).
 * The number of lanes is `input.length / (wordBits/8)`, and MUST equal
 * `offsets.length`. Output is the same length as the input.
 *
 * **Endianness (`littleEndian`).** A rotation acts on the numeric VALUE of a
 * lane, so the byte order used to decode/encode the lane matters. `littleEndian:
 * true` (Keccak's convention) reads the lowest-address byte as the least
 * significant; `false` reads it as the most significant (matching
 * `rotate-bits-right@1`). Rotation is NOT endianness-invariant, so this flag is
 * load-bearing: decoding a Keccak lane big-endian would scramble ρ.
 *
 * **Left vs right.** ρ is defined as a LEFT rotation (FIPS 202 §3.2.2:
 * `A′[x,y,z] = A[x,y,(z−r) mod w]`, which on the lane value is `rotl(v, r)`), so
 * this primitive rotates LEFT. A right rotation by `r` is a left rotation by
 * `wordBits − r`, so a caller wanting right-rotation can pre-adjust the offsets;
 * a dedicated direction param is deferred until a second consumer needs it.
 *
 * **Authoring conventions.** Port-native: `kind:"ported"`, omit `legacy`,
 * `meta`, `shapeContract`. Both ports polymorphic `layout:"raw"` (the length is
 * wiring-determined: 200 bytes for Keccak-f[1600]).
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

const VALID_WORD_BITS = new Set([8, 16, 32, 64]);

type Params = {
  readonly wordBits: number;
  readonly offsets: readonly number[];
  readonly littleEndian: boolean;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("rotate-lanes: params must be an object");
  }
  const p = params as Record<string, Json>;
  const wordBits = p.wordBits;
  if (typeof wordBits !== "number" || !VALID_WORD_BITS.has(wordBits)) {
    throw new Error("rotate-lanes: params.wordBits must be 8, 16, 32, or 64");
  }
  const offsets = p.offsets;
  if (!Array.isArray(offsets) || offsets.length < 1) {
    throw new Error("rotate-lanes: params.offsets must be a non-empty array of rotation amounts");
  }
  for (const o of offsets) {
    if (typeof o !== "number" || !Number.isInteger(o) || o < 0) {
      throw new Error("rotate-lanes: every offset must be a non-negative integer");
    }
  }
  const littleEndian = p.littleEndian;
  if (littleEndian !== undefined && typeof littleEndian !== "boolean") {
    throw new Error("rotate-lanes: params.littleEndian must be a boolean when present");
  }
  return {
    wordBits,
    offsets: offsets as readonly number[],
    littleEndian: (littleEndian as boolean | undefined) ?? false,
  };
};

// ─── Lane codec + left-rotate (BigInt, so 64-bit is exact) ─────────────────

const decodeLane = (
  bytes: Uint8Array,
  start: number,
  width: number,
  littleEndian: boolean,
): bigint => {
  let v = 0n;
  for (let b = 0; b < width; b++) {
    const byte = BigInt(bytes[start + b] as number);
    // little-endian: byte b carries bit-weight 8·b; big-endian: the reverse.
    const shift = littleEndian ? 8 * b : 8 * (width - 1 - b);
    v |= byte << BigInt(shift);
  }
  return v;
};

const encodeLane = (
  out: Uint8Array,
  start: number,
  width: number,
  littleEndian: boolean,
  value: bigint,
): void => {
  for (let b = 0; b < width; b++) {
    const shift = littleEndian ? 8 * b : 8 * (width - 1 - b);
    out[start + b] = Number((value >> BigInt(shift)) & 0xffn);
  }
};

// ─── Port contract + executor ─────────────────────────────────────────────

export const rotateLanesPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const rotateLanes: PortedExecutor = (inputs, params, _ctx) => {
  const { wordBits, offsets, littleEndian } = readParams(params);
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error("rotate-lanes: missing required input port 'input'");
  }
  const width = wordBits / 8;
  if (input.length % width !== 0) {
    throw new Error(
      `rotate-lanes: input length ${input.length} is not a multiple of lane size ${width} (wordBits=${wordBits})`,
    );
  }
  const laneCount = input.length / width;
  if (laneCount !== offsets.length) {
    throw new Error(
      `rotate-lanes: input has ${laneCount} lanes but offsets has ${offsets.length} entries — they must match`,
    );
  }
  const wb = BigInt(wordBits);
  const mask = (1n << wb) - 1n;
  const out = new Uint8Array(input.length);
  for (let i = 0; i < laneCount; i++) {
    const v = decodeLane(input, i * width, width, littleEndian);
    // Canonicalize the rotation amount to [0, wordBits). r === 0 is identity.
    const r = BigInt((offsets[i] as number) % wordBits);
    const rotated = r === 0n ? v : ((v << r) | (v >> (wb - r))) & mask;
    encodeLane(out, i * width, width, littleEndian, rotated);
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const rotateLanesDoc: StepDocumentation = {
  name: "Rotate lanes",
  summary:
    "Rotates each fixed-width lane left by its own amount — the per-lane rotation used by Keccak's ρ step.",
  detail: `# Rotate lanes

Splits the input into equal-width **lanes** and rotates each lane's bits to the
**left** by a per-lane amount. A rotation is a circular shift: bits that fall
off the top wrap back to the bottom, so no bits are lost — only rearranged.
Unlike a plain rotate, **every lane can turn by a different amount**, given by
the \`offsets\` list (one entry per lane).

## Math

For lane \`i\` of width \`B\` bits, rotating left by \`r = offsets[i]\`:

\`\`\`
ROTL(v, r, B) = ((v << r) | (v >> (B − r)))   within B bits
\`\`\`

The byte order used to read each lane's value is set by \`littleEndian\`.
Rotation depends on that value, so the endianness matters.

## Where it fits

In **SHA-3 / Keccak** this is the **ρ (rho) step** (FIPS 202 §3.2.2). The
1600-bit state is 25 lanes of 64 bits; ρ rotates lane \`(x,y)\` left by a fixed
offset from Keccak's rotation table. Keccak stores its state as a
**little-endian** bit string, so \`littleEndian\` is \`true\` here — reading the
lanes big-endian would rotate the wrong bits and silently corrupt the hash.

ρ provides **inter-slice diffusion**: on its own it just spins each lane, but
combined with θ (which mixes columns) and π (which moves lanes around), a single
flipped input bit spreads across the whole state within a couple of rounds.`,
  params: new Map([
    ["wordBits", "Lane width in bits: 8, 16, 32, or 64 (64 for Keccak)."],
    [
      "offsets",
      "One left-rotation amount per lane, in order. The number of entries must equal the number of lanes (input length ÷ lane size).",
    ],
    [
      "littleEndian",
      "How each lane's bytes are read into a value: true = lowest byte is least significant (Keccak's convention); false = big-endian. Defaults to false.",
    ],
  ]),
  references: ["FIPS 202 §3.2.2 (Keccak ρ step)", "FIPS 202 §3.1.2 (state as a bit string)"],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead.
};
