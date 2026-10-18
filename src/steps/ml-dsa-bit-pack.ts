/**
 * ml-dsa.bit-pack / ml-dsa.bit-unpack — pack coefficients in a SIGNED range
 * `[−a, b]` into a dense bit string, and back (FIPS 204 Algorithms 17 and 19,
 * `BitPack` and `BitUnpack`).
 *
 * bit-pack: input ports `a` (the vector), `lower` (the range's magnitude below
 * zero, `a` in FIPS's notation), `upper` (`b`) and `modulus` (q). Output
 * `output`: each coefficient as `b − w` in `bitlen(a + b)` bits, LSB first.
 *
 * bit-unpack: input ports `a` (the packed bytes), `lower`, `upper`, `modulus`.
 * Output `output`: each value `b − x`, written back as a residue mod q.
 *
 * ## Why not `zq-byte-encode@1`
 *
 * `zq-byte-encode@1` IS FIPS 204's `SimpleBitPack` — the same LSB-first bit
 * stream, for values in `[0, b]` — and ML-DSA reuses it unchanged for the
 * public key's `t1`. What it cannot do is a range that dips below zero. The
 * secret vectors live in `[−η, η]`, `t0` in `[−2^(d−1)+1, 2^(d−1)]`, and the
 * signature's `z` in `[−γ1+1, γ1]`; each is stored by FLIPPING it, `b − w`,
 * which maps the range onto `[0, a + b]` with `b` going to 0. That flip is the
 * entire difference, and it is why the unpacker's output is `b − x`, not `x`.
 *
 * ## The range is on ports
 *
 * For `z` the range is `[−(γ1−1), γ1]`, and γ1 is the number P4's signing
 * experiment edits. On ports, the constant that sets the mask's range also sets
 * how z is packed, so the two cannot disagree. (η and d reach here as wired
 * constants too, for the same reason in a quieter key.)
 *
 * ## Strict on the way in, faithful on the way out
 *
 * bit-pack throws on a coefficient outside `[−a, b]` rather than truncating it
 * — a truncated `z` would be a different signature with no error. The signing
 * loop never asks it to pack a rejected candidate; P4 selects zeros first.
 *
 * bit-unpack does NOT range-check, because FIPS 204's BitUnpack does not. Only
 * the secret vectors are affected: their 3-bit fields can hold 5, 6 and 7,
 * which unpack below −η, while z's and t0's ranges fill their fields exactly.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { bitlen, modPm } from "../core/ml-dsa-arith";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readCoeff,
  readScalarPort,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
  zqElementCount,
} from "../core/zq-vector";

const PACK = "ml-dsa.bit-pack";
const UNPACK = "ml-dsa.bit-unpack";

const readRange = (
  inputs: ReadonlyMap<string, Uint8Array>,
  step: string,
): { a: number; b: number; width: number } => {
  const a = readScalarPort(inputs, "lower", step);
  const b = readScalarPort(inputs, "upper", step);
  const width = bitlen(a + b);
  if (width < 1 || width > 32) {
    throw new Error(`${step}: range [−${a}, ${b}] needs ${width} bits; 1 to 32 are supported`);
  }
  return { a, b, width };
};

export const mlDsaBitPackPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["lower", { layout: "raw" }],
    ["upper", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const mlDsaBitUnpackPortContract: PortContract = mlDsaBitPackPortContract;

export const mlDsaBitPack: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, PACK);
  const vec = requireZqPort(inputs, "a", PACK);
  const q = Number(readZqModulus(inputs.get("modulus"), p, PACK));
  const { a, b, width } = readRange(inputs, PACK);
  const n = zqElementCount(vec, p, "a", PACK);
  if ((n * width) % 8 !== 0) {
    throw new Error(`${PACK}: ${n} coefficients × ${width} bits is not a whole number of bytes`);
  }
  const out = new Uint8Array((n * width) / 8);
  for (let i = 0; i < n; i++) {
    const w = modPm(Number(readCoeff(vec, i, p)), q);
    if (w < -a || w > b) {
      throw new Error(
        `${PACK}: coefficient ${i} is ${w}, outside the range [−${a}, ${b}] this packing holds`,
      );
    }
    const v = b - w;
    for (let j = 0; j < width; j++) {
      // LSB of the value first, LSB of the byte first — FIPS 204's BitsToBytes.
      if (Math.floor(v / 2 ** j) % 2 === 1) {
        const bit = i * width + j;
        out[bit >> 3] = (out[bit >> 3] as number) | (1 << (bit & 7));
      }
    }
  }
  return new Map([["output", out]]);
};

export const mlDsaBitUnpack: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, UNPACK);
  const packed = requireZqPort(inputs, "a", UNPACK);
  const q = readZqModulus(inputs.get("modulus"), p, UNPACK);
  const { b, width } = readRange(inputs, UNPACK);
  const totalBits = packed.length * 8;
  if (totalBits % width !== 0) {
    throw new Error(
      `${UNPACK}: ${packed.length} bytes is not a whole number of ${width}-bit values`,
    );
  }
  const n = totalBits / width;
  const out = new Uint8Array(n * p.coeffBytes);
  for (let i = 0; i < n; i++) {
    let x = 0;
    for (let j = 0; j < width; j++) {
      const bit = i * width + j;
      if ((((packed[bit >> 3] as number) >> (bit & 7)) & 1) === 1) x += 2 ** j;
    }
    const w = BigInt(b - x);
    writeCoeff(out, i, ((w % q) + q) % q, p);
  }
  return new Map([["output", out]]);
};

const SHARED = `## Where the range comes from

- **Secret vectors s1, s2:** −η … η, so 3 bits at η = 2.
- **The low part of the key, t0:** −4,095 … 4,096, so 13 bits.
- **The signature's z:** −131,071 … 131,072, so 18 bits.

The two ends arrive on the \`lower\` and \`upper\` ports, as wired constants, so
one constant can set both the range a value is drawn from and the way it is
packed.`;

export const mlDsaBitPackDoc: StepDocumentation = {
  name: "BitPack — signed values to a dense bit string",
  summary:
    "Packs coefficients that may be negative, in a range −a … b, end to end in exactly bitlen(a + b) bits each.",
  detail: `# BitPack

Packs a list of coefficients, each between \`−a\` and \`b\`, into the fewest bits
that can hold that range — no padding, no gaps.

## The flip

A bit string holds non-negative numbers, and these can be negative. So each
value w is stored as \`b − w\` instead:

\`\`\`
w = b      →  0
w = 0      →  b
w = −a     →  a + b
\`\`\`

That fits every value in \`0 … a + b\`, which needs \`bitlen(a + b)\` bits. Each one
is then written low bit first, end to end — the same bit order as the unsigned
packer, "Pack to d-bit stream", which ML-DSA uses for the public key's t1.

## Out-of-range is an error

A value outside \`−a … b\` is refused rather than cut down to fit. A silently
truncated signature would be a different signature, with nothing to say so.

${SHARED}`,
  params: new Map([
    ["coeffBytes", "How many bytes each incoming coefficient occupies. 4."],
    [
      "littleEndian",
      "Byte order within one INCOMING coefficient. The packed output's bit order is fixed by the specification (least significant bit first).",
    ],
  ]),
  references: [
    "FIPS 204 Algorithm 17 — BitPack",
    "FIPS 204 Algorithm 12 — BitsToBytes",
    "FIPS 204 Algorithms 24 and 26 — skEncode and sigEncode, its callers",
  ],
};

export const mlDsaBitUnpackDoc: StepDocumentation = {
  name: "BitUnpack — a dense bit string back to signed values",
  summary:
    "Reads values packed in bitlen(a + b) bits each and undoes the flip, giving coefficients in −a … b.",
  detail: `# BitUnpack

The reverse of BitPack: reads \`bitlen(a + b)\`-bit values x out of the bit
string, low bit first, and turns each back into \`b − x\`. Negative results are
written the way every negative number travels here: −5 as \`q − 5\`.

## No range check, on purpose

A field of \`bitlen(a + b)\` bits can sometimes hold more than \`a + b\`. For z and
t0 it cannot — their ranges fill 18 and 13 bits exactly. But the secret vectors'
range −2 … 2 needs 3 bits, and 3 bits also hold 5, 6 and 7, which unpack to
−3, −4 and −5. The standard does not check for those here, and neither does
this step: a malformed private key is its holder's problem, and a signature's
z is checked by size afterwards.

${SHARED}`,
  params: new Map([
    ["coeffBytes", "How many bytes each outgoing coefficient occupies. 4."],
    [
      "littleEndian",
      "Byte order within one OUTGOING coefficient. The packed input's bit order is fixed.",
    ],
  ]),
  references: [
    "FIPS 204 Algorithm 19 — BitUnpack",
    "FIPS 204 Algorithm 13 — BytesToBits",
    "FIPS 204 Algorithms 25 and 27 — skDecode and sigDecode, its callers",
  ],
};
