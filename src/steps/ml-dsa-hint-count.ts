/**
 * ml-dsa.hint-count — how many hint bits are set, and is that within ω?
 *
 * Two input ports: `h` (the hint vector, every coefficient 0 or 1) and `omega`
 * (ω, big-endian, any width). Two output ports:
 *
 * - `output` — one byte, `1` if the number of ones is `≤ ω`, else `0`;
 * - `count` — that number, two bytes big-endian.
 *
 * ## `≤`, unlike the norm checks
 *
 * FIPS 204 Algorithm 7 rejects a candidate when "the number of 1's in h is
 * greater than ω". So exactly ω ones is ACCEPTED — the opposite edge
 * convention from `zq-inf-norm-below@1`'s strict `<`. The reason is not deep:
 * ω is the number of index slots the signature has room for
 * (`ml-dsa.hint-pack@1` writes the hint into exactly ω bytes), so ω ones is
 * full, not over. Both edges are pinned by ±1 tests.
 *
 * ## Why ω is on a port
 *
 * The same ω fixes the size of the packed hint. On a wire, one constant feeds
 * this check, the packer and the unpacker, so editing it cannot leave them
 * disagreeing about how long a signature is.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. `output` is one
 * byte and `count` two.
 */

import { coeffNumbers, countBytes, flagByte } from "../core/ml-dsa-arith";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { readScalarPort, readZqVecParams, requireZqPort, zqElementCount } from "../core/zq-vector";

const STEP = "ml-dsa.hint-count";

export const mlDsaHintCountPortContract: PortContract = {
  inputs: new Map([
    ["h", { layout: "raw" }],
    ["omega", { layout: "raw" }],
  ]),
  outputs: new Map([
    ["output", { layout: "raw", byteLength: 1 }],
    ["count", { layout: "raw", byteLength: 2 }],
  ]),
};

export const mlDsaHintCount: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const hBytes = requireZqPort(inputs, "h", STEP);
  zqElementCount(hBytes, p, "h", STEP);
  const omega = readScalarPort(inputs, "omega", STEP);
  const h = coeffNumbers(hBytes, p);
  let count = 0;
  h.forEach((bit, i) => {
    if (bit > 1) {
      throw new Error(`${STEP}: hint coefficient ${i} is ${bit}; a hint is one bit, 0 or 1`);
    }
    count += bit;
  });
  return new Map([
    ["output", flagByte(count <= omega)],
    ["count", countBytes(count)],
  ]);
};

export const mlDsaHintCountDoc: StepDocumentation = {
  name: "Count hint bits (at most ω)",
  summary:
    "Counts how many coefficients the hint corrects, and reports whether that fits in the ω slots a signature has room for.",
  detail: `# Count hint bits

Counts the ones in a hint vector and checks the total against ω:

\`\`\`
count  = number of i with h[i] = 1
output = 1  if count ≤ ω,  else 0
\`\`\`

## Why there is a limit

A signature stores its hint compactly, as a list of *positions* — which
coefficients need correcting — rather than a bit for every coefficient. It has
room for exactly **ω** positions (80 in ML-DSA-44). A candidate that needs more
corrections than that cannot be written down, so it is discarded and the signer
tries again. This is one of the four checks in the signing loop.

## At most, not fewer than

Exactly ω ones is fine: that fills every slot. Only ω + 1 or more is rejected.
That is the opposite edge from the "is every coefficient small?" checks, which
reject a value sitting exactly on their bound. Mixing the two up changes which
candidates are accepted, and therefore every byte of the signature that comes
out.

## ω is wired, not set here

ω arrives on a port, so one constant drives this check and the hint packer and
unpacker together. Change it and the signature's length changes with it.`,
  params: new Map([
    ["coeffBytes", "How many bytes each hint coefficient occupies. 4 for ML-DSA."],
    ["littleEndian", "Byte order within one hint coefficient. False (big-endian)."],
  ]),
  references: [
    "FIPS 204 Algorithm 7 (ML-DSA.Sign_internal) — reject if the number of 1's in h exceeds ω",
    "FIPS 204 Algorithm 20 — HintBitPack, which has room for ω positions",
  ],
};
