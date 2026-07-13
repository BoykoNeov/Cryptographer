/**
 * keccak.pad — SHA-3 / Keccak sponge padding (pad10*1 + domain separation),
 * FIPS 202 §5.1 + §B.2, 2026-07-13.
 *
 * **What it does.** Extends the message to a whole number of `rate`-byte blocks
 * using Keccak's "pad10*1" rule, prefixed by a **domain-separation** suffix that
 * distinguishes the FIPS 202 functions from each other:
 *   1. append the `domainByte` (which already carries the padding's leading
 *      1-bit in its low bits): `0x06` for SHA3-*, `0x1F` for SHAKE*;
 *   2. append zero bytes until one byte short of a rate multiple;
 *   3. OR `0x80` into the very last byte (the padding's trailing 1-bit).
 *
 * The number of appended bytes is `rate − (len mod rate)`, always in `[1,
 * rate]` — so a message whose length is already a multiple of `rate` gains a
 * FULL extra all-padding block. When only ONE byte is added (i.e. `len ≡ −1 mod
 * rate`), steps 1 and 3 land on the SAME byte and merge to `domainByte | 0x80`
 * (`0x86` for SHA-3) — the classic Keccak pad edge case.
 *
 * **Why not `pad-with-byte@1` / `append-be64-length@1`.** SHA-256's
 * Merkle–Damgård padding appends a `0x80` sentinel THEN a big-endian length
 * suffix. The sponge does NEITHER: there is no length field, and the sentinel
 * bits are the domain byte + a trailing `0x80` with the merge behaviour above.
 * A dedicated step keeps the two padding schemes honestly distinct.
 *
 * **Authoring conventions.** Port-native: `kind:"ported"`, omit `legacy`,
 * `meta`, `shapeContract`. Both ports polymorphic `layout:"raw"` — the input is
 * a message of any length and the output length depends on it, so neither
 * byteLength is known at spec time (the same posture as SHA-256's padding
 * leaves).
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly rate: number;
  readonly domainByte: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("keccak.pad: params must be an object");
  }
  const p = params as Record<string, Json>;
  const rate = p.rate;
  if (typeof rate !== "number" || !Number.isInteger(rate) || rate < 1) {
    throw new Error(
      `keccak.pad: params.rate must be a positive integer (bytes), got ${String(rate)}`,
    );
  }
  const domainByte = p.domainByte;
  if (
    typeof domainByte !== "number" ||
    !Number.isInteger(domainByte) ||
    domainByte < 0 ||
    domainByte > 0xff
  ) {
    throw new Error(
      `keccak.pad: params.domainByte must be a byte in [0, 255] (0x06 SHA-3, 0x1F SHAKE), got ${String(domainByte)}`,
    );
  }
  return { rate, domainByte };
};

// ─── Port contract + executor ─────────────────────────────────────────────

export const keccakPadPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const keccakPad: PortedExecutor = (inputs, params, _ctx) => {
  const { rate, domainByte } = readParams(params);
  const msg = inputs.get("input");
  if (msg === undefined) {
    throw new Error("keccak.pad: missing required input port 'input'");
  }
  // pad length is always in [1, rate]; a message already a multiple of rate
  // gains a full extra all-padding block (FIPS 202 pad10*1).
  const padLen = rate - (msg.length % rate);
  const out = new Uint8Array(msg.length + padLen);
  out.set(msg, 0);
  out[msg.length] = domainByte; // domain suffix + padding's leading 1-bit
  out[out.length - 1] = (out[out.length - 1] as number) ^ 0x80; // trailing 1-bit
  // ^ When padLen === 1 the two writes hit the same byte, merging to
  // domainByte ^ 0x80 (= 0x86 for SHA-3's 0x06) — the intended edge case.
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const keccakPadDoc: StepDocumentation = {
  name: "Keccak pad (pad10*1)",
  summary:
    "Pads the message to a whole number of sponge blocks with a domain byte and Keccak's 10*1 rule.",
  detail: `# Keccak pad (pad10*1)

Extends the message so its length becomes a whole number of \`rate\`-byte
sponge blocks, and tags it with a **domain-separation** byte so the different
SHA-3 functions can never collide.

## The rule

1. Append the **domain byte** (\`0x06\` for SHA3-224/256/384/512, \`0x1F\` for
   SHAKE128/256). Its low bits also carry the leading \`1\` of the padding.
2. Append \`0\` bytes until the total is one byte short of a \`rate\` multiple.
3. Set the top bit (\`| 0x80\`) of the **last** byte.

The amount added is \`rate − (length mod rate)\`, which is always between 1 and
\`rate\`. So a message that is *already* a multiple of \`rate\` still gains one
full extra block of padding — the sponge always absorbs at least one pad byte.

## The merge case

When exactly one byte is added (the message is one byte short of a block),
steps 1 and 3 write the **same** byte, so it becomes \`domain | 0x80\` — for
SHA-3 that is \`0x06 | 0x80 = 0x86\`. This single-byte pad is a common source of
implementation bugs; it is exercised directly by the tests.

## Why the domain byte

Absorbing a fixed suffix that differs per function means SHA3-256 and SHAKE256
(and a raw Keccak sponge) can never produce the same absorbed input for the same
message — a cheap, robust form of domain separation (FIPS 202 §B.2).`,
  params: new Map([
    [
      "rate",
      "Sponge rate in bytes — 136 for SHA3-256 (1088 bits). The block size the sponge absorbs.",
    ],
    ["domainByte", "Domain-separation + leading pad bit: 0x06 for SHA-3, 0x1F for SHAKE."],
  ]),
  references: ["FIPS 202 §5.1 (pad10*1)", "FIPS 202 §B.2 (domain separation)"],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
