/**
 * ml-dsa.format-message — prefix the message with its domain separator and
 * context string: `M′ = 0 ‖ |ctx| ‖ ctx ‖ M` (FIPS 204 Algorithms 2 and 3,
 * the external `ML-DSA.Sign` / `ML-DSA.Verify`).
 *
 * One input port `input` (the message M), one output port `output` (M′,
 * `2 + |ctx|` bytes longer). One param, `context`: the context string, as a
 * list of byte values, empty by default and at most 255 bytes.
 *
 * ## Why this tiny step exists
 *
 * The internal signing algorithm signs whatever bytes it is handed. The
 * standard's EXTERNAL interface never hands it the raw message: it prepends a
 * zero byte (meaning "pure ML-DSA", as opposed to the pre-hashed HashML-DSA,
 * which uses 1), the context string's length, and the context string. Miss
 * this prefix and every signature is valid under this app and rejected by every
 * other implementation — Node's `crypto.verify` included — because the two are
 * signing different bytes. It is the single most common interoperability bug
 * with ML-DSA, which is why it is a step on the canvas rather than a line
 * inside the signer.
 *
 * ## What a context string is for
 *
 * An application can bind its signatures to a purpose — "firmware-update",
 * "login" — so that a signature made for one cannot be replayed as the other,
 * even under the same key. The empty context is the default and what most
 * callers use.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

const STEP = "ml-dsa.format-message";

/** The context bytes, validated. An absent param is the empty context. */
export const readContext = (params: Json): Uint8Array => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error(`${STEP}: params must be an object`);
  }
  const ctx = (params as Record<string, Json>).context;
  if (ctx === undefined) return new Uint8Array(0);
  if (!Array.isArray(ctx) || ctx.length > 255) {
    throw new Error(`${STEP}: params.context must be a list of at most 255 byte values`);
  }
  return Uint8Array.from(ctx, (b, i) => {
    if (typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 255) {
      throw new Error(`${STEP}: params.context[${i}] must be an integer in 0..255`);
    }
    return b;
  });
};

export const mlDsaFormatMessagePortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const mlDsaFormatMessage: PortedExecutor = (inputs, params, _ctx) => {
  const context = readContext(params);
  const message = inputs.get("input");
  if (message === undefined) throw new Error(`${STEP}: missing required input port "input"`);
  const out = new Uint8Array(2 + context.length + message.length);
  // out[0] = 0: pure ML-DSA. HashML-DSA would put 1 here.
  out[1] = context.length;
  out.set(context, 2);
  out.set(message, 2 + context.length);
  return new Map([["output", out]]);
};

export const mlDsaFormatMessageDoc: StepDocumentation = {
  name: "Format the message (context prefix)",
  summary:
    "Puts a zero byte, the context string's length and the context string in front of the message — the bytes ML-DSA actually signs.",
  detail: `# Format the message

ML-DSA never signs the raw message. It signs

\`\`\`
M′ = 0 ‖ length(ctx) ‖ ctx ‖ M
\`\`\`

- **0** — one byte meaning "the message itself is being signed". The
  pre-hashed variant, HashML-DSA, puts a 1 here instead, so the two can never
  be confused.
- **length(ctx)** — one byte, 0 to 255.
- **ctx** — the context string, empty by default.
- **M** — the message.

## Why it matters so much

Leave this step out and signing still works — every signature you make
verifies under this app. But every **other** implementation adds the prefix
before checking, so they are all checking different bytes from the ones that
were signed, and they all say "invalid". It is the most common way to make
ML-DSA signatures nobody else accepts.

## What the context string is for

It lets an application say what a signature is **for**. A signature made with
context "login" will not verify with context "payment", even under the same
key, so one cannot be replayed as the other. Most uses leave it empty.`,
  params: new Map([
    [
      "context",
      "The context string as a list of byte values, empty by default, at most 255 bytes. The signer and the verifier must use the same one.",
    ],
  ]),
  references: [
    "FIPS 204 Algorithm 2 — ML-DSA.Sign (forms M′ before signing)",
    "FIPS 204 Algorithm 3 — ML-DSA.Verify (forms the same M′ before checking)",
  ],
};
