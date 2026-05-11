/**
 * Inverse Speck round function — undoes one forward `speck.round@1` step.
 *
 * The forward round does:
 *     x' ← (ROR(x, alpha) + y) ⊕ k_i
 *     y' ← ROL(y, beta) ⊕ x'
 *
 * Inverting backwards (recover y, then x):
 *     y  ← ROR(y' ⊕ x', beta)
 *     x  ← ROL((x' ⊕ k_i) - y, alpha)        (subtraction mod 2^n)
 *
 * Reads the round-key word from `aux[roundKeyAux]`. The decrypt spec
 * orders its leaves so the round keys are consumed in REVERSE
 * (`roundKey.21` first, `roundKey.0` last) — i.e., the same forward
 * key-schedule runs and only the leaf ordering of the inverse cipher's
 * spec encodes the reversal. This mirrors the AES decrypt pattern where
 * `aes.key-expansion@1` is shared verbatim and the spec leaves encode
 * the reverse-order consumption.
 */

import type { BytesState, Json, StepDocumentation, StepExecutor } from "../core/types";
import {
  type SpeckByteOrder,
  decodeBlock,
  decodeWord,
  encodeBlock,
  readByteOrder,
} from "./speck-word-codec";

export const speckRoundInverse: StepExecutor = (state, params, ctx) => {
  if (state.shape !== "bytes") {
    throw new Error("speck.round-inverse expects bytes state");
  }
  const p = readParams(params);
  const expectedBytes = 2 * (p.wordBits / 8);
  if (state.bytes.length !== expectedBytes) {
    throw new Error(
      `speck.round-inverse: block must be ${expectedBytes} bytes for wordBits=${p.wordBits}; got ${state.bytes.length}`,
    );
  }

  const rkBytes = ctx.aux.get(p.roundKeyAux);
  if (!(rkBytes instanceof Uint8Array) || rkBytes.length !== p.wordBits / 8) {
    throw new Error(
      `speck.round-inverse: aux '${p.roundKeyAux}' must be a ${p.wordBits / 8}-byte Uint8Array`,
    );
  }
  const k = decodeWord(rkBytes, 0, p.wordBits, p.byteOrder);

  const [xNew, yNew] = decodeBlock(state.bytes, p.wordBits, p.byteOrder);
  const mask = wordMask(p.wordBits);
  // y = ROR(y' XOR x', beta)
  const y = ror(yNew ^ xNew, p.beta, p.wordBits);
  // x = ROL((x' XOR k) - y mod 2^n, alpha). The `+ mask + 1` keeps the
  // subtraction non-negative before masking, since JS `-` can return
  // negative numbers but `&` does the right thing on int32 — we mask to
  // wordBits explicitly to avoid sign-extension surprises.
  const sub = ((xNew ^ k) - y + mask + 1) & mask;
  const x = rol(sub, p.alpha, p.wordBits);

  const out = encodeBlock(p.wordBits, p.byteOrder, x, y);
  const next: BytesState = { shape: "bytes", bytes: out };
  return { state: next, auxReads: [p.roundKeyAux] };
};

// ─── Documentation ────────────────────────────────────────────────────────

export const speckRoundInverseDoc: StepDocumentation = {
  name: "Speck Round (Inverse)",
  summary: "Undo one Speck forward round: y ← ROR(y′ ⊕ x′, β); x ← ROL((x′ ⊕ k) − y, α).",
  detail: `## Inverse Speck Round

The forward Speck round chains two assignments. To invert, we run them
back-to-front: recover \`y\` from \`y'\` and \`x'\`, then recover \`x\`.

Forward:
\`\`\`
x'  =  (ROR(x, alpha) + y)  XOR  k_i
y'  =  ROL(y, beta)  XOR  x'
\`\`\`

Inverse:
\`\`\`
y   =  ROR(y'  XOR  x', beta)
x   =  ROL((x'  XOR  k_i)  −  y, alpha)
\`\`\`

The subtraction is **modular** in \`2^n\` — same as the forward addition
just reversed. In code we keep values masked to \`wordBits\` and add
\`2^n\` before subtracting so the JavaScript arithmetic doesn't dip
negative; the trailing mask normalises the result.

**Round-key order.** The inverse cipher consumes round keys in
**reverse**: \`k_{rounds-1}, k_{rounds-2}, …, k_0\`. The forward key
schedule still runs unchanged; only the spec's leaf ordering encodes the
reversal. That keeps the schedule itself reusable across encrypt and
decrypt — the same pattern AES uses, where the forward S-box drives key
expansion even on the decrypt path.`,
  params: new Map([
    [
      "roundKeyAux",
      "Name of the aux entry holding this inverse round's key word. The decrypt spec wires roundKey.21 to leaf 1, roundKey.0 to the final leaf.",
    ],
    [
      "alpha",
      "Right-rotation amount on x in the forward round. Same value as the forward step uses.",
    ],
    [
      "beta",
      "Left-rotation amount on y in the forward round. Same value as the forward step uses.",
    ],
    ["wordBits", "Word width in bits. Speck32/64 = 16."],
    [
      "byteOrder",
      "Byte serialization convention: 'be-paper' or 'le-nsa'. Must match the forward step.",
    ],
  ]),
  references: [
    "Beaulieu et al. 2013 §3 (the inverse round is the natural reversal of the forward equations; not stated explicitly but trivially derived)",
  ],
};

// ─── Helpers ──────────────────────────────────────────────────────────────

const wordMask = (bits: number): number => (bits === 32 ? 0xffffffff : (1 << bits) - 1);

const rol = (x: number, n: number, bits: number): number => {
  const mask = wordMask(bits);
  const xm = x & mask;
  return ((xm << n) | (xm >>> (bits - n))) & mask;
};

const ror = (x: number, n: number, bits: number): number => {
  const mask = wordMask(bits);
  const xm = x & mask;
  return ((xm >>> n) | (xm << (bits - n))) & mask;
};

type Params = {
  roundKeyAux: string;
  alpha: number;
  beta: number;
  wordBits: number;
  byteOrder: SpeckByteOrder;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("speck.round-inverse requires object params");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.roundKeyAux !== "string")
    throw new Error("speck.round-inverse: roundKeyAux must be string");
  for (const k of ["alpha", "beta", "wordBits"] as const) {
    const v = p[k];
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1) {
      throw new Error(`speck.round-inverse: ${k} must be a positive integer`);
    }
  }
  return {
    roundKeyAux: p.roundKeyAux,
    alpha: p.alpha as number,
    beta: p.beta as number,
    wordBits: p.wordBits as number,
    byteOrder: readByteOrder(params, "speck.round-inverse"),
  };
};
