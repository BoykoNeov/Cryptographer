/**
 * RSA — textbook public-key cipher with traced key generation.
 *
 * The project's first **public-key / asymmetric** primitive. Plan:
 * `docs/plans/shimmying-booping-moth.md`. Two halves are made visible:
 *
 *   1. **Key generation** — from the editable constants `p, q, e` the spec
 *      derives `n = p·q`, `φ(n) = (p-1)(q-1)`, and the private exponent
 *      `d = e⁻¹ mod φ(n)`, each a visible trace frame (`mul`/`sub`/
 *      `mod-inverse`). The modular inverse is a v1 ORACLE (one frame); a
 *      later phase decomposes the extended-Euclid loop.
 *   2. **Square-and-multiply exponentiation** — `c = mᵉ mod n` (encrypt) /
 *      `m = cᵈ mod n` (decrypt) as an unrolled ladder of `W·8` rungs, each a
 *      `mod-mul@1` square followed by a `cond-mod-mul@1` conditional multiply
 *      that reads its exponent bit AT RUNTIME — so editing the exponent
 *      (`e`, or `p,q` → `d`) re-runs live.
 *
 * **Phase 1 = FLAT (no groups).** Every key-gen leaf is a top-level sibling
 * of the ladder rungs, so `n`/`φ`/`d` fan out PORT-TO-PORT to the rungs (a
 * node's output is visible to any later sibling in the same walk scope). No
 * `aux` broadcast, no group-scope crossing, no hybrid steps — just the five
 * pure primitives (+ the existing `aux-load-bytes@1` / `constant-load@1`
 * sources). Phase 2 wraps key-gen in a collapsible group, which re-introduces
 * the scope wall and needs a publish-to-aux export; see the plan.
 *
 * **Working width `W`.** Every integer (p, q, e, n, φ, d, the accumulator)
 * is a uniform `W`-byte big-endian value. `W = 2` (16-bit) is the default:
 * it holds the classic n=3233 example (and any n < 65536), keeping the
 * ladder at 16 rungs for a legible trace. `W` is a builder argument — widen
 * + rebuild for larger numbers (the `bigint`-internal primitives generalize).
 *
 * **Math is real RSA**, verified against a Python oracle in
 * `tests/rsa-vectors.test.ts` (`feedback_crypto_verification`): for the
 * default `p=61, q=53, e=17`, `n=3233`, `φ=3120`, `d=2753`, and
 * `pow(65,17,3233)=2790` round-trips back to 65.
 */

import type { CipherSpec, PortBinding, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";

// ─── Tunables ─────────────────────────────────────────────────────────────

/** Uniform working width in bytes for every RSA integer. 2 ⇒ n < 65536, a
 *  16-rung ladder — sized for the textbook n≈3233 example's legibility. */
export const RSA_WORKING_WIDTH = 2;

/** Default key material (the classic Wikipedia textbook RSA example). */
export const RSA_DEFAULT_P = 61;
export const RSA_DEFAULT_Q = 53;
export const RSA_DEFAULT_E = 17;
/** Default message m = 65 (< n = 3233). Encrypts to c = 2790. */
export const RSA_DEFAULT_MESSAGE = 65;

// ─── Byte helpers ─────────────────────────────────────────────────────────

/** Big-endian byte array (length `width`) for a small non-negative integer. */
const beBytes = (value: number, width: number): Uint8Array => {
  const out = new Uint8Array(width);
  let v = value;
  for (let i = width - 1; i >= 0; i--) {
    out[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  return out;
};

/** Same as `beBytes` but as a plain `number[]` for `constant-load@1` params. */
const beConst = (value: number, width: number): number[] => Array.from(beBytes(value, width));

const port = (node: string, p: string): PortBinding => ({ node, port: p });

// ─── Spec builder ─────────────────────────────────────────────────────────

export type RsaDirection = "encrypt" | "decrypt";

/**
 * Build a flat RSA spec for one direction at working width `W`.
 *
 * The key-generation leaves are identical in both directions (so the learner
 * sees `n`, `φ`, `d` derived either way); the only differences are which
 * exponent the ladder consumes — the public `e` on encrypt, the derived
 * private `d` on decrypt — and the input semantics (message vs ciphertext,
 * both arriving on the `$input` source).
 */
export const buildRsaSpec = (
  direction: RsaDirection,
  W: number = RSA_WORKING_WIDTH,
): CipherSpec => {
  const rungs = W * 8; // one ladder rung per modulus-width bit (MSB→LSB)
  const exponentSource: PortBinding =
    direction === "encrypt" ? port("load-e", "output") : port("d", "output");

  const keyGen: StepNode[] = [
    // Read the editable constants p, q, e (materialized into aux by the
    // runtime from `cipherConstants`) onto ports.
    {
      kind: "step",
      id: "load-p",
      type: "aux-load-bytes@1",
      params: { auxName: "p", byteLength: W },
    },
    {
      kind: "step",
      id: "load-q",
      type: "aux-load-bytes@1",
      params: { auxName: "q", byteLength: W },
    },
    {
      kind: "step",
      id: "load-e",
      type: "aux-load-bytes@1",
      params: { auxName: "e", byteLength: W },
    },
    // The literal 1, for p−1 / q−1.
    { kind: "step", id: "one", type: "constant-load@1", params: { bytes: beConst(1, W) } },
    // n = p · q  (the public modulus, threaded to every rung as `modulus`).
    {
      kind: "step",
      id: "n",
      type: "mul@1",
      params: {},
      portInputs: { a: port("load-p", "output"), b: port("load-q", "output") },
    },
    // φ(n) = (p − 1)(q − 1).
    {
      kind: "step",
      id: "p-minus-1",
      type: "sub@1",
      params: {},
      portInputs: { a: port("load-p", "output"), b: port("one", "output") },
    },
    {
      kind: "step",
      id: "q-minus-1",
      type: "sub@1",
      params: {},
      portInputs: { a: port("load-q", "output"), b: port("one", "output") },
    },
    {
      kind: "step",
      id: "phi",
      type: "mul@1",
      params: {},
      portInputs: { a: port("p-minus-1", "output"), b: port("q-minus-1", "output") },
    },
    // d = e⁻¹ mod φ(n)  (the private exponent; the decrypt ladder's exponent).
    {
      kind: "step",
      id: "d",
      type: "mod-inverse@1",
      params: {},
      portInputs: { value: port("load-e", "output"), modulus: port("phi", "output") },
    },
    // result₀ = 1 — the square-and-multiply accumulator seed.
    { kind: "step", id: "result-seed", type: "constant-load@1", params: { bytes: beConst(1, W) } },
  ];

  // ── Exponentiation ladder (left-to-right binary exponentiation) ──────────
  // result = 1; for each bit of the exponent MSB→LSB: result = result² mod n;
  // if the bit is set: result = result · base mod n  (base = message m / c).
  const ladder: StepNode[] = [];
  for (let j = 0; j < rungs; j++) {
    const bitIndex = rungs - 1 - j; // rung 0 tests the MSB
    const prevResult: PortBinding =
      j === 0 ? port("result-seed", "output") : port(`mult-${j - 1}`, "output");
    // Square: result² mod n — both factors wired to the same upstream port.
    ladder.push({
      kind: "step",
      id: `square-${j}`,
      type: "mod-mul@1",
      params: {},
      portInputs: {
        a: prevResult,
        b: prevResult,
        modulus: port("n", "output"),
      },
    });
    // Conditional multiply by the base (message/ciphertext) when bit set.
    ladder.push({
      kind: "step",
      id: `mult-${j}`,
      type: "cond-mod-mul@1",
      params: { bitIndex },
      portInputs: {
        base: port(`square-${j}`, "output"),
        factor: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
        exponent: exponentSource,
        modulus: port("n", "output"),
      },
    });
  }

  return {
    id: direction === "encrypt" ? "rsa@1" : "rsa-decrypt@1",
    name: "RSA (textbook)",
    stateShape: "bytes",
    inputs: {
      // The message m (encrypt) / ciphertext c (decrypt) arrives on the
      // `$input` source as `W` big-endian bytes; the ladder's `factor` reads
      // it. No symmetric key — the public/private key material is the editable
      // `p, q, e` constants below.
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    steps: [...keyGen, ...ladder],
    cipherConstants: {
      p: beBytes(RSA_DEFAULT_P, W),
      q: beBytes(RSA_DEFAULT_Q, W),
      e: beBytes(RSA_DEFAULT_E, W),
    },
    // The cipher's result is the final rung's accumulator.
    outputFrom: port(`mult-${rungs - 1}`, "output"),
  };
};

export const rsaEncryptSpec: CipherSpec = buildRsaSpec("encrypt");
export const rsaDecryptSpec: CipherSpec = buildRsaSpec("decrypt");
