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
 * **Phase 1 = FLAT; Phase 2 = grouped.** Phase 1 placed every key-gen leaf as
 * a top-level sibling of the ladder rungs, so `n`/`φ`/`d` fanned out
 * PORT-TO-PORT among same-scope siblings (no `aux`, no group-scope crossing).
 * Phase 2 wraps the key-gen leaves in a collapsible **"Key Generation"**
 * group for pedagogical structure — which re-introduces the group-scope wall:
 * a group walks its children in an isolated scope, so a rung OUTSIDE the group
 * can no longer reference a port INSIDE it. The group's `rsa.publish-key-params@1`
 * tail mirrors the computed `n`/`e`/`d` into the global `aux` map (the one
 * channel that crosses a group boundary), and the ladder reads them back via
 * top-level `aux-load-bytes@1` loaders. This is the same B-minimal
 * publish-to-aux export the four decomposed key schedules use; the
 * key-generation math stays VISIBLE as port-native frames above the tail.
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

/** Aux-key prefix the "Key Generation" group's publish tail writes under, and
 *  the top-level exponentiation-ladder loaders read back: `rsa.n` (modulus,
 *  every rung), `rsa.e` (encrypt exponent), `rsa.d` (decrypt exponent). */
export const RSA_AUX_PREFIX = "rsa";

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
 * Build an RSA spec for one direction at working width `W`.
 *
 * The key-generation leaves are identical in both directions (so the learner
 * sees `n`, `φ`, `d` derived either way) and are wrapped in a collapsible
 * "Key Generation" group whose `rsa.publish-key-params@1` tail exports the
 * computed parameters into `aux`. The only direction-dependent difference is
 * which exponent the ladder loads back across the group wall — the public `e`
 * (`aux["rsa.e"]`) on encrypt, the derived private `d` (`aux["rsa.d"]`) on
 * decrypt — plus the input semantics (message vs ciphertext, both arriving on
 * the `$input` source).
 */
export const buildRsaSpec = (
  direction: RsaDirection,
  W: number = RSA_WORKING_WIDTH,
): CipherSpec => {
  const rungs = W * 8; // one ladder rung per modulus-width bit (MSB→LSB)
  // The ladder's exponent crosses the group wall via aux: encrypt loads the
  // public `e`, decrypt the derived private `d`. Both wire to `load-exp`.
  const exponentAuxKey = direction === "encrypt" ? `${RSA_AUX_PREFIX}.e` : `${RSA_AUX_PREFIX}.d`;

  // ── Key generation (collapsible group) ───────────────────────────────────
  // p, q, e → n = p·q, φ = (p−1)(q−1), d = e⁻¹ mod φ — each a VISIBLE
  // port-native frame, in dependency order. The `rsa.publish-key-params@1`
  // tail mirrors n/e/d into aux["rsa.*"] so the exponentiation ladder (outside
  // this group, where ports can't reach in) reads them back. Identical for
  // both directions — the learner watches the same derivation either way.
  const keyGenChildren: StepNode[] = [
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
    // n = p · q  (the public modulus, published as `rsa.n` for every rung).
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
    // Publish tail: mirror n / e / d into aux["rsa.n" | "rsa.e" | "rsa.d"] so
    // the ladder can read them across the group boundary (`aux` is the only
    // cross-scope channel). This is also where RSA's two keys become concrete:
    // public (n, e) and private (n, d).
    {
      kind: "step",
      id: "publish-key",
      type: "rsa.publish-key-params@1",
      params: { outputPrefix: RSA_AUX_PREFIX },
      portInputs: {
        n: port("n", "output"),
        e: port("load-e", "output"),
        d: port("d", "output"),
      },
    },
  ];

  const keyGenGroup: StepNode = {
    kind: "group",
    id: "key-generation",
    label: "Key Generation",
    // Default-EXPANDED (no `defaultCollapsed`): key generation is RSA's
    // headline feature — the user explicitly chose to trace it — so collapsing
    // it by default would hide what the flat Phase-1 spec showed. The group
    // adds a collapse affordance for learners who want to focus on the ladder;
    // it does not hide the derivation on first render.
    children: keyGenChildren,
  };

  // ── Ladder loaders + accumulator seed (top-level) ────────────────────────
  // The group published n / e / d into aux; these top-level loaders bring the
  // modulus and the direction's exponent back onto ports the rungs can wire
  // to. (The factor — the message m / ciphertext c — still arrives on the
  // `$input` source, untouched by the regrouping.)
  const loadN: StepNode = {
    kind: "step",
    id: "load-n",
    type: "aux-load-bytes@1",
    params: { auxName: `${RSA_AUX_PREFIX}.n`, byteLength: W },
  };
  const loadExp: StepNode = {
    kind: "step",
    id: "load-exp",
    type: "aux-load-bytes@1",
    params: { auxName: exponentAuxKey, byteLength: W },
  };
  // result₀ = 1 — the square-and-multiply accumulator seed (the ladder's, not
  // key material, so it lives at top level next to the rungs it seeds).
  const resultSeed: StepNode = {
    kind: "step",
    id: "result-seed",
    type: "constant-load@1",
    params: { bytes: beConst(1, W) },
  };

  // ── Exponentiation ladder (left-to-right binary exponentiation) ──────────
  // result = 1; for each bit of the exponent MSB→LSB: result = result² mod n;
  // if the bit is set: result = result · base mod n  (base = message m / c).
  const ladder: StepNode[] = [];
  for (let j = 0; j < rungs; j++) {
    const bitIndex = rungs - 1 - j; // rung 0 tests the MSB
    const prevResult: PortBinding =
      j === 0 ? port("result-seed", "output") : port(`mult-${j - 1}`, "output");
    // Square: result² mod n — both factors wired to the same upstream port,
    // the modulus to the published `rsa.n` loader.
    ladder.push({
      kind: "step",
      id: `square-${j}`,
      type: "mod-mul@1",
      params: {},
      portInputs: {
        a: prevResult,
        b: prevResult,
        modulus: port("load-n", "output"),
      },
    });
    // Conditional multiply by the base (message/ciphertext) when bit set; the
    // exponent comes from the published `rsa.e`/`rsa.d` loader.
    ladder.push({
      kind: "step",
      id: `mult-${j}`,
      type: "cond-mod-mul@1",
      params: { bitIndex },
      portInputs: {
        base: port(`square-${j}`, "output"),
        factor: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
        exponent: port("load-exp", "output"),
        modulus: port("load-n", "output"),
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
    // The Key-Generation group runs first (publishing n/e/d into aux), then
    // the loaders read them back, then the ladder consumes them.
    steps: [keyGenGroup, loadN, loadExp, resultSeed, ...ladder],
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
