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

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { eeaMaxIterations } from "../steps/eea-step";

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

// ─── narrationOverride docs (RSA Phase 2) ───────────────────────────────────
// Per-leaf friendly names + prose for the inspector, attached via the spec
// leaf's `narrationOverride` field (the registry doc is the generic primitive's
// — `mul@1` is "Multiply", but THIS `mul` leaf is "Modulus n = p·q"). Same
// idiom as the four key-schedule builders: shared static docs for the leaves
// that say the same thing every time, small functions for the ladder rungs that
// bake in the rung number / exponent-bit index (both known at spec-build time —
// only whether the bit is 0 or 1 is runtime-dependent, which is the dynamic
// `src/ui/narration/` registry's job, out of scope for a static override).

const NARR_LOAD_P: StepDocumentation = {
  name: "Load prime p",
  summary: "Read the first secret prime p from the editable key constants.",
  detail: `## Load prime p

\`p\` is one of the two secret primes whose product is the public modulus
\`n = p·q\`. It is read from the editable \`cipherConstants\` (default 61 in the
textbook example) — edit it and the whole derivation (n, φ, d) re-runs live.

RSA's security rests on the difficulty of recovering \`p\` and \`q\` from the
public \`n\`: multiplying two primes is easy, factoring their product is not.`,
  references: ["Rivest, Shamir, Adleman 1978"],
};

const NARR_LOAD_Q: StepDocumentation = {
  name: "Load prime q",
  summary: "Read the second secret prime q from the editable key constants.",
  detail: `## Load prime q

\`q\` is the second secret prime (default 53). Together with \`p\` it forms the
modulus \`n = p·q\` and Euler's totient \`φ(n) = (p−1)(q−1)\`. Both primes are
secret; only their product \`n\` is published.`,
  references: ["Rivest, Shamir, Adleman 1978"],
};

const NARR_LOAD_E: StepDocumentation = {
  name: "Load public exponent e",
  summary: "Read the public exponent e — half of the public key (n, e).",
  detail: `## Load public exponent e

\`e\` is the public encryption exponent (default 17; real keys commonly use
65537). It must be **coprime to φ(n)** — \`gcd(e, φ) = 1\` — so that the private
exponent \`d = e⁻¹ mod φ\` exists. Pick an \`e\` sharing a factor with φ and the
modular-inverse step throws, which is the honest "that e is not a valid public
exponent."`,
  references: ["Rivest, Shamir, Adleman 1978"],
};

const NARR_ONE: StepDocumentation = {
  name: "Constant 1",
  summary: "The literal 1 used to form p − 1 and q − 1 for the totient.",
  detail: `## Constant 1

A literal \`1\`, subtracted from each prime to build Euler's totient
\`φ(n) = (p−1)(q−1)\`. Carried as a \`W\`-byte value so it lines up with the
prime widths at the subtraction's ports.`,
};

const NARR_N: StepDocumentation = {
  name: "Modulus n = p·q",
  summary: "Multiply the two primes to form the public modulus n.",
  detail: `## Modulus n = p·q

The **public modulus** — shared by both encryption (\`c = mᵉ mod n\`) and
decryption (\`m = cᵈ mod n\`), and threaded to every ladder rung as the
\`modulus\`. Its bit-length is the RSA "key size." For the textbook example
\`n = 61·53 = 3233\`.

Recovering the secret primes from \`n\` is the integer-factorization problem —
believed hard for large \`n\`, which is what keeps the private key private.`,
  references: ["Rivest, Shamir, Adleman 1978"],
};

const NARR_P_MINUS_1: StepDocumentation = {
  name: "p − 1",
  summary: "Subtract 1 from p — a factor of Euler's totient φ(n).",
  detail: `## p − 1

One factor of \`φ(n) = (p−1)(q−1)\`. Because \`n\`'s only prime factors are
\`p\` and \`q\`, Euler's totient factors this cleanly — that closed form is
exactly what makes \`d\` computable by someone who knows \`p\` and \`q\` (and
intractable for someone who knows only \`n\`).`,
};

const NARR_Q_MINUS_1: StepDocumentation = {
  name: "q − 1",
  summary: "Subtract 1 from q — the other factor of Euler's totient φ(n).",
  detail: `## q − 1

The second factor of \`φ(n) = (p−1)(q−1)\`. See "p − 1" — together these give
the totient that the private exponent is defined modulo.`,
};

const NARR_PHI: StepDocumentation = {
  name: "Totient φ(n) = (p−1)(q−1)",
  summary: "Euler's totient of n — the modulus for the private-exponent inverse.",
  detail: `## Euler's totient φ(n)

\`φ(n)\` counts the integers in \`[1, n]\` that are coprime to \`n\`. For a
product of two distinct primes it is \`(p−1)(q−1)\` (here \`60·52 = 3120\`).

The private exponent is defined **modulo φ(n)**: \`d = e⁻¹ mod φ(n)\`. Euler's
theorem (\`mᵠ⁽ⁿ⁾ ≡ 1 mod n\` for \`gcd(m, n) = 1\`) is what makes
\`(mᵉ)ᵈ ≡ m mod n\` — i.e. why decryption undoes encryption.

(The Carmichael function \`λ(n)\` also yields a valid, smaller \`d\`; this
textbook build uses \`φ\`, the classic presentation.)`,
  references: ["Rivest, Shamir, Adleman 1978"],
};

const NARR_D: StepDocumentation = {
  name: "Private exponent d = e⁻¹ mod φ(n)",
  summary: "Modular inverse of e modulo φ(n) — the private key exponent.",
  detail: `## Private exponent d

\`d\` is the unique value in \`[0, φ(n))\` with \`e·d ≡ 1 (mod φ(n))\` — the
**modular multiplicative inverse** of \`e\`. It exists if and only if
\`gcd(e, φ) = 1\` (the coprimality precondition), by Bézout's identity: the
extended Euclidean algorithm finds \`x, y\` with \`e·x + φ·y = gcd(e, φ)\`, and
when that gcd is 1, \`x mod φ\` is \`d\`. For the textbook key
\`d = 17⁻¹ mod 3120 = 2753\`.

The pair \`(n, d)\` is the **private key**. The traced extended-Euclid loop just
above derives it: a shrinking-remainder chain whose last non-zero remainder is
\`gcd(e, φ)\` and whose companion coefficient settles to \`d\`. This final step
reads that settled \`(gcd, coefficient)\` slot — emitting the coefficient as \`d\`
when the gcd is 1, and throwing otherwise (a non-coprime \`e\` has no inverse).`,
  references: [
    "Rivest, Shamir, Adleman 1978",
    "Knuth, TAOCP Vol. 2 §4.5.2 — the extended Euclidean algorithm",
  ],
};

/** Square rung `rungNum` of `total` (1-indexed for humans). */
const NARR_SQUARE = (rungNum: number, total: number): StepDocumentation => ({
  name: `Square (rung ${rungNum}/${total})`,
  summary: "result ← result² mod n — the unconditional squaring step of the rung.",
  detail: `## Square (rung ${rungNum} of ${total})

Left-to-right binary exponentiation processes the exponent one bit per rung,
**squaring the accumulator every rung**: \`result ← result² mod n\`. (Squaring
is a \`mod-mul\` with both factors wired to the same upstream port.) Reducing
mod \`n\` each step keeps the accumulator bounded — this is what makes
exponentiating a huge exponent tractable.`,
  references: ["Knuth, TAOCP Vol. 2 §4.6.3 — evaluation of powers"],
});

/** Conditional multiply testing exponent bit `bitIndex` (the rung's fixed bit). */
const NARR_COND_MULT = (bitIndex: number): StepDocumentation => ({
  name: `Multiply if exponent bit ${bitIndex} is set`,
  summary: `result ← result · base mod n when exponent bit ${bitIndex} is 1, else carry forward.`,
  detail: `## Conditional multiply (exponent bit ${bitIndex})

The other half of the rung. It reads **bit ${bitIndex}** of the exponent AT
RUNTIME: if that bit is **1**, multiply the accumulator by the base (the message
\`m\` on encrypt, the ciphertext \`c\` on decrypt) mod \`n\`; if **0**, carry the
squared accumulator forward unchanged.

Because the bit is read live, editing the exponent (\`e\`, or \`p,q\` → \`d\`)
flips exactly which rungs multiply — and the trace re-runs. The 0-bit rungs are
honest identity frames: they show the squaring still happened, just no multiply.`,
  references: ["Knuth, TAOCP Vol. 2 §4.6.3 — evaluation of powers"],
});

// ── Extended-Euclid decomposition narration (RSA Phase 4) ───────────────────
// The `mod-inverse@1` oracle is decomposed into a traced loop: two coefficient
// seeds + `eeaMaxIterations(W)` `eea-step` rungs + the `eea-extract` tail (which
// carries NARR_D — it IS the private exponent). These name the seeds + per-rung
// frames. As with the ladder, only the iteration NUMBER is static (baked at
// build); whether a given rung is still doing real work or has hit the
// identity fixed-point is runtime, so it is left to the dynamic narration layer.

const NARR_EEA_T0: StepDocumentation = {
  name: "Coefficient seed t = 0",
  summary: "Initial Bézout coefficient t = 0 — seeds the extended-Euclid loop.",
  detail: `## Coefficient seed t = 0

The extended Euclidean algorithm tracks a Bézout coefficient alongside the
shrinking remainder. It starts as the pair \`(t, newT) = (0, 1)\`; this is the
\`t = 0\` seed. After the loop settles, \`t\` holds \`e⁻¹ mod φ\` = the private
exponent \`d\`.`,
  references: ["Knuth, TAOCP Vol. 2 §4.5.2 — the extended Euclidean algorithm"],
};

const NARR_EEA_NEWT0: StepDocumentation = {
  name: "Coefficient seed newT = 1",
  summary: "Initial companion coefficient newT = 1 — the other half of the seed pair.",
  detail: `## Coefficient seed newT = 1

The companion of the \`t = 0\` seed: the Bézout coefficient pair starts as
\`(t, newT) = (0, 1)\`. Each \`eea-step\` shifts the pair by the step's quotient,
keeping it reduced modulo φ so every value stays a non-negative integer.`,
  references: ["Knuth, TAOCP Vol. 2 §4.5.2 — the extended Euclidean algorithm"],
};

/** Extended-Euclid iteration `iterNum` of `total` (1-indexed for humans). */
const NARR_EEA_STEP = (iterNum: number, total: number): StepDocumentation => ({
  name: `Extended-Euclid step ${iterNum}/${total}`,
  summary:
    "One division step: shift (r, newR, t, newT) by q = ⌊r/newR⌋. Identity once the remainder reaches 0.",
  detail: `## Extended-Euclid step ${iterNum} of ${total}

One iteration of the loop that derives \`d = e⁻¹ mod φ\`. The running state is the
four-tuple \`(r, newR, t, newT)\`, carried rung-to-rung. With \`q = ⌊r / newR⌋\`:

\`\`\`
r ← newR,    newR ← r − q·newR        (Euclid's remainder step)
t ← newT,    newT ← (t − q·newT) mod φ (the Bézout coefficient, reduced)
\`\`\`

The remainder sequence shrinks to \`gcd(e, φ)\`; the coefficient settles to \`d\`.
The chain is unrolled to a fixed worst-case length (Lamé's theorem bounds
Euclid's step count), so once the remainder hits 0 this and every later rung is
an honest identity frame — like the square-and-multiply ladder's 0-bit rungs.

**Coefficient shown reduced mod φ.** The raw Bézout coefficient is signed; to
keep every value a non-negative integer it is reduced into \`[0, φ)\`, so a
textbook's \`−183\` appears here as \`φ − 183\`. This is exact for the inverse.`,
  references: ["Knuth, TAOCP Vol. 2 §4.5.2 — the extended Euclidean algorithm"],
});

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

  // The publish tail exports exactly the key this direction's ladder consumes:
  // the public key {n, e} on encrypt, the private key {n, d} on decrypt. (Both
  // also export `n`, the shared modulus.) Building `portInputs` from the same
  // list keeps the ports and the published-aux-keys in lockstep.
  const publishedKeys: readonly string[] = direction === "encrypt" ? ["n", "e"] : ["n", "d"];
  const publishSource: Record<string, PortBinding> = {
    n: port("n", "output"),
    e: port("load-e", "output"),
    d: port("d", "output"),
  };
  const publishInputs: Record<string, PortBinding> = {};
  for (const k of publishedKeys) {
    const src = publishSource[k];
    if (src === undefined) throw new Error(`buildRsaSpec: no source for published key "${k}"`);
    publishInputs[k] = src;
  }

  // ── d = e⁻¹ mod φ as a TRACED extended-Euclid loop (RSA Phase 4) ──────────
  // The decomposition of the `mod-inverse@1` oracle: two coefficient seeds + a
  // chain of `eea-step@1` rungs (one division step per frame, the running
  // (r, newR, t, newT) tuple carried port-to-port) + the `eea-extract@1` tail
  // (id "d") that reads the settled (r=gcd, t=inverse) slot. Seeds: r₀ = φ (the
  // `phi` leaf), newR₀ = e (the `load-e` leaf), t₀ = 0, newT₀ = 1. The chain is
  // unrolled to `eeaMaxIterations(W)` rungs — Euclid's worst case (consecutive
  // Fibonacci numbers, Lamé's theorem) is bounded — and a rung whose remainder
  // has reached 0 is an honest identity frame. The coefficient is kept reduced
  // mod φ so every port value stays a non-negative big-endian integer (the
  // central design decision — see `src/steps/eea-step.ts`).
  const K = eeaMaxIterations(W);
  const eeaDecomposition: StepNode[] = [
    {
      kind: "step",
      id: "eea-t0",
      type: "constant-load@1",
      params: { bytes: beConst(0, W) },
      narrationOverride: NARR_EEA_T0,
    },
    {
      kind: "step",
      id: "eea-newt0",
      type: "constant-load@1",
      params: { bytes: beConst(1, W) },
      narrationOverride: NARR_EEA_NEWT0,
    },
  ];
  for (let i = 0; i < K; i++) {
    // Rung 0 reads the seeds; every later rung reads the previous rung's tuple.
    const prev = (slot: string): PortBinding => port(`eea-${i - 1}`, slot);
    eeaDecomposition.push({
      kind: "step",
      id: `eea-${i}`,
      type: "eea-step@1",
      params: {},
      portInputs: {
        r: i === 0 ? port("phi", "output") : prev("r"),
        newR: i === 0 ? port("load-e", "output") : prev("newR"),
        t: i === 0 ? port("eea-t0", "output") : prev("t"),
        newT: i === 0 ? port("eea-newt0", "output") : prev("newT"),
        modulus: port("phi", "output"),
      },
      narrationOverride: NARR_EEA_STEP(i + 1, K),
    });
  }
  // Terminal: read the LAST rung's settled (r, t) slot — r is gcd(e, φ), t is
  // the inverse. Throws when gcd ≠ 1 (e not coprime to φ — no valid inverse).
  // Keeps id "d" so the publish tail's `port("d", "output")` and the KAT's
  // `frameOutValue(trace, "d")` resolve unchanged.
  eeaDecomposition.push({
    kind: "step",
    id: "d",
    type: "eea-extract@1",
    params: {},
    portInputs: { gcd: port(`eea-${K - 1}`, "r"), value: port(`eea-${K - 1}`, "t") },
    narrationOverride: NARR_D,
  });

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
      narrationOverride: NARR_LOAD_P,
    },
    {
      kind: "step",
      id: "load-q",
      type: "aux-load-bytes@1",
      params: { auxName: "q", byteLength: W },
      narrationOverride: NARR_LOAD_Q,
    },
    {
      kind: "step",
      id: "load-e",
      type: "aux-load-bytes@1",
      params: { auxName: "e", byteLength: W },
      narrationOverride: NARR_LOAD_E,
    },
    // The literal 1, for p−1 / q−1.
    {
      kind: "step",
      id: "one",
      type: "constant-load@1",
      params: { bytes: beConst(1, W) },
      narrationOverride: NARR_ONE,
    },
    // n = p · q  (the public modulus, published as `rsa.n` for every rung).
    {
      kind: "step",
      id: "n",
      type: "mul@1",
      params: {},
      portInputs: { a: port("load-p", "output"), b: port("load-q", "output") },
      narrationOverride: NARR_N,
    },
    // φ(n) = (p − 1)(q − 1).
    {
      kind: "step",
      id: "p-minus-1",
      type: "sub@1",
      params: {},
      portInputs: { a: port("load-p", "output"), b: port("one", "output") },
      narrationOverride: NARR_P_MINUS_1,
    },
    {
      kind: "step",
      id: "q-minus-1",
      type: "sub@1",
      params: {},
      portInputs: { a: port("load-q", "output"), b: port("one", "output") },
      narrationOverride: NARR_Q_MINUS_1,
    },
    {
      kind: "step",
      id: "phi",
      type: "mul@1",
      params: {},
      portInputs: { a: port("p-minus-1", "output"), b: port("q-minus-1", "output") },
      narrationOverride: NARR_PHI,
    },
    // d = e⁻¹ mod φ(n) — the private exponent (and the decrypt ladder's
    // exponent), derived by the TRACED extended-Euclid loop built above: two
    // coefficient seeds + K division-step rungs + the gcd-gated `eea-extract`
    // tail (id "d"). Replaces the single-frame `mod-inverse@1` oracle (kept
    // registered as the cross-check oracle, no longer emitted by any spec).
    ...eeaDecomposition,
    // Publish tail: mirror this direction's key material into aux["rsa.*"] so
    // the ladder can read it across the group boundary (`aux` is the only
    // cross-scope channel). Each direction publishes EXACTLY the key its ladder
    // consumes — the public key {n, e} on encrypt, the private key {n, d} on
    // decrypt — so RSA's two-key split is concrete AND nothing is written-but-
    // unread (publishing the unused exponent would draw an `unused-write`
    // warning on the default spec). `d` is still derived + narrated above for
    // both directions; in encrypt its output simply goes unconsumed.
    {
      kind: "step",
      id: "publish-key",
      type: "rsa.publish-key-params@1",
      params: { outputPrefix: RSA_AUX_PREFIX, keys: [...publishedKeys] },
      portInputs: publishInputs,
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
      narrationOverride: NARR_SQUARE(j + 1, rungs),
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
      narrationOverride: NARR_COND_MULT(bitIndex),
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
