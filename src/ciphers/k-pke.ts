/**
 * K-PKE — the public-key encryption scheme underneath ML-KEM (FIPS 203 §5).
 * `docs/plans/unified-stargazing-quasar.md`, P3.
 *
 * ## What this is, and what it is not
 *
 * K-PKE is a textbook lattice encryption scheme: a public key, a message, a
 * ciphertext. It is **not** ML-KEM, and the difference is the point of P4. K-PKE
 * is secure only against an attacker who watches; hand that attacker the ability
 * to submit ciphertexts of their own and it falls over. ML-KEM is the wrapper
 * that fixes this — re-encrypt what you decrypted, check it matches, and return
 * a plausible fake secret if it does not.
 *
 * So this file deliberately ships **no selector entry**. A learner handed
 * "post-quantum encryption" that is missing the part which makes it safe would
 * be worse off than one who had never seen it. P3's proof is its KAT.
 *
 * ## Three builders, not one spec
 *
 * `KeyGen`, `Encrypt` and `Decrypt` are separate specs. Combining them would
 * make the tests end-to-end only, and the whole value of the oracle here is that
 * it provides **checkpoints**: the last 32 bytes of `ek` pin `G`; `dk_PKE` pins
 * the PRF, the sampler and the transform on `s`; the first 1152 bytes of `ek`
 * pin the matrix and the matrix-vector product. A failure names its own cause.
 *
 * Encrypt and Decrypt receive their key material through `cipherConstants` and
 * an `aux-load-bytes@1`, which is the same channel `q`, `ζ` and `γ` already
 * use — one editable source of truth the runtime seeds before any step runs.
 *
 * ## The three facts that were verified rather than recalled
 *
 * Each of these has a wrong version that is entirely self-consistent, so each
 * was checked against the Node-24 fixture before this file existed. The failure
 * signatures are recorded because they are how a future breakage will present:
 *
 * 1. **`G(d ‖ k)`, not `G(d)`.** The parameter `k` (3 here) is appended. The
 *    FIPS 203 draft omitted it; the final standard does not, and OpenSSL
 *    implements the final. Getting it wrong breaks ρ, and therefore everything.
 * 2. **`A[i][j] = SampleNTT(ρ ‖ j ‖ i)` in key generation, `ρ ‖ i ‖ j` in
 *    encryption.** That byte swap IS the transpose. Applying it in both places,
 *    or in neither, gives a key generation that passes its tests and an
 *    encryption that does not — ρ and `dk_PKE` stay correct, `ek` goes wrong.
 * 3. **`N` runs 0,1,2 for `s` and 3,4,5 for `e`.** Swapping the two groups
 *    leaves ρ correct and `dk_PKE` wrong.
 *
 * ## Where the cost is
 *
 * Six forward transforms in key generation, seven in encryption. Each is the
 * shipped `buildNttGroup` — the same object the NTT selector entry shows — so
 * the transform cannot drift between the place it is taught and the place it is
 * used. They are default-collapsed, since a learner opening K-PKE wants to see
 * the ALGORITHM, and the butterflies have their own screen.
 *
 * The Keccak calls go the other way: one frame each. See
 * `src/steps/ml-kem-hash-g.ts` for why, and for the "cross-reference monolith"
 * rule that governs how they describe themselves.
 */

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { port } from "./block-cipher-core";
import {
  COEFF_BYTES,
  GAMMA_TABLE_BYTES,
  N_INV_BYTES,
  POLY_BYTES,
  Q_BYTES,
  ZETA_TABLE_BYTES,
} from "./mlkem-constants";
import { buildNttGroup } from "./ntt-3329-256";

// ─── ML-KEM-768's parameter set (FIPS 203 §8, Table 2) ────────────────────
//
// Read off the table, not recalled: a transposed η pair or `du`/`dv` pair is a
// clean total mismatch that reads like an arithmetic bug.

/** Vector dimension — the matrix is k×k and the secret is k polynomials. */
export const K_PKE_K = 3;
/** Noise width for the secret `s` and the key-generation error `e`. */
export const ETA_1 = 2;
/** Noise width for the encryption errors `e₁` and `e₂`. */
export const ETA_2 = 2;
/** Bits kept per coefficient when compressing `u`. */
export const D_U = 10;
/** Bits kept per coefficient when compressing `v`. */
export const D_V = 4;
/** The dense packing width — 12 bits, because `q` needs 12 bits. */
const D_ENCODE = 12;

/** One packed polynomial: 256 coefficients × 12 bits. */
const ENCODED_POLY_BYTES = (256 * D_ENCODE) / 8;
/** `ByteEncode₁₂(t̂) ‖ ρ`. */
export const EK_BYTES = K_PKE_K * ENCODED_POLY_BYTES + 32;
/** `ByteEncode₁₂(ŝ)`. */
export const DK_BYTES = K_PKE_K * ENCODED_POLY_BYTES;
/** `c₁ ‖ c₂` — k polynomials at `du` bits, then one at `dv`. */
export const CIPHERTEXT_BYTES = 32 * D_U * K_PKE_K + 32 * D_V;

/** Vector-step params, shared with the NTT. Big-endian per coefficient. */
const VEC_PARAMS = { coeffBytes: COEFF_BYTES, littleEndian: false } as const;

// ─── Node ids the tests and P4 address ────────────────────────────────────

/** KeyGen: the encapsulation key, and the spec's own output. */
export const KPKE_EK_ID = "ek";
/** KeyGen: `ByteEncode₁₂(ŝ)` — the secret half, which the fixture also pins. */
export const KPKE_DK_ID = "dk";
/** KeyGen: the public seed ρ, checkable on its own before anything else. */
export const KPKE_RHO_ID = "seeds";
/** Encrypt / Decrypt: where the key material is fetched out of aux. */
export const KPKE_EK_IN_ID = "ek-in";
export const KPKE_DK_IN_ID = "dk-in";
/** The single visible modulus source every arithmetic leaf reads. */
const Q_ID = "q";
/** The γ table the base-case multiplies read. */
const GAMMA_ID = "gamma";

/** Aux names the runtime seeds from `cipherConstants`. */
export const KPKE_EK_AUX = "ek";
export const KPKE_DK_AUX = "dk";
export const KPKE_RANDOMNESS_AUX = "r";

// ─── Narration for the leaves whose OCCURRENCE teaches something ──────────
//
// The LCG's split: the registry doc says what a primitive IS, and these say what
// this particular occurrence is DOING. Only the leaves carrying a fact that the
// generic documentation cannot know get one — the three places where a
// self-consistent wrong answer is possible.

const narrKByte: StepDocumentation = {
  name: "The parameter byte k = 3",
  summary: "Appended to the seed before hashing, so ML-KEM-512, -768 and -1024 cannot share a key.",
  detail: `## Why one byte matters

The seed is hashed as \`d ‖ 3\`, not as \`d\` alone. That 3 is the vector
dimension — the parameter that makes this ML-KEM-768 rather than -512 or -1024.

Feeding it into the hash is called *domain separation*: it guarantees that the
same 32-byte seed produces completely unrelated key pairs at the three security
levels. Without it, a seed reused across parameter sets would give three keys
with a shared derivation, and an attacker who broke the weakest would have a
head start on the others.

It is also a version marker. Earlier drafts of the standard hashed \`d\` alone.
An implementation that still does interoperates with nothing — and the symptom
is total: ρ differs, so the matrix differs, so every byte after this point
differs.`,
  references: ["FIPS 203 Algorithm 13 — K-PKE.KeyGen"],
};

const narrSeedSplit: StepDocumentation = {
  name: "Split into ρ (public) and σ (secret)",
  summary: "The same 64 bytes, cut in half: the first half is published, the second never leaves.",
  detail: `## One hash, two fates

Sixty-four bytes come out of the hash and get cut down the middle. Nothing
distinguishes the halves mathematically — both are uniform random bytes. What
separates them is entirely what happens next:

- **ρ**, the first 32, generates the public matrix **A**. It is copied into the
  public key in the clear, at the very end. Anyone can regenerate A from it.
- **σ**, the second 32, generates the secret **s** and the error **e**. If it
  ever escaped, the private key would follow immediately.

This is worth pausing on. A public key here is 1184 bytes, and 1152 of them are
the vector \`t̂\`. The matrix A — nine polynomials, over 4KB — is not stored at
all. It is regenerated from these 32 bytes every time anybody needs it. Choosing
to publish a *seed* instead of the data it expands to is what keeps a
post-quantum key from being enormous.`,
  references: ["FIPS 203 Algorithm 13 — K-PKE.KeyGen"],
};

const narrMatrixIndex = (row: number, col: number, transposed: boolean): StepDocumentation => ({
  name: `Index bytes for A[${row}][${col}]`,
  summary: transposed
    ? `ρ ‖ ${row} ‖ ${col} — the encryption order, which is what makes this the TRANSPOSE.`
    : `ρ ‖ ${col} ‖ ${row} — note the reversal: column first, then row.`,
  detail: `## Two bytes, and the order of them is the transpose

Each of the nine matrix entries is generated from ρ plus two bytes saying which
entry it is. This one is **A[${row}][${col}]**, and the bytes go on in the order
\`${transposed ? `${row}, ${col}` : `${col}, ${row}`}\`.

${
  transposed
    ? `Encryption needs **Aᵀ**, the transpose. It does not transpose anything: it
appends the two bytes the other way round, so the entry it draws at position
[${row}][${col}] is the one key generation drew at [${col}][${row}]. Same seed,
same nine polynomials, read in the other order.`
    : `Key generation appends **column first**. That looks like a typo and is not.
Encryption appends them the other way round, and that difference — two bytes
swapped — is the entire implementation of "use the transpose".`
}

## Why it is a whole extra failure mode

Get this wrong in both places and the two still agree with each other: a key pair
that encrypts and decrypts its own messages perfectly, and cannot exchange a
single one with any other implementation. Get it wrong in one place and
decryption fails outright.

Neither shows up in a round-trip test, which is why the key here is pinned
against a public key generated by somebody else's code.`,
  references: [
    "FIPS 203 Algorithm 13 — K-PKE.KeyGen (ρ ‖ j ‖ i)",
    "FIPS 203 Algorithm 14 — K-PKE.Encrypt (ρ ‖ i ‖ j)",
  ],
});

const narrCounter = (n: number, what: string): StepDocumentation => ({
  name: `Counter byte N = ${n}`,
  summary: `Distinguishes ${what} from the other five polynomials drawn from the same secret seed.`,
  detail: `## Six polynomials, one seed, one byte

The secret seed σ is 32 bytes and it has to produce six different noise
polynomials — three for the secret **s**, three for the error **e**. The only
thing that differs between the six calls is this counter.

\`\`\`
N = 0, 1, 2  →  s₀, s₁, s₂
N = 3, 4, 5  →  e₀, e₁, e₂
\`\`\`

This one is **N = ${n}**, giving ${what}.

## The mistake this is drawn on the canvas to prevent

Sample \`e\` on 0,1,2 and \`s\` on 3,4,5 — the same six polynomials, assigned the
other way round — and everything still works. The key pair is consistent, it
encrypts, it decrypts. It simply is not the key pair that seed is supposed to
produce, so it can never talk to anything else.

The tell, if it ever happens: ρ stays correct while the secret key goes wrong.`,
  references: ["FIPS 203 Algorithm 13 — K-PKE.KeyGen"],
});

// ─── Small builders ───────────────────────────────────────────────────────

/** The shared modulus source, plus the γ table. Both are top-level here — port
 *  flow reaches every consumer, unlike inside an iterate body where aux is
 *  forced (see `ntt-3329-256.ts`'s header). */
const constantNodes = (withGamma: boolean): StepNode[] => {
  const nodes: StepNode[] = [
    {
      kind: "step",
      id: Q_ID,
      type: "aux-load-bytes@1",
      params: { auxName: "q", byteLength: COEFF_BYTES },
    },
  ];
  if (withGamma) {
    nodes.push({
      kind: "step",
      id: GAMMA_ID,
      type: "aux-load-bytes@1",
      params: { auxName: "gamma", byteLength: GAMMA_TABLE_BYTES.length },
    });
  }
  return nodes;
};

/**
 * One matrix entry: attach the two index bytes to ρ and sample.
 *
 * `row`/`col` are the entry's logical position; `transposed` picks which order
 * the bytes go on, which is the only difference between the matrix and its
 * transpose.
 */
const matrixEntryNodes = (options: {
  readonly id: string;
  readonly rho: PortBinding;
  readonly row: number;
  readonly col: number;
  readonly transposed: boolean;
}): StepNode[] => {
  const { id, rho, row, col, transposed } = options;
  const first = transposed ? row : col;
  const second = transposed ? col : row;
  return [
    {
      kind: "step",
      id: `${id}.idx`,
      type: "constant-load@1",
      params: { bytes: [first, second] },
      narrationOverride: narrMatrixIndex(row, col, transposed),
    },
    {
      kind: "step",
      id: `${id}.seed`,
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: { input0: rho, input1: port(`${id}.idx`, "output") },
    },
    {
      kind: "step",
      id,
      type: "ml-kem.sample-ntt@1",
      params: { ...VEC_PARAMS },
      portInputs: { input: port(`${id}.seed`, "output"), modulus: port(Q_ID, "output") },
    },
  ];
};

/** One noise polynomial: counter byte, join, stretch, sample. */
const noiseNodes = (options: {
  readonly id: string;
  readonly seed: PortBinding;
  readonly counter: number;
  readonly eta: number;
  readonly label: string;
}): StepNode[] => {
  const { id, seed, counter, eta, label } = options;
  return [
    {
      kind: "step",
      id: `${id}.ctr`,
      type: "constant-load@1",
      params: { bytes: [counter] },
      narrationOverride: narrCounter(counter, label),
    },
    {
      kind: "step",
      id: `${id}.in`,
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: { input0: seed, input1: port(`${id}.ctr`, "output") },
    },
    {
      kind: "step",
      id: `${id}.prf`,
      type: "ml-kem.prf@1",
      params: { eta },
      portInputs: { input: port(`${id}.in`, "output") },
    },
    {
      kind: "step",
      id,
      type: "zq-cbd@1",
      params: { ...VEC_PARAMS, eta },
      portInputs: { a: port(`${id}.prf`, "output"), modulus: port(Q_ID, "output") },
    },
  ];
};

/**
 * One row of a matrix-vector product in the transformed domain:
 * `Σⱼ M[row][j] ∘ v[j]`.
 *
 * The `∘` is `zq-base-case-mul@1`, never an element-wise multiply — the
 * transform stops at 128 degree-1 polynomials, so each pair multiplies in its
 * own ring `Z_q[X]/(X²−γ)`. The step type's broken family prefix says so at the
 * palette; this is the place that would have got it wrong.
 */
const dotProductNodes = (options: {
  readonly id: string;
  readonly matrixRow: readonly PortBinding[];
  readonly vector: readonly PortBinding[];
}): { readonly nodes: StepNode[]; readonly output: PortBinding } => {
  const { id, matrixRow, vector } = options;
  const nodes: StepNode[] = [];

  for (let j = 0; j < matrixRow.length; j++) {
    nodes.push({
      kind: "step",
      id: `${id}.mul${j}`,
      type: "zq-base-case-mul@1",
      params: { ...VEC_PARAMS },
      portInputs: {
        a: matrixRow[j] as PortBinding,
        b: vector[j] as PortBinding,
        gamma: port(GAMMA_ID, "output"),
        modulus: port(Q_ID, "output"),
      },
    });
  }

  let running: PortBinding = port(`${id}.mul0`, "output");
  for (let j = 1; j < matrixRow.length; j++) {
    const sumId = `${id}.sum${j}`;
    nodes.push({
      kind: "step",
      id: sumId,
      type: "zq-vec-add@1",
      params: { ...VEC_PARAMS },
      portInputs: {
        a: running,
        b: port(`${id}.mul${j}`, "output"),
        modulus: port(Q_ID, "output"),
      },
    });
    running = port(sumId, "output");
  }

  return { nodes, output: running };
};

/** `zq-vec-add@1` over two polynomials. */
const addNode = (id: string, a: PortBinding, b: PortBinding): StepNode => ({
  kind: "step",
  id,
  type: "zq-vec-add@1",
  params: { ...VEC_PARAMS },
  portInputs: { a, b, modulus: port(Q_ID, "output") },
});

/** The dense 12-bit packing of one polynomial. */
const encodeNode = (id: string, a: PortBinding, d = D_ENCODE): StepNode => ({
  kind: "step",
  id,
  type: "zq-byte-encode@1",
  params: { ...VEC_PARAMS, d },
  portInputs: { a, modulus: port(Q_ID, "output") },
});

/** Its partner, which loses nothing — unlike compress/decompress. */
const decodeNode = (id: string, a: PortBinding, d = D_ENCODE): StepNode => ({
  kind: "step",
  id,
  type: "zq-byte-decode@1",
  params: { ...VEC_PARAMS, d },
  portInputs: { a, modulus: port(Q_ID, "output") },
});

/** `concat@1` over an arbitrary list of bindings. */
const concatNode = (id: string, parts: readonly PortBinding[]): StepNode => {
  const portInputs: Record<string, PortBinding> = {};
  parts.forEach((p, i) => {
    portInputs[`input${i}`] = p;
  });
  return {
    kind: "step",
    id,
    type: "concat@1",
    params: { inputCount: parts.length },
    portInputs,
  };
};

/** Cut a wide value into fixed-width pieces. */
const splitNode = (
  id: string,
  input: PortBinding,
  widths: readonly number[],
  narration?: StepDocumentation,
): StepNode => ({
  kind: "step",
  id,
  type: "split-bytes@1",
  params: { widths: [...widths] },
  portInputs: { input },
  ...(narration === undefined ? {} : { narrationOverride: narration }),
});

// ─── K-PKE.KeyGen (FIPS 203 Algorithm 13) ─────────────────────────────────

/**
 * Key generation from a 32-byte seed `d`.
 *
 * Output is `ek`; `dk_PKE` is produced too and reachable at `KPKE_DK_ID`,
 * because a spec has one output port and the encapsulation key is the one a
 * learner is looking for. Both halves are pinned by the KAT.
 */
export const buildKPkeKeyGenSpec = (): CipherSpec => {
  const steps: StepNode[] = [...constantNodes(true)];

  // (ρ, σ) ← G(d ‖ k)
  steps.push(
    {
      kind: "step",
      id: "k-byte",
      type: "constant-load@1",
      params: { bytes: [K_PKE_K] },
      narrationOverride: narrKByte,
    },
    concatNode("g-in", [port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT), port("k-byte", "output")]),
    {
      kind: "step",
      id: "g",
      type: "ml-kem.hash-g@1",
      params: {},
      portInputs: { input: port("g-in", "output") },
    },
    splitNode(KPKE_RHO_ID, port("g", "output"), [32, 32], narrSeedSplit),
  );
  const rho = port(KPKE_RHO_ID, "output0");
  const sigma = port(KPKE_RHO_ID, "output1");

  // Â[i][j] ← SampleNTT(ρ ‖ j ‖ i). Column byte first — see the narration.
  const matrix: PortBinding[][] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    const row: PortBinding[] = [];
    for (let j = 0; j < K_PKE_K; j++) {
      const id = `A.${i}${j}`;
      steps.push(...matrixEntryNodes({ id, rho, row: i, col: j, transposed: false }));
      row.push(port(id, "output"));
    }
    matrix.push(row);
  }

  // s on counters 0…2, THEN e on 3…5. The order is not interchangeable.
  const secret: PortBinding[] = [];
  const error: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    const id = `s.${i}`;
    steps.push(
      ...noiseNodes({ id, seed: sigma, counter: i, eta: ETA_1, label: `the secret s${i}` }),
    );
    secret.push(port(id, "output"));
  }
  for (let i = 0; i < K_PKE_K; i++) {
    const id = `e.${i}`;
    steps.push(
      ...noiseNodes({
        id,
        seed: sigma,
        counter: K_PKE_K + i,
        eta: ETA_1,
        label: `the error e${i}`,
      }),
    );
    error.push(port(id, "output"));
  }

  // ŝ ← NTT(s), ê ← NTT(e). Six of the shipped transform, default-collapsed.
  const secretHat: PortBinding[] = [];
  const errorHat: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    const id = `ntt.s${i}`;
    steps.push(
      buildNttGroup({
        id,
        label: `NTT(s${i})`,
        direction: "forward",
        seedBinding: secret[i] as PortBinding,
      }),
    );
    secretHat.push(port(id, "out"));
  }
  for (let i = 0; i < K_PKE_K; i++) {
    const id = `ntt.e${i}`;
    steps.push(
      buildNttGroup({
        id,
        label: `NTT(e${i})`,
        direction: "forward",
        seedBinding: error[i] as PortBinding,
      }),
    );
    errorHat.push(port(id, "out"));
  }

  // t̂ ← Â ∘ ŝ + ê
  const tHat: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    const dot = dotProductNodes({
      id: `t.${i}`,
      matrixRow: matrix[i] as PortBinding[],
      vector: secretHat,
    });
    steps.push(...dot.nodes);
    steps.push(addNode(`t.${i}`, dot.output, errorHat[i] as PortBinding));
    tHat.push(port(`t.${i}`, "output"));
  }

  // ek ← ByteEncode₁₂(t̂) ‖ ρ  and  dk ← ByteEncode₁₂(ŝ)
  const ekParts: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    steps.push(encodeNode(`ek.enc${i}`, tHat[i] as PortBinding));
    ekParts.push(port(`ek.enc${i}`, "output"));
  }
  steps.push(concatNode(KPKE_EK_ID, [...ekParts, rho]));

  const dkParts: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    steps.push(encodeNode(`dk.enc${i}`, secretHat[i] as PortBinding));
    dkParts.push(port(`dk.enc${i}`, "output"));
  }
  steps.push(concatNode(KPKE_DK_ID, dkParts));

  return {
    id: "k-pke-768-keygen@1",
    name: "K-PKE key generation (ML-KEM-768)",
    stateShape: "bytes",
    inputs: {
      // The message slot carries the 32-byte seed `d`. Everything else about the
      // key pair is deterministic, so this seed IS the key pair.
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    cipherConstants: { q: Q_BYTES, zeta: ZETA_TABLE_BYTES, gamma: GAMMA_TABLE_BYTES },
    steps,
    outputFrom: port(KPKE_EK_ID, "output"),
  };
};

// ─── K-PKE.Encrypt (FIPS 203 Algorithm 14) ────────────────────────────────

/**
 * Encrypt a 32-byte message under `ek`, with 32 bytes of randomness `r`.
 *
 * Both arrive through aux (`cipherConstants`), the channel `q` and the ζ table
 * already use. The message is the spec's input.
 */
export const buildKPkeEncryptSpec = (ek: Uint8Array, r: Uint8Array): CipherSpec => {
  const steps: StepNode[] = [...constantNodes(true)];

  steps.push(
    {
      kind: "step",
      id: KPKE_EK_IN_ID,
      type: "aux-load-bytes@1",
      params: { auxName: KPKE_EK_AUX, byteLength: EK_BYTES },
    },
    {
      kind: "step",
      id: "r-in",
      type: "aux-load-bytes@1",
      params: { auxName: KPKE_RANDOMNESS_AUX, byteLength: 32 },
    },
    // t̂ is the first 3·384 bytes of ek; ρ is the trailing 32.
    splitNode("ek-split", port(KPKE_EK_IN_ID, "output"), [
      ...Array.from({ length: K_PKE_K }, () => ENCODED_POLY_BYTES),
      32,
    ]),
  );
  const rho = port("ek-split", `output${K_PKE_K}`);
  const randomness = port("r-in", "output");

  const tHat: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    steps.push(decodeNode(`t.dec${i}`, port("ek-split", `output${i}`)));
    tHat.push(port(`t.dec${i}`, "output"));
  }

  // Âᵀ[i][j] ← SampleNTT(ρ ‖ i ‖ j). The bytes go on the other way round here,
  // and that is the whole transpose.
  const matrixT: PortBinding[][] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    const row: PortBinding[] = [];
    for (let j = 0; j < K_PKE_K; j++) {
      const id = `At.${i}${j}`;
      steps.push(...matrixEntryNodes({ id, rho, row: i, col: j, transposed: true }));
      row.push(port(id, "output"));
    }
    matrixT.push(row);
  }

  // y on 0…2, e₁ on 3…5, e₂ on 6.
  const y: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    const id = `y.${i}`;
    steps.push(
      ...noiseNodes({ id, seed: randomness, counter: i, eta: ETA_1, label: `the blinding y${i}` }),
    );
    y.push(port(id, "output"));
  }
  const e1: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    const id = `e1.${i}`;
    steps.push(
      ...noiseNodes({
        id,
        seed: randomness,
        counter: K_PKE_K + i,
        eta: ETA_2,
        label: `the error e₁${i}`,
      }),
    );
    e1.push(port(id, "output"));
  }
  steps.push(
    ...noiseNodes({
      id: "e2",
      seed: randomness,
      counter: 2 * K_PKE_K,
      eta: ETA_2,
      label: "the error e₂",
    }),
  );

  // ŷ ← NTT(y)
  const yHat: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    const id = `ntt.y${i}`;
    steps.push(
      buildNttGroup({
        id,
        label: `NTT(y${i})`,
        direction: "forward",
        seedBinding: y[i] as PortBinding,
      }),
    );
    yHat.push(port(id, "out"));
  }

  // u ← NTT⁻¹(Âᵀ ∘ ŷ) + e₁
  const u: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    const dot = dotProductNodes({
      id: `au.${i}`,
      matrixRow: matrixT[i] as PortBinding[],
      vector: yHat,
    });
    steps.push(...dot.nodes);
    const inv = `intt.u${i}`;
    steps.push(
      buildNttGroup({
        id: inv,
        label: `NTT⁻¹((Aᵀŷ)${i})`,
        direction: "inverse",
        seedBinding: dot.output,
      }),
    );
    steps.push(addNode(`u.${i}`, port(inv, "out"), e1[i] as PortBinding));
    u.push(port(`u.${i}`, "output"));
  }

  // μ ← Decompress₁(ByteDecode₁(m)) — one bit per coefficient, 0 or ⌈q/2⌉.
  steps.push(decodeNode("mu.dec", port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT), 1), {
    kind: "step",
    id: "mu",
    type: "zq-decompress@1",
    params: { ...VEC_PARAMS, d: 1 },
    portInputs: { a: port("mu.dec", "output"), modulus: port(Q_ID, "output") },
  });

  // v ← NTT⁻¹(t̂ᵀ ∘ ŷ) + e₂ + μ
  const dotV = dotProductNodes({ id: "tv", matrixRow: tHat, vector: yHat });
  steps.push(...dotV.nodes);
  steps.push(
    buildNttGroup({
      id: "intt.v",
      label: "NTT⁻¹(t̂ᵀŷ)",
      direction: "inverse",
      seedBinding: dotV.output,
    }),
    addNode("v.e2", port("intt.v", "out"), port("e2", "output")),
    addNode("v", port("v.e2", "output"), port("mu", "output")),
  );

  // c ← ByteEncode_du(Compress_du(u)) ‖ ByteEncode_dv(Compress_dv(v))
  const c1Parts: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    steps.push(
      {
        kind: "step",
        id: `c1.cmp${i}`,
        type: "zq-compress@1",
        params: { ...VEC_PARAMS, d: D_U },
        portInputs: { a: u[i] as PortBinding, modulus: port(Q_ID, "output") },
      },
      encodeNode(`c1.enc${i}`, port(`c1.cmp${i}`, "output"), D_U),
    );
    c1Parts.push(port(`c1.enc${i}`, "output"));
  }
  steps.push(
    {
      kind: "step",
      id: "c2.cmp",
      type: "zq-compress@1",
      params: { ...VEC_PARAMS, d: D_V },
      portInputs: { a: port("v", "output"), modulus: port(Q_ID, "output") },
    },
    encodeNode("c2.enc", port("c2.cmp", "output"), D_V),
    concatNode("c", [...c1Parts, port("c2.enc", "output")]),
  );

  return {
    id: "k-pke-768-encrypt@1",
    name: "K-PKE encryption (ML-KEM-768)",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    cipherConstants: {
      q: Q_BYTES,
      zeta: ZETA_TABLE_BYTES,
      ninv: N_INV_BYTES,
      gamma: GAMMA_TABLE_BYTES,
      [KPKE_EK_AUX]: ek,
      [KPKE_RANDOMNESS_AUX]: r,
    },
    steps,
    outputFrom: port("c", "output"),
  };
};

// ─── K-PKE.Decrypt (FIPS 203 Algorithm 15) ────────────────────────────────

/** Decrypt a ciphertext under `dk_PKE`, recovering the 32-byte message. */
export const buildKPkeDecryptSpec = (dk: Uint8Array): CipherSpec => {
  const steps: StepNode[] = [...constantNodes(true)];

  steps.push(
    {
      kind: "step",
      id: KPKE_DK_IN_ID,
      type: "aux-load-bytes@1",
      params: { auxName: KPKE_DK_AUX, byteLength: DK_BYTES },
    },
    splitNode("c-split", port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT), [
      ...Array.from({ length: K_PKE_K }, () => 32 * D_U),
      32 * D_V,
    ]),
    splitNode(
      "dk-split",
      port(KPKE_DK_IN_ID, "output"),
      Array.from({ length: K_PKE_K }, () => ENCODED_POLY_BYTES),
    ),
  );

  // u′ ← Decompress_du(ByteDecode_du(c₁)) — the lossy step's partner, and NOT
  // its inverse: what comes back is a bucket centre, not the original value.
  const uPrime: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    steps.push(decodeNode(`u.dec${i}`, port("c-split", `output${i}`), D_U), {
      kind: "step",
      id: `u.${i}`,
      type: "zq-decompress@1",
      params: { ...VEC_PARAMS, d: D_U },
      portInputs: { a: port(`u.dec${i}`, "output"), modulus: port(Q_ID, "output") },
    });
    uPrime.push(port(`u.${i}`, "output"));
  }

  steps.push(decodeNode("v.dec", port("c-split", `output${K_PKE_K}`), D_V), {
    kind: "step",
    id: "v",
    type: "zq-decompress@1",
    params: { ...VEC_PARAMS, d: D_V },
    portInputs: { a: port("v.dec", "output"), modulus: port(Q_ID, "output") },
  });

  const sHat: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    steps.push(decodeNode(`s.dec${i}`, port("dk-split", `output${i}`)));
    sHat.push(port(`s.dec${i}`, "output"));
  }

  // ŵ ← NTT(u′)
  const uHat: PortBinding[] = [];
  for (let i = 0; i < K_PKE_K; i++) {
    const id = `ntt.u${i}`;
    steps.push(
      buildNttGroup({
        id,
        label: `NTT(u′${i})`,
        direction: "forward",
        seedBinding: uPrime[i] as PortBinding,
      }),
    );
    uHat.push(port(id, "out"));
  }

  // w ← v′ − NTT⁻¹(ŝᵀ ∘ û)
  const dot = dotProductNodes({ id: "su", matrixRow: sHat, vector: uHat });
  steps.push(...dot.nodes);
  steps.push(
    buildNttGroup({
      id: "intt.w",
      label: "NTT⁻¹(ŝᵀû′)",
      direction: "inverse",
      seedBinding: dot.output,
    }),
    {
      kind: "step",
      id: "w",
      type: "zq-vec-sub@1",
      params: { ...VEC_PARAMS },
      portInputs: {
        a: port("v", "output"),
        b: port("intt.w", "out"),
        modulus: port(Q_ID, "output"),
      },
    },
    // m ← ByteEncode₁(Compress₁(w)). Compressing to ONE bit is the decision
    // step: every coefficient is rounded to whichever of 0 or ⌈q/2⌉ it is nearer,
    // and the noise — which is what makes the whole scheme secure — is what has
    // to stay small enough for that rounding to land on the right side.
    {
      kind: "step",
      id: "m.cmp",
      type: "zq-compress@1",
      params: { ...VEC_PARAMS, d: 1 },
      portInputs: { a: port("w", "output"), modulus: port(Q_ID, "output") },
    },
    encodeNode("m", port("m.cmp", "output"), 1),
  );

  return {
    id: "k-pke-768-decrypt@1",
    name: "K-PKE decryption (ML-KEM-768)",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    cipherConstants: {
      q: Q_BYTES,
      zeta: ZETA_TABLE_BYTES,
      ninv: N_INV_BYTES,
      gamma: GAMMA_TABLE_BYTES,
      [KPKE_DK_AUX]: dk,
    },
    steps,
    outputFrom: port("m", "output"),
  };
};

/** A polynomial on a port, re-exported so tests need not reach into constants. */
export { POLY_BYTES };
