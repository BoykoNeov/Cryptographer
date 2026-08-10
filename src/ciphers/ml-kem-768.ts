/**
 * ML-KEM-768 — the key-encapsulation mechanism (FIPS 203 §7).
 * `docs/plans/unified-stargazing-quasar.md`, P4.
 *
 * ## What this adds to K-PKE, and why it is the part that ships
 *
 * `k-pke.ts` deliberately has no selector entry: it is secure only against an
 * attacker who watches, and handing a learner "post-quantum encryption" without
 * the part that fixes that would be worse than showing them nothing. This file
 * is that part — the Fujisaki–Okamoto transform — and it is what a learner
 * actually selects.
 *
 * Three ideas, and each one is a step you can scrub to:
 *
 * 1. **The randomness is derived from the message, not chosen.** `(K, r) = G(m)`,
 *    so nobody can produce a valid ciphertext without knowing `m` in advance.
 * 2. **Decapsulation re-encrypts what it decrypted** and compares. That check is
 *    what a hand-built ciphertext cannot survive.
 * 3. **A failed check returns a different key, never an error.** See
 *    `steps/ml-kem-select-shared-secret.ts` — the one step that separates the
 *    IND-CPA scheme underneath from the IND-CCA mechanism on top.
 *
 * ## The key pair is born inside both specs
 *
 * The 64-byte seed `d ‖ z` is a `constant-load@1` leaf and therefore editable,
 * exactly as RSA's `p, q, e` are: change it and the whole key pair changes in
 * front of you. Key generation then runs inside a **default-collapsed group**,
 * so the algorithm a learner opened is what they see first and the 485 nodes
 * that produced the key are one box away.
 *
 * That costs roughly 485 nodes and 6,200 frames per spec, which is why it was a
 * decision rather than a default — see the plan's P4 section for the measured
 * alternatives that were rejected.
 *
 * ## Why key generation is grouped and the K-PKE bodies are not
 *
 * **A group has exactly one input port.** The runtime seeds a group's scope with
 * `port(groupId, "in")` and nothing else, so a body needing two or three inputs
 * can only be grouped by concatenating them outside and splitting them back
 * inside — plumbing that exists to serve the box rather than the algorithm.
 *
 * Key generation takes exactly one input (the seed), so it groups for free. The
 * encryption and decryption bodies take two and three, and they are also the
 * content a learner came to see, so they stay inline. The transforms inside them
 * are collapsed on their own account.
 *
 * ## Port flow cannot cross a group boundary
 *
 * Hence `q` and the γ table appear twice — once at the top level for the inline
 * bodies, once inside the key-generation group. They are `aux-load-bytes@1`
 * leaves reading `cipherConstants`, and aux is the only channel that crosses a
 * scope. This is the same constraint the CSPRNG's seed and the NTT's modulus
 * both ran into.
 */

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { port } from "./block-cipher-core";
import {
  CIPHERTEXT_BYTES,
  DK_BYTES,
  EK_BYTES,
  KPKE_DK_ID,
  KPKE_EK_ID,
  type KPkeEmbedding,
  kPkeConstantNodes,
  kPkeDecryptNodes,
  kPkeEncryptNodes,
  kPkeKeyGenNodes,
} from "./k-pke";
import { GAMMA_TABLE_BYTES, N_INV_BYTES, Q_BYTES, ZETA_TABLE_BYTES } from "./mlkem-constants";

// ─── Widths (FIPS 203 §8, Table 3) ────────────────────────────────────────

/** `d ‖ z` — the two 32-byte halves that determine everything else. */
export const ML_KEM_SEED_BYTES = 64;
/** The message `m`: 32 bytes of randomness, which is also what binds `r`. */
export const ML_KEM_MESSAGE_BYTES = 32;
/** The shared secret, at every parameter set. */
export const ML_KEM_SHARED_SECRET_BYTES = 32;
/** The encapsulation key — K-PKE's, unchanged. */
export const ML_KEM_EK_BYTES = EK_BYTES;
/** `dk_PKE ‖ ek ‖ H(ek) ‖ z` (FIPS 203 §7.1). 1152 + 1184 + 32 + 32. */
export const ML_KEM_DK_BYTES = DK_BYTES + EK_BYTES + 64;
/** The ciphertext — K-PKE's, unchanged. */
export const ML_KEM_CIPHERTEXT_BYTES = CIPHERTEXT_BYTES;

// ─── Node ids the tests, the UI and the browser scrub address ─────────────

/** The editable 64-byte seed. Everything else in either spec follows from it. */
export const MLKEM_SEED_ID = "seed";
/** The default-collapsed key-generation group. */
export const MLKEM_KEYGEN_ID = "keygen";
/** Splits the group's `ek ‖ dk` output back into the pair FIPS 203 returns. */
export const MLKEM_KEYPAIR_ID = "keypair";
/** `G`'s two halves: `output0` is the shared secret, `output1` the randomness. */
export const MLKEM_KR_ID = "kr";
/** Encapsulation's ciphertext, and the spec's output. */
export const MLKEM_CIPHERTEXT_ID = "enc.c";
/** Decapsulation's parse of `dk` — FIPS 203 Algorithm 18 steps 1–4. */
export const MLKEM_DK_SPLIT_ID = "dk-split";
/** Decapsulation's recovered message `m′`. */
export const MLKEM_MPRIME_ID = "dec.m";
/** Decapsulation's re-encrypted ciphertext `c′`. */
export const MLKEM_REENCRYPT_ID = "re.c";
/** The rejection secret `K̄ = J(z ‖ c)`. */
export const MLKEM_REJECTION_ID = "j";
/** The select, and decapsulation's output. */
export const MLKEM_SELECT_ID = "shared";

/** Aux names the runtime seeds from `cipherConstants`. */
const CONSTANTS = {
  q: Q_BYTES,
  zeta: ZETA_TABLE_BYTES,
  ninv: N_INV_BYTES,
  gamma: GAMMA_TABLE_BYTES,
};

/**
 * The default seed, and therefore the default key pair.
 *
 * These 64 bytes are the `counting` vector in
 * `tests/fixtures/ml-kem-768-seed-vectors.json`, captured from Node 24's
 * OpenSSL — chosen over the all-zero one because a seed of zeros makes several
 * degenerate coincidences look like correct behaviour. So the app's first paint
 * is a key pair somebody else's implementation produced from the same seed: the
 * same "first impression IS a test vector" choice AES-128 makes with FIPS-197
 * §C.1. `tests/ml-kem-768-kat.test.ts` pins that correspondence, and the
 * fixture carries an encapsulation under this very seed as well.
 */
export const ML_KEM_DEFAULT_SEED = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
]);

/**
 * The default message `m` for encapsulation.
 *
 * A real encapsulation draws these 32 bytes at random. Here they are an
 * editable input, which is the only way the trace can be reproducible — and it
 * makes the point that the "randomness" `r` is a *function* of this value
 * rather than a second independent draw.
 */
export const ML_KEM_DEFAULT_MESSAGE = new Uint8Array(
  Array.from({ length: ML_KEM_MESSAGE_BYTES }, (_, i) => (i * 7 + 1) & 0xff),
);

/**
 * The default ciphertext — decapsulation's input when a learner lands in the
 * decrypt direction.
 *
 * **These 1088 bytes are OpenSSL's**, not ours: the encapsulation Node 24
 * produced under the `counting` seed, lifted verbatim out of
 * `tests/fixtures/ml-kem-768-seed-vectors.json`. So the first Run in the
 * decapsulation direction reproduces a shared secret a different implementation
 * reported — the strongest form of "first impression IS a test vector" available
 * here, and strictly better than baking in whatever our own encapsulation
 * happens to emit.
 *
 * It also gives the browser scrub its most interesting single gesture: flip one
 * bit of this and the trace stops returning `663473b4…` and starts returning the
 * decoy, with the select's narration saying so.
 *
 * Why a hex string: 1088 `0x..` literals is four pages of noise. The NTT's
 * `DEFAULT_NTT_OUTPUT` is stored the same way for the same reason.
 */
export const ML_KEM_DEFAULT_CIPHERTEXT: Uint8Array = (() => {
  const hex =
    "f9ae1f0f7b35add849ad18d5787052a29f171655a7324338c8d0f808974b7fe6d4e658d891ff" +
    "bdc5f1e4d5d946ab9af7e0433739be7c0a1485465e0e264e441b5eaf58e1e9ee82e0816bf968" +
    "8c2cf3e36d8742fcf557303327c9f2e3bf251042c472041857ab825a3408de76bc9d1fe76597" +
    "7753c617a46e36b285902fd4393006b4b15ad83e97206b43a2bfb68ecd6f6410a21e6121dc7a" +
    "fe38ccf29368785c8643aa58aca108d14f35bf025699ecf6e656aa5636f82e72d7825b42d658" +
    "cb08046bc765e1bf5eaa5fa8efacd48b56b2e43fef2a921c2bfdadd47af84228d474083e9087" +
    "85b239c60d92cfe213726ac9cd5cbafd1df8372fbe45d5cf08dc69e42ae7cef81490f25aec56" +
    "d3ad81c8f0010229c2b7c0529d6877cd3b5ed1a02d14004f4f9feb85c2dd54e50f076ecfa6cd" +
    "7234094fba1b6e55965a9970c336094a41a71055f867d7fc0a1a2fedade2959e994d4d42b528" +
    "a4337364abb6f03311a1b389e6b1c8ecbc8d6794c70084e781c10d429b5abfe53cfbc4b9d941" +
    "8d5685a51cd009c31e64c25791cb4d75c8ff42eadba682c2a6aa5b8f7264406a85d8488ddeaf" +
    "69474b032e4683113c4cb58837b5271f3a81603cd7743f82f2af7d33e285293eb7ab0fa46dcc" +
    "032672207dea792352cdd55afcd22970b76679e4f080904a9dc68ac0def123210fd0bc90d19a" +
    "453743720f87efa56e41262749b22ce4934f8022aff542babe307e127c41ec828d573db28be4" +
    "e1c3eebf77780d2bfbe06ba8e455a6e54d72d1e187952015fd5d77b6e5d6869f84cedb661d5c" +
    "9aee1cc220c0f313d44bdc7889317578f32dec777e73dce7b10eb18bd78735c27841d4ba0918" +
    "acd3d4ef4db1b27a2740e6ce5742fb30c0750015c67640f50fa95afddd116d1610da2b710439" +
    "9ea84b8c163441065b9d101a12d53aec959f58b98b847c5093f70c709029aa15514f68279994" +
    "315877a72cc671431c978170d6d2b79f4f967a2980e9d37803ef3bfdb407c4b7aeff1ea41e0e" +
    "c246f8ac9c62dfec756f52d2ac1f4999c2c72eb22abbd076951edccbc6f64c60a45fc860f938" +
    "5b2866e5b3be25d1abc833f0c6df6aa966aab01ac2b1e758cc85b792cde85d36ba735bbcea8f" +
    "7ea8bc17f88e8af79df1de11555f8f0ecafc5d1d15cbe40a3959908402ed5101b38662d0ce5e" +
    "7c8c929c5b1883d8c774ab9d444b6bfc23ceb60c9747fbe0a2a4dc3482840bc42def82495550" +
    "f2376b1389dbf9775359f80cd3604ab509515c174b9d32ff41333f7afd1c371ab604bdad5d32" +
    "f06c134db5daf3e2b079472d6853d506a1e86d781e7fb2b93d876063e51e0c1aed15ee18f7e0" +
    "6f6e0c83dde88b19ac1a09a8253d460bb4c983208252edc53465c72a7c5b5569240f3e9b1f22" +
    "b54c485acee07597b9c8708f455bf53ff2bd81f5c32e631fedc1f10f7f4244a3e01e8377fb90" +
    "b03e2e9a048437876099abeb1e6071536dd02d3204fa9b0f4ceaf6ea703b15e116f932a5d31c" +
    "b4d45f9081a1bf853e52f699e1ce19223c4c153c208984d4";
  const out = new Uint8Array(ML_KEM_CIPHERTEXT_BYTES);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
})();

/**
 * The shared secret `ML_KEM_DEFAULT_CIPHERTEXT` decapsulates to, as OpenSSL
 * reported it. Not read by the app — it is here so the KAT can state the claim
 * the default makes, and so a reader of this file can see what the first Run
 * should show.
 */
export const ML_KEM_DEFAULT_SHARED_SECRET =
  "663473b48bf01c101f1a66ca7e324d15650ed1adcd1e25c7b18f9c52b7469de1";

// ─── Narration for the leaves carrying a fact the generic docs cannot ─────

const narrSeed: StepDocumentation = {
  name: "The seed d ‖ z — the entire key pair, in 64 bytes",
  summary:
    "Edit these and every byte downstream changes. The first half generates the keys; the second is used only when a ciphertext is rejected.",
  detail: `## A key pair is a seed

A public key here is 1184 bytes and a private key 2400, and neither is stored by
anything that can regenerate them: both come from these 64 bytes, deterministically.
That is why an ML-KEM private key can be backed up as a seed.

The two halves never mix:

- **d** (the first 32) is fed to \`G\` and produces everything about the key
  pair — the matrix seed ρ, the secret vector, the errors.
- **z** (the second 32) is copied into the private key untouched and is read at
  exactly one moment: when a ciphertext fails its re-encryption check and a
  decoy shared secret has to be produced. Nothing else ever reads it.

A consequence worth checking for yourself: two seeds differing only in \`z\` give
**identical** public keys and identical K-PKE private keys, and differ only in
what they return for a corrupted ciphertext.

## Why it is editable here and random everywhere else

A real implementation draws these bytes from the operating system. Fixing them
is what makes this trace reproducible — and what lets you change one byte and
watch 3,584 bytes of key material change with it.`,
  references: ["FIPS 203 Algorithm 16 — ML-KEM.KeyGen_internal(d, z)"],
};

const narrDkAssemble: StepDocumentation = {
  name: "dk = dk_PKE ‖ ek ‖ H(ek) ‖ z",
  summary:
    "The private key carries the public key and its digest around with it, so decapsulation never needs to be handed them separately.",
  detail: `## Four pieces, and only the first is secret in the usual sense

FIPS 203's decapsulation key is a concatenation:

\`\`\`
dk = dk_PKE ‖ ek ‖ H(ek) ‖ z
     1152     1184   32      32     = 2400 bytes
\`\`\`

- **dk_PKE** — the actual decryption key, the transformed secret vector \`ŝ\`.
- **ek** — the *public* key, carried inside the private one. Decapsulation has
  to re-encrypt, and re-encrypting needs the public key.
- **H(ek)** — its digest, stored rather than recomputed. It is needed on every
  decapsulation, and hashing 1184 bytes each time would be waste.
- **z** — the rejection secret. Only the select at the end ever reads it.

## Why carrying ek inside dk is not redundancy

A KEM's decapsulation is one function of one private key and one ciphertext.
Nothing hands it a public key. But the Fujisaki–Okamoto check *requires* the
public key, because it re-runs encryption — so the standard puts it in the
private key rather than complicate the interface.`,
  references: ["FIPS 203 §7.1 — the form of dk", "FIPS 203 Algorithm 16"],
};

const narrDkParse: StepDocumentation = {
  name: "Parse dk back into its four pieces",
  summary:
    "Decapsulation is handed a private key and a ciphertext, and nothing else. Everything it needs comes out of these offsets.",
  detail: `## The first four lines of decapsulation

FIPS 203 Algorithm 18 opens by cutting the 2400-byte key at three offsets:

\`\`\`
dk_PKE ← dk[0     : 1152]      the decryption key
ek     ← dk[1152  : 2336]      the public key, for the re-encryption
h      ← dk[2336  : 2368]      H(ek), stored at key generation
z      ← dk[2368  : 2400]      the rejection secret
\`\`\`

Get an offset wrong and the failure is total but silent in a specific way: the
decryption still returns *a* message (K-PKE decryption cannot fail), the
re-encryption still produces *a* ciphertext, the comparison fails, and a
perfectly well-formed decoy secret comes out. Every ciphertext is rejected and
nothing reports an error — which is precisely the behaviour the design is
supposed to have for a *forged* ciphertext.

## Why ek is taken from here and not from the group above

The key-generation group in this trace produced the same \`ek\`, and reading it
from there would give identical bytes. It is parsed out of \`dk\` instead because
that is what decapsulation actually has: a real one is never in the same room as
key generation. The trace shows both only because it is teaching.`,
  references: ["FIPS 203 Algorithm 18 — ML-KEM.Decaps_internal, steps 1–4"],
};

const narrKr: StepDocumentation = {
  name: "K and r — the shared secret and the randomness, from one hash",
  summary:
    "The randomness that encrypts the message is derived FROM the message. That single fact is what makes forging a ciphertext impossible.",
  detail: `## One hash, and the trick is which side it is on

\`\`\`
(K, r) ← G(m ‖ H(ek))
\`\`\`

- **K** is the shared secret. It is settled here, before the ciphertext exists —
  the ciphertext is a way to *transport* it, not a thing it is derived from.
- **r** is the randomness the encryption below is then run with.

## Why deriving r from m is the whole security argument

In the textbook scheme underneath, \`r\` is an independent random value. That
means many different ciphertexts encrypt the same message, and an attacker can
build malformed ones freely and learn from how they decrypt.

Here \`r\` is a *function* of \`m\`. So there is exactly one valid ciphertext per
message, and producing it requires knowing \`m\` first. An attacker cannot
construct a valid ciphertext for a message they do not know — and decapsulation
can *verify* validity, simply by redoing the derivation and the encryption and
checking it lands on the same bytes.

That is the Fujisaki–Okamoto transform in one line, and the rest of this trace
is its consequences.`,
  references: [
    "FIPS 203 Algorithm 17 — ML-KEM.Encaps_internal",
    "FIPS 203 Algorithm 18 — ML-KEM.Decaps_internal, step 6",
  ],
};

const narrJoinZC: StepDocumentation = {
  name: "z ‖ c — the input to the rejection secret",
  summary:
    "Both halves are load-bearing: z keeps the decoy unpredictable, c keeps two different failures from producing the same decoy.",
  detail: `## Why the decoy depends on the ciphertext

\`K̄ = J(z ‖ c)\` is computed on every decapsulation, valid or not, and returned
only when the check fails.

- Without **z**, an attacker could compute the decoy themselves and so recognise
  a rejection on sight — which is the one bit the whole construction hides.
- Without **c**, every rejected ciphertext would yield the *same* decoy. Two
  identical answers would announce "both of those were rejected" just as loudly
  as an error message.

Together they give an answer that is deterministic (the same bad ciphertext
always gets the same secret, so retrying reveals nothing), unpredictable, and
different for every distinct failure.`,
  references: ["FIPS 203 Algorithm 18 — ML-KEM.Decaps_internal, step 7"],
};

const narrEncapsH: StepDocumentation = {
  name: "H(ek) — computed here, because encapsulation has only the public key",
  summary:
    "Decapsulation reads this same digest out of the private key. Encapsulation has to hash the key itself.",
  detail: `## The same 32 bytes, reached two different ways

\`G\` is fed \`m ‖ H(ek)\` on both sides, and both sides must agree on those 32
bytes or the re-encryption check can never pass.

- **Encapsulation** holds the public key and nothing else, so it hashes it.
- **Decapsulation** finds the digest already sitting inside the private key,
  stored there at key generation, and does not recompute it.

## What the digest is doing in the derivation at all

It binds the shared secret to a specific public key. Without it, the same message
would derive the same \`K\` under every public key in the world — so a ciphertext
captured from one session could be replayed at a different recipient and produce
a secret the attacker already knew was in play.`,
  references: ["FIPS 203 Algorithm 17 — ML-KEM.Encaps_internal, step 1"],
};

// ─── Shared construction ──────────────────────────────────────────────────

/** A `constant-load@1` carrying the seed — editable, like RSA's p, q and e. */
const seedNode = (seed: Uint8Array): StepNode => ({
  kind: "step",
  id: MLKEM_SEED_ID,
  type: "constant-load@1",
  params: { bytes: [...seed] },
  narrationOverride: narrSeed,
});

const concatNode = (id: string, parts: readonly PortBinding[], narration?: StepDocumentation) => {
  const portInputs: Record<string, PortBinding> = {};
  parts.forEach((p, i) => {
    portInputs[`input${i}`] = p;
  });
  const node: StepNode = {
    kind: "step",
    id,
    type: "concat@1",
    params: { inputCount: parts.length },
    portInputs,
    ...(narration === undefined ? {} : { narrationOverride: narration }),
  };
  return node;
};

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

/**
 * ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16) as a default-collapsed group.
 *
 * One input (the seed), one output (`ek ‖ dk`) — which is exactly the pair the
 * standard's KeyGen returns, so the split placed on it outside is FIPS's own
 * `(ek, dk)` and not an artefact of the container's single-port rule.
 *
 * Its own `q` / `gamma` leaves live inside because port flow stops at the group
 * boundary; they read the same `cipherConstants` the outer ones do.
 */
const keyGenGroup = (): StepNode => {
  const ctx: KPkeEmbedding = {
    prefix: `${MLKEM_KEYGEN_ID}.`,
    q: port(`${MLKEM_KEYGEN_ID}.q`, "output"),
    gamma: port(`${MLKEM_KEYGEN_ID}.gamma`, "output"),
  };
  const children: StepNode[] = kPkeConstantNodes(true, ctx.prefix);

  // The group's scope is seeded with `port(groupId, "in")` and nothing else.
  children.push(splitNode(`${ctx.prefix}dz`, port(MLKEM_KEYGEN_ID, "in"), [32, 32]));
  const d = port(`${ctx.prefix}dz`, "output0");
  const z = port(`${ctx.prefix}dz`, "output1");

  const keys = kPkeKeyGenNodes(ctx, d);
  children.push(...keys.nodes);

  children.push(
    {
      kind: "step",
      id: `${ctx.prefix}h`,
      type: "ml-kem.hash-h@1",
      params: {},
      portInputs: { input: keys.ek },
    },
    concatNode(
      `${ctx.prefix}dk-full`,
      [keys.dk, keys.ek, port(`${ctx.prefix}h`, "output"), z],
      narrDkAssemble,
    ),
    concatNode(`${ctx.prefix}pair`, [keys.ek, port(`${ctx.prefix}dk-full`, "output")]),
  );

  return {
    kind: "group",
    id: MLKEM_KEYGEN_ID,
    label: "Key generation — 64 seed bytes → the key pair",
    defaultCollapsed: true,
    seedInput: port(MLKEM_SEED_ID, "output"),
    bodyOutput: port(`${ctx.prefix}pair`, "output"),
    children,
  };
};

/** The top-level constants the inline K-PKE bodies read. */
const outerEmbedding = (prefix: string): KPkeEmbedding => ({
  prefix,
  q: port("q", "output"),
  gamma: port("gamma", "output"),
});

/** Seed → key generation → `(ek, dk)`. Shared by both directions verbatim. */
const keyMaterialNodes = (
  seed: Uint8Array,
): { readonly nodes: StepNode[]; readonly ek: PortBinding; readonly dk: PortBinding } => {
  const nodes: StepNode[] = [
    ...kPkeConstantNodes(true),
    seedNode(seed),
    keyGenGroup(),
    splitNode(MLKEM_KEYPAIR_ID, port(MLKEM_KEYGEN_ID, "out"), [ML_KEM_EK_BYTES, ML_KEM_DK_BYTES]),
  ];
  return {
    nodes,
    ek: port(MLKEM_KEYPAIR_ID, "output0"),
    dk: port(MLKEM_KEYPAIR_ID, "output1"),
  };
};

// ─── ML-KEM.Encaps (FIPS 203 Algorithm 17 / §7.2) ─────────────────────────

/**
 * Encapsulation: message `m` in, ciphertext out, shared secret at `kr.output0`.
 *
 * **The spec's output is the ciphertext, not the shared secret**, because the
 * ciphertext is the thing that travels — and because it is what decapsulation
 * takes as its input, so the two directions compose the way the UI's
 * encrypt/decrypt pair does everywhere else. The shared secret is one scrub
 * away, at the `G` split, and comparing it against what decapsulation returns
 * is the exercise worth doing.
 */
export const buildMlKemEncapsSpec = (seed: Uint8Array = ML_KEM_DEFAULT_SEED): CipherSpec => {
  const material = keyMaterialNodes(seed);
  const steps: StepNode[] = [...material.nodes];

  const message = port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT);

  // (K, r) ← G(m ‖ H(ek))
  steps.push(
    {
      kind: "step",
      id: "h",
      type: "ml-kem.hash-h@1",
      params: {},
      portInputs: { input: material.ek },
      narrationOverride: narrEncapsH,
    },
    concatNode("g-in", [message, port("h", "output")]),
    {
      kind: "step",
      id: "g",
      type: "ml-kem.hash-g@1",
      params: {},
      portInputs: { input: port("g-in", "output") },
    },
    splitNode(MLKEM_KR_ID, port("g", "output"), [32, 32], narrKr),
  );

  // c ← K-PKE.Encrypt(ek, m, r)
  steps.push(
    ...kPkeEncryptNodes(outerEmbedding("enc."), {
      ek: material.ek,
      message,
      randomness: port(MLKEM_KR_ID, "output1"),
    }).nodes,
  );

  return {
    id: "ml-kem-768-encaps@1",
    name: "ML-KEM-768 encapsulation",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    cipherConstants: { ...CONSTANTS },
    steps,
    outputFrom: port(MLKEM_CIPHERTEXT_ID, "output"),
  };
};

// ─── ML-KEM.Decaps (FIPS 203 Algorithm 18 / §7.3) ─────────────────────────

/**
 * Decapsulation: ciphertext in, shared secret out — and never an error.
 *
 * Three K-PKE bodies live here: key generation (collapsed), the decryption, and
 * the re-encryption that checks it. The last of those is not redundancy; it is
 * the check, and the select it feeds is the entire difference between this and
 * the scheme in `k-pke.ts`.
 */
export const buildMlKemDecapsSpec = (seed: Uint8Array = ML_KEM_DEFAULT_SEED): CipherSpec => {
  const material = keyMaterialNodes(seed);
  const steps: StepNode[] = [...material.nodes];

  const ciphertext = port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT);

  // dk_PKE ‖ ek ‖ h ‖ z
  steps.push(
    splitNode(MLKEM_DK_SPLIT_ID, material.dk, [DK_BYTES, ML_KEM_EK_BYTES, 32, 32], narrDkParse),
  );
  const dkPke = port(MLKEM_DK_SPLIT_ID, "output0");
  const ekFromDk = port(MLKEM_DK_SPLIT_ID, "output1");
  const h = port(MLKEM_DK_SPLIT_ID, "output2");
  const z = port(MLKEM_DK_SPLIT_ID, "output3");

  // m′ ← K-PKE.Decrypt(dk_PKE, c)
  const decrypted = kPkeDecryptNodes(outerEmbedding("dec."), { dk: dkPke, ciphertext });
  steps.push(...decrypted.nodes);

  // (K′, r′) ← G(m′ ‖ h)
  steps.push(
    concatNode("g-in", [decrypted.message, h]),
    {
      kind: "step",
      id: "g",
      type: "ml-kem.hash-g@1",
      params: {},
      portInputs: { input: port("g-in", "output") },
    },
    splitNode(MLKEM_KR_ID, port("g", "output"), [32, 32], narrKr),
  );

  // K̄ ← J(z ‖ c). Computed unconditionally — see the select's description.
  steps.push(concatNode("j-in", [z, ciphertext], narrJoinZC), {
    kind: "step",
    id: MLKEM_REJECTION_ID,
    type: "ml-kem.kdf-j@1",
    params: {},
    portInputs: { input: port("j-in", "output") },
  });

  // c′ ← K-PKE.Encrypt(ek, m′, r′)
  steps.push(
    ...kPkeEncryptNodes(outerEmbedding("re."), {
      ek: ekFromDk,
      message: decrypted.message,
      randomness: port(MLKEM_KR_ID, "output1"),
    }).nodes,
  );

  // if c ≠ c′ then K′ ← K̄
  steps.push({
    kind: "step",
    id: MLKEM_SELECT_ID,
    type: "ml-kem.select-shared-secret@1",
    params: {},
    portInputs: {
      // The RECEIVED ciphertext, never the re-encryption — with a valid
      // ciphertext the two are equal, so wiring this to `re.c` would pass every
      // test that does not corrupt one.
      ciphertext,
      reencryption: port(MLKEM_REENCRYPT_ID, "output"),
      shared: port(MLKEM_KR_ID, "output0"),
      rejection: port(MLKEM_REJECTION_ID, "output"),
    },
  });

  return {
    id: "ml-kem-768-decaps@1",
    name: "ML-KEM-768 decapsulation",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    cipherConstants: { ...CONSTANTS },
    steps,
    outputFrom: port(MLKEM_SELECT_ID, "output"),
  };
};

/** Re-exported so the surface tables and tests agree on the two node ids. */
export { KPKE_EK_ID, KPKE_DK_ID };
