/**
 * ML-DSA-44 — the lattice signature (FIPS 204), key generation and
 * verification. `docs/plans/refactored-petting-tide.md`, P3.
 *
 * ## What ships here, and what does not yet
 *
 * Signing is P4. It is the part of ML-DSA that teaches the most — a loop that
 * throws away candidate signatures until one is safe to publish — and it needs
 * a loop that stops on its own, which the engine does not have yet. So this
 * file builds the two halves that need no loop: **key generation** (FIPS 204
 * Algorithm 6) and **verification** (Algorithm 8). Like K-PKE before ML-KEM,
 * there is no selector entry until the whole scheme exists; a signature scheme
 * that can check signatures but not make them is not something to hand a
 * learner on its own.
 *
 * ## The key pair is born inside the spec
 *
 * The 32-byte seed ξ is an editable `constant-load@1` leaf, and key generation
 * runs inside a **default-collapsed group** — ML-KEM-768's design, unchanged. A
 * group has exactly one input and one output, and key generation needs exactly
 * one of each: ξ in, `pk ‖ sk` out, which is the pair FIPS 204's KeyGen
 * returns. The split outside the group is therefore the standard's own
 * `(pk, sk)`, not an artefact of the container. P4's signing spec embeds the
 * same group; verification uses only the public half.
 *
 * ## Verification takes the signature as its input
 *
 * A spec has one input. The signature has a fixed width (2420 bytes) and the
 * message does not, so the signature is the input and the message is an
 * editable leaf beside the seed. That is also the shape ML-KEM's decapsulation
 * has — what travels is the input — and it makes the experiment worth doing a
 * single gesture: flip one byte of the input and watch the verdict change.
 *
 * ## Every constant a learner might edit rides a wire
 *
 * The P2 rule. q, γ1, γ2, β and ω live in `cipherConstants` (editable in the
 * Constants panel) and reach every consumer through `aux-load-bytes@1`. The two
 * bounds verification needs are DERIVED from them by visible `sub@1` leaves —
 * γ1 − β (how large z may be) and γ1 − 1 (z's packing range) — rather than
 * stored as constants of their own, so editing γ1 cannot leave one of them
 * behind. Values fixed by a structural parameter (η, the t0 range, 2^d) are
 * `constant-load@1` leaves next to the steps that use them.
 *
 * ## Node ids are prefixed
 *
 * The flat trace keys frames by step id, so two copies of one body sharing ids
 * do not raise an error — they silently break the scrubber, frame preservation
 * and the graph (K-PKE P3's lesson). Every id a body emits goes through
 * `ctx.prefix`; key generation's is `keygen.`.
 *
 * ## The transforms and the hashes are one frame each
 *
 * `ml-dsa.ntt@1` and the SHAKE-based steps are cross-reference monoliths: the
 * transform is traced in full under Lattice → NTT mod 8380417, the sponge
 * under Hash → SHAKE. A verification runs five transforms and four hashes;
 * unrolled, the transforms alone would be thousands of frames.
 */

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { port } from "./block-cipher-core";
import {
  ML_DSA_44_BETA,
  ML_DSA_44_ETA,
  ML_DSA_44_GAMMA1,
  ML_DSA_44_GAMMA2,
  ML_DSA_44_K,
  ML_DSA_44_L,
  ML_DSA_44_OMEGA,
  ML_DSA_44_TAU,
  ML_DSA_COEFF_BYTES,
  ML_DSA_D,
  ML_DSA_POLY_BYTES,
  ML_DSA_Q_BYTES,
  mlDsaCoeffBytes,
} from "./mldsa-constants";

// ─── Widths (FIPS 204 Table 2) ─────────────────────────────────────────────

const K = ML_DSA_44_K;
const L = ML_DSA_44_L;

/** `bitlen(q − 1) − d`: the bits of t1 that survive into the public key. */
const T1_BITS = 23 - ML_DSA_D;
/** One packed t1 polynomial: 256 × 10 bits. */
const T1_POLY_BYTES = (256 * T1_BITS) / 8;
/** One packed s1/s2 polynomial: 256 × bitlen(2η) = 3 bits. */
const ETA_POLY_BYTES = (256 * 3) / 8;
/** One packed t0 polynomial: 256 × 13 bits. */
const T0_POLY_BYTES = (256 * ML_DSA_D) / 8;
/** One packed z polynomial: 256 × (1 + bitlen(γ1 − 1)) = 18 bits. */
const Z_POLY_BYTES = (256 * 18) / 8;

/** The seed ξ. */
export const ML_DSA_SEED_BYTES = 32;
/** `ρ ‖ SimpleBitPack(t1)` = 32 + 4 · 320. */
export const ML_DSA_44_PK_BYTES = 32 + K * T1_POLY_BYTES;
/** `ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0` = 32 + 32 + 64 + 8 · 96 + 4 · 416. */
export const ML_DSA_44_SK_BYTES = 128 + (K + L) * ETA_POLY_BYTES + K * T0_POLY_BYTES;
/** `c̃ ‖ z ‖ h` = 32 + 4 · 576 + (ω + k). */
export const ML_DSA_44_SIG_BYTES = 32 + L * Z_POLY_BYTES + ML_DSA_44_OMEGA + K;

/** Vector-step params, shared by every Z_q step here. Big-endian per coefficient. */
const VEC = { coeffBytes: ML_DSA_COEFF_BYTES, littleEndian: false } as const;

// ─── Node ids the tests and P4 address ─────────────────────────────────────

/** The editable seed ξ. */
export const MLDSA_SEED_ID = "seed";
/** The default-collapsed key-generation group. */
export const MLDSA_KEYGEN_ID = "keygen";
/** Splits the group's `pk ‖ sk` back into the pair FIPS 204 returns. */
export const MLDSA_KEYPAIR_ID = "keypair";
/** Key-generation body ids, before the `keygen.` prefix. */
export const MLDSA_SEEDS_ID = "seeds";
export const MLDSA_PK_ID = "pk";
export const MLDSA_SK_ID = "sk";
/** The editable message, and its formatted form M′. */
export const MLDSA_MESSAGE_ID = "message";
export const MLDSA_MPRIME_ID = "m-prime";
/** Verification's landmarks. */
export const MLDSA_SIG_SPLIT_ID = "sig-split";
export const MLDSA_HINT_ID = "h";
export const MLDSA_Z_NORM_ID = "z-norm";
export const MLDSA_RECOMPUTED_ID = "c-tilde-prime";
export const MLDSA_VERDICT_ID = "verdict";

/** Aux names the runtime seeds from `cipherConstants`. */
export const MLDSA_AUX = {
  q: "q",
  gamma1: "gamma1",
  gamma2: "gamma2",
  beta: "beta",
  omega: "omega",
} as const;

/** The editable constants, four bytes each, big-endian (the port convention). */
const CONSTANTS: Record<string, Uint8Array> = {
  [MLDSA_AUX.q]: ML_DSA_Q_BYTES,
  [MLDSA_AUX.gamma1]: mlDsaCoeffBytes(ML_DSA_44_GAMMA1),
  [MLDSA_AUX.gamma2]: mlDsaCoeffBytes(ML_DSA_44_GAMMA2),
  [MLDSA_AUX.beta]: mlDsaCoeffBytes(ML_DSA_44_BETA),
  [MLDSA_AUX.omega]: mlDsaCoeffBytes(ML_DSA_44_OMEGA),
};

// ─── Defaults ──────────────────────────────────────────────────────────────

/**
 * The default seed: the `counting` key in `tests/fixtures/ml-dsa-44-vectors.json`
 * (bytes 0, 1, …, 31), whose public and private keys were captured from Node
 * 24's OpenSSL. So first paint is a key pair somebody else's implementation
 * produced from the same 32 bytes — ML-KEM-768's choice, for the same reason.
 */
export const ML_DSA_44_DEFAULT_SEED = new Uint8Array(
  Array.from({ length: ML_DSA_SEED_BYTES }, (_, i) => i),
);

/**
 * The default message. Chosen, not arbitrary: under the default seed its
 * deterministic signature takes THREE attempts — the first rejected because z
 * came out too large, the second because r0 did — so P4's signing trace shows
 * both common rejections on first paint. Measured by the P2 composition in
 * `tests/ml-dsa-44-oracle.test.ts`; recorded in the fixture's `p3` section.
 */
export const ML_DSA_44_DEFAULT_MESSAGE = new TextEncoder().encode("Hello, world!");

/**
 * The default signature — verification's input — over the default message under
 * the default seed, with the empty context.
 *
 * **These 2420 bytes are `@noble/post-quantum`'s**, its deterministic signature
 * (`rnd = 0³²`), and Node 24 verifies them: lifted verbatim from the fixture's
 * `p3.defaultPair`. So the first Run of verification checks a signature a
 * different implementation made, and P4's own signing has to reproduce exactly
 * these bytes.
 */
export const ML_DSA_44_DEFAULT_SIGNATURE: Uint8Array = (() => {
  const hex =
    "e4d9bf15d2db7934ad6de3403adfdf3dc4433baffe01809f9b5187d3a8beee914839cd9d0c29" +
    "b50a97ee3491b013e5ad3ccc2c4099d56894db12555b179af87a41a76f7ee7efda428a654ef4" +
    "0cb81b9638bdf5668a71d4a2d435b906fdb288207eaf5c7b3cc5e02655bedf9f5a1c0fb77d65" +
    "61453570e67ae440cd335441eaad4c75c8207e10e22cbca82ce298228d7b1bbc496b3cfe4e08" +
    "3a48a81c752ef26aeada40e7509fa3f7a2d73b780a4c560e88665d8d581927140082f669987d" +
    "b19cdd9c41716c05a25887ed9bb4ee7313e973c12ded4787efa3c7ed70447c3489f68e464787" +
    "3816c0fcdec325302211028352512f4fd6ceb48c524702420987e2223652c37489048acc20db" +
    "71d3f541fdba654b20a4b88c1d0c2e9b6131480e94a23a2a1d4aa178d349a2e1cbc88a7e58dd" +
    "ffb172a134386c27fb952063c34605b4a0484bb5377fc5313b03eddbedae9bb0d2714687d820" +
    "8cae7568dd88f6b27b6312b734e19f9814e239de15ffd5278ded9abfad72d4f8e7f3b58fe385" +
    "5dceb53988f14c139510018222f71d7fb382344e6e6fd2022839141c7fe4a8b3ce7f3e6b2aca" +
    "4ff409f7222d59a7f445be161cd2d4931eead3a92d3b38e60e9e1cf57eedd22c2d4f3ac2ffb1" +
    "9232592f63871f70abe0d2c8595aec8af66d7ef8e298bb848873cc04a6b8ff2e20a3f0847b1a" +
    "1e60291f807eae820b7b5cc587a4e4f915f06a6d075176f0645a2e28849fd5731e3226ea9854" +
    "d00637e673f97002821abc2a67f93f3a52203c5861cefa46737fd2052a66f92144c9519d9fa4" +
    "20caeac81ed0f00fa69d87dd0274fd06bd2db22765058b55694bcf71a3fe1a2069325daa7903" +
    "140d02015ea02a9025e96eab23238ff172d28da9e6b1ff7eaa9ed9d3de3183161e3174ae4f4d" +
    "2944f93d96de16f390921a02433e3dba1ef3e3b390003ccf5cfd4942ad89b8466bd6b2f32fd5" +
    "8e3427124e37da8dfcb94c82886494b6c3936f6f0027b925c2c7a120e1635e10cf2f6c651f6d" +
    "35e1d82759ec5a16c569ddbf82448816a430d55d1a4f78dc36ed9f2770a2c6cfa1b0251456e1" +
    "e29cf0528a52e4bacf603d24dfb4ea0f4972a27d3b3b8af8f269cc60be3bd6ebe5cecc24f369" +
    "5a464595a3bdc0c4e5e4555173efc2ecd0f482432c378a1052f95715babe8d303ffd28f6d4f3" +
    "33a996cd5208b3022c2dab0b06d6ed9eb112131665b4cb7e49a544fea6419ab51731800df32c" +
    "a196b56c6a700840bbad55171c423790ed63711fa023caf0d6a1a8b576eaf9a79ef5b986f59a" +
    "5f1fa112dd9def2595e0d18fdf41531aad93f27dd8d7ab106efe976553bc6918516d44c90cec" +
    "0347fda535a3bf1f36f5c81f0f32646e757de9e38b840ff8d8f67b72bd9e8e18a537db01ecbf" +
    "3e13b99783da14dc8c7b25b6b8e45c3911dd93042a22c8663c8302d8fbc52e511876e3695252" +
    "905a4454b0a00ee44f35f1f34ea06d3f7544dded900ac2332c73702134f0482ae746b7de98f0" +
    "ed2be2b7f98f94b9e6d6d17fc43cb46d371528cb61f2d6b5fffe216fdaa85a22921f7a1509ab" +
    "fb8b0b77d3f2ab40a443357dc4a4c58a106eceda0b97fc00d90dae44e2899f94602c86b71008" +
    "f593a6dd7aab64733116c792786171dc16e67d0259f6726b869f31b63d3d47b92a7c1b25c7af" +
    "8fb2ddcdfec152fbbd934a7331f3ab714ea0cf938d1e755ba184960d5dcabcaff9ae5e32307b" +
    "c1bbb5ed178b1a3b6851346adb0eebd268d1c904d50f3d69f9b15855e4dd8c6a10228cfb3289" +
    "f5e2b0ac1e0f82315fcfdcffcaa7bb054d12778d9cc84a8ef0fb91706f7145d343a69931aceb" +
    "bbb418ba421dffb32185701e416c43ed1cb062e96b2d5ef303f7159041ee5039be260277cb88" +
    "427feb0e16e561bfd67a2eada9f8b8444f65a168636dcd6b2f24935a2f71074764263ee85492" +
    "d625bac8747e524b9a6d65a388031074284af9fafc6c3fd0868d471f54c47b4f6d7b5664a22b" +
    "fa9ae9358cde620cd4f5a8e36d738a4be5e9c5ae868e3ce98ff0e87aa99bc5b34e5338d9998f" +
    "036bc6c759740e680d1859b3ba37492468cd6906f64bd9423e377f81bdea9b971cf69941e439" +
    "70d5f44004a502d1ed4c87e8a0e045b57b12b1f5ae9a19e796e938c64cb10ab9616f05ce9e1e" +
    "cbe9d0ad70cc0ec08f2aecc6d0c8be870a827e9f286222a0944e5785373911bc4449be1d9ed6" +
    "220e4741fd64eaf03c247b5f9d9359568c43da3ec9d0b076824ae610944b4b73e76dfcd2bc4c" +
    "48218d3a89228a0fdea4d9e87589dd1628d12860bd91be2c511d7f27f3ff000904ff29b9a208" +
    "17580ca517e9632f3fe05f212a83c6c1c8fa067da353c1e52086c49261197a00c90ae5a3f1e1" +
    "88c22752d09798272b8fca3c2e2f3a820da25b8eac02e0829b597848330866044242d3901cc5" +
    "06a5229dbe28b393c0cd7735e528a429be1bb4781e3c222f1b9d6385bfcc57495063ddd69a3e" +
    "771e1433bea2d8e54d4bca813edd66797edec4fc34649c40ac7c6ddd247d83f853c84637c0ac" +
    "f68fa2a5eca11cc7e8b8bab3830c6c623bb58ad63ef0a8af50fdfcfe0fd78d7a24d9f946523a" +
    "aea93c6d0bd769515738de849b3593d164d0a2c8d800eeb2ddb4bc6347c3e43876f6ccfd14fc" +
    "115c9ff3ddc774321328f31fb91ac51aa1fdced588982d11b754d59ca24da516d47855ba821b" +
    "7a012a27c36f3bbf2b627088f7de471af5f7fd377fe2ba32b016080c5bbbb2643175c60848d1" +
    "0972f159a61fd0aa51c308ddef6b7b56189869b57ba4e4a481a3e376fde52b1ba2181e7b2986" +
    "a5f4dc53a52a7b6b0ec641856cc60b7b06c8210e1e6221db4bd1cb95a1447e2f844401593d63" +
    "51555e7fcd41629f3fb992cc370cd87f6b655e5049e8a0352f7ff8b9ec94f07fc0f96d6e9583" +
    "61e868b1b9678d7041264e289b1fc5e2fc68c6208d8d81aa38ab6d25c05e3df68cf3448b6a62" +
    "9fd57216372961adb7005d85dcd7d023011f7a6af57f622a9a2b3767fe68f747ac4c82a5b0a4" +
    "03d3e36f02e7f83bcff63a73032525c99828e7bb1e43e911bd4405126e048784ace85e1d0d12" +
    "a4609169ba9160aae8b44bed99e7cd19c3f58abe26e38d1c1ade0512e4469e2960e453cd55ba" +
    "b7bceac04ddd398ac2a6dca0c81f7ef17881c11a3623e001720ffe598d22e61d1f272aca7b9d" +
    "263e65ce1014fe6a946e03884d56e43ed27c2b2ebc80d974aac127cd6aeb15dc9485ef1245f7" +
    "b8026ba4aadbfdaad25c82290f842bc81553fd3e38d33621f10e3256fe7556e8e8ab6c5f042b" +
    "152d2db26905752300aafa7088595152fef2032831455e606d7476899399a3aab6bdbfc6e6ea" +
    "f8fc000105082429394367707d8588919e9fa1a6b1b7d4d7d8e9f7fe2a617e84a4e2050c0d18" +
    "2632353b487e848b95a1a2a3a8b3b9c6fc00000000001630364b";
  const out = new Uint8Array(ML_DSA_44_SIG_BYTES);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
})();

// ─── Narration for the leaves whose occurrence teaches something ───────────

const narrSeed: StepDocumentation = {
  name: "The seed ξ — the entire key pair, in 32 bytes",
  summary:
    "Edit these and every byte of both keys changes. Nothing else about the key pair is chosen.",
  detail: `## A key pair is a seed

The public key is 1312 bytes and the private key 2560, and both are a
deterministic function of these 32. That is why an ML-DSA private key can be
stored as just its seed.

A real implementation draws the seed from the operating system. Fixing it here
is what makes the trace reproducible, and lets you change one byte and watch
the whole key pair change with it.`,
  references: ["FIPS 204 Algorithm 1 — ML-DSA.KeyGen", "FIPS 204 Algorithm 6"],
};

const narrKl: StepDocumentation = {
  name: "The parameter bytes k = 4, l = 4",
  summary: "Appended to the seed before hashing, so ML-DSA-44, -65 and -87 never share a key pair.",
  detail: `## Two bytes of domain separation

The seed is hashed as \`ξ ‖ k ‖ l\`, not as \`ξ\` alone. k and l are the matrix
dimensions, which are what make this ML-DSA-44 rather than -65 or -87.

Feeding them into the hash guarantees that the same seed gives three unrelated
key pairs at the three security levels. Without them, a seed reused across
levels would give keys with a shared derivation.

They are also a version marker. The round-3 draft of the scheme hashed \`ξ\`
alone, and an implementation that still does gets every key wrong from the
first byte: ρ differs, so the matrix differs, so everything differs.`,
  references: ["FIPS 204 Algorithm 6 — ML-DSA.KeyGen_internal, step 1"],
};

const narrSeeds: StepDocumentation = {
  name: "Split into ρ, ρ′ and K",
  summary:
    "128 bytes, cut three ways: ρ is published, ρ′ makes the secret, and K is kept for signing.",
  detail: `## One hash, three fates

- **ρ** (32 bytes) generates the public matrix A. It is copied into the public
  key, so anyone can regenerate A from it. A itself, sixteen polynomials and
  16 KB, is never stored.
- **ρ′** (64 bytes) generates the secret vectors s1 and s2.
- **K** (32 bytes) goes into the private key and is used only when signing, to
  derive each signature's mask.`,
  references: ["FIPS 204 Algorithm 6 — ML-DSA.KeyGen_internal, step 1"],
};

const narrT1Encode: StepDocumentation = {
  name: "Pack t1 at 10 bits per coefficient",
  summary:
    "Ten, not thirteen: Power2Round removed the low 13 of t's 23 bits, and this packs the 10 that are left.",
  detail: `## Why the width is 10

A coefficient of t needs 23 bits, because q does. Power2Round, the step above,
kept only the top \`23 − d = 23 − 13 = 10\` of them as t1, and moved the low 13
into t0, which stays in the private key. So the public key stores 10 bits per
coefficient.

That is the whole point of the split: the public key shrinks from 2,976 bytes
to 1,312. The verifier never learns t0, and the hint in each signature is what
lets it cope without it.`,
  references: ["FIPS 204 Algorithm 22 — pkEncode", "FIPS 204 Algorithm 35 — Power2Round"],
};

const narrMessage: StepDocumentation = {
  name: "The message M",
  summary:
    "What the signature claims was signed. Change one byte and the signature no longer verifies.",
  detail: `## The message is an editable leaf, not the input

Verification's input is the signature, because the signature has a fixed width
and the message does not. The message sits here instead, beside the seed.

Edit it and the verdict turns to invalid: the message is hashed into μ, μ into
the recomputed challenge, and the challenge no longer matches the one inside
the signature.`,
  references: ["FIPS 204 Algorithm 3 — ML-DSA.Verify"],
};

const narrPkSplit: StepDocumentation = {
  name: "Parse the public key into ρ and t1",
  summary: "All a verifier ever holds: the matrix seed and the high bits of t.",
  detail: `## The verifier's whole knowledge

The verifier gets the public key and nothing else from key generation. The key
generation above is in this trace only because it is teaching; a real verifier
is never in the same room as one.

ρ regenerates the matrix A. t1 is t with its low 13 bits removed, which is why
the signature has to carry a hint.`,
  references: ["FIPS 204 Algorithm 23 — pkDecode"],
};

const narrSigSplit: StepDocumentation = {
  name: "Parse the signature into c̃, z and h",
  summary: "32 bytes of challenge seed, 2304 bytes of response, 84 bytes of hint — 2420 in all.",
  detail: `## Three parts, three jobs

- **c̃** is the challenge seed: a hash the signer made of its commitment w1 and
  the message. Verification succeeds only if it can make the same hash.
- **z** is the response, \`y + c·s1\`: the signer's random mask, shifted by the
  secret. It is small enough to reveal nothing about s1, which is why the
  signer threw away every candidate whose z came out too large.
- **h** is the hint: which coefficients the verifier's rounding would get wrong
  without t0, so it can correct them.`,
  references: ["FIPS 204 Algorithm 27 — sigDecode"],
};

const narrZBound: StepDocumentation = {
  name: "γ1 − β — how large z may be",
  summary:
    "Computed from γ1 and β rather than stored, so editing either one moves the bound with it.",
  detail: `## Where the bound comes from

z is \`y + c·s1\`. The mask y is drawn below γ1, and \`c·s1\` can move a
coefficient by at most β = τ·η. A z inside \`γ1 − β\` is one that could have come
from any secret, so it reveals nothing. A larger one is refused, by the signer
when it makes candidates and by the verifier here.

This subtraction is a visible step on purpose. A second constant holding
130,994 would go stale the moment γ1 or β was edited.`,
  references: ["FIPS 204 Algorithm 8 — the ‖z‖∞ < γ1 − β check"],
};

const narrZLower: StepDocumentation = {
  name: "γ1 − 1 — the low end of z's packing range",
  summary: "z is packed as a value in [−(γ1 − 1), γ1], so its range follows γ1 too.",
  detail: `## The range of the packed response

The signature stores each coefficient of z as an 18-bit number standing for a
value from −(γ1 − 1) up to γ1. That range is exactly 2γ1 values, which fills the
18 bits with nothing spare.

Like the norm bound, this is derived from γ1 rather than stored, so the two can
never disagree.`,
  references: ["FIPS 204 Algorithm 27 — sigDecode, BitUnpack(z, γ1 − 1, γ1)"],
};

const narrTwoD: StepDocumentation = {
  name: "2^d = 8192",
  summary: "Shifts t1 back up by the 13 bits Power2Round removed.",
  detail: `## Rebuilding t, approximately

The public key holds t1, the high bits of t. Multiplying by \`2^13\` puts them
back in place, giving t minus its low part t0. The verifier computes with that
approximation, and the error it leaves is what the hint corrects.`,
  references: ["FIPS 204 Algorithm 8 — ML-DSA.Verify_internal, step 9"],
};

const narrRecomputed: StepDocumentation = {
  name: "c̃′ — the verifier's own challenge",
  summary:
    "The hash the signer made, remade from public data. Equal to c̃ only if the signer held the secret key.",
  detail: `## The signature equation, in one hash

The signer hashed μ (the message, bound to this public key) together with its
commitment w1. The verifier has neither the secret nor w1, but it can rebuild
w1 from the matrix, z, t1 and the hint. If the rebuilt w1 is the signer's, this
hash reproduces c̃ exactly; if anything is off by one bit, it comes out as an
unrelated 32 bytes.`,
  references: ["FIPS 204 Algorithm 8 — ML-DSA.Verify_internal, step 12"],
};

// ─── Embedding ─────────────────────────────────────────────────────────────

/**
 * The wire for each editable constant, as seen from one scope. Port flow cannot
 * cross a group boundary, so each scope that needs a constant loads its own
 * copy from aux; this record is how a body is told where its copies are.
 */
export type MlDsaConstants = {
  readonly q: PortBinding;
  readonly gamma1: PortBinding;
  readonly gamma2: PortBinding;
  readonly omega: PortBinding;
  /** γ1 − β, the largest z may be (exclusive). */
  readonly zBound: PortBinding;
  /** γ1 − 1, the low end of z's packing range. */
  readonly zLower: PortBinding;
};

/** Everything a body needs to know about the spec it is being built into. */
export type MlDsaEmbedding = {
  /** Prepended to every node id this body emits. */
  readonly prefix: string;
  readonly q: PortBinding;
};

const nid = (ctx: MlDsaEmbedding, id: string): string => `${ctx.prefix}${id}`;
const own = (ctx: MlDsaEmbedding, id: string, portName = "output"): PortBinding =>
  port(nid(ctx, id), portName);

/** An `aux-load-bytes@1` for one entry of `cipherConstants`. */
const auxConstant = (id: string, auxName: string): StepNode => ({
  kind: "step",
  id,
  type: "aux-load-bytes@1",
  params: { auxName, byteLength: ML_DSA_COEFF_BYTES },
});

/** A `constant-load@1` of one four-byte coefficient. */
const coeffConstant = (id: string, value: number, narration?: StepDocumentation): StepNode => ({
  kind: "step",
  id,
  type: "constant-load@1",
  params: { bytes: [...mlDsaCoeffBytes(value)] },
  ...(narration === undefined ? {} : { narrationOverride: narration }),
});

/**
 * The editable constants for one scope, plus the two bounds derived from them.
 * `full: false` gives q alone, which is all key generation reads.
 */
export const mlDsaConstantNodes = (
  prefix: string,
  full: boolean,
): { readonly nodes: StepNode[]; readonly bindings: MlDsaConstants } => {
  const id = (s: string) => `${prefix}${s}`;
  const out = (s: string) => port(id(s), "output");
  const nodes: StepNode[] = [auxConstant(id("q"), MLDSA_AUX.q)];
  if (full) {
    nodes.push(
      auxConstant(id("gamma1"), MLDSA_AUX.gamma1),
      auxConstant(id("gamma2"), MLDSA_AUX.gamma2),
      auxConstant(id("beta"), MLDSA_AUX.beta),
      auxConstant(id("omega"), MLDSA_AUX.omega),
      coeffConstant(id("one"), 1),
      {
        kind: "step",
        id: id("z-lower"),
        type: "sub@1",
        params: {},
        portInputs: { a: out("gamma1"), b: out("one") },
        narrationOverride: narrZLower,
      },
      {
        kind: "step",
        id: id("z-bound"),
        type: "sub@1",
        params: {},
        portInputs: { a: out("gamma1"), b: out("beta") },
        narrationOverride: narrZBound,
      },
    );
  }
  return {
    nodes,
    bindings: {
      q: out("q"),
      gamma1: out("gamma1"),
      gamma2: out("gamma2"),
      omega: out("omega"),
      zBound: out("z-bound"),
      zLower: out("z-lower"),
    },
  };
};

// ─── Small builders ────────────────────────────────────────────────────────

const concatNode = (
  ctx: MlDsaEmbedding,
  id: string,
  parts: readonly PortBinding[],
  narration?: StepDocumentation,
): StepNode => {
  const portInputs: Record<string, PortBinding> = {};
  parts.forEach((p, i) => {
    portInputs[`input${i}`] = p;
  });
  return {
    kind: "step",
    id: nid(ctx, id),
    type: "concat@1",
    params: { inputCount: parts.length },
    portInputs,
    ...(narration === undefined ? {} : { narrationOverride: narration }),
  };
};

const splitNode = (
  ctx: MlDsaEmbedding,
  id: string,
  input: PortBinding,
  widths: readonly number[],
  narration?: StepDocumentation,
): StepNode => ({
  kind: "step",
  id: nid(ctx, id),
  type: "split-bytes@1",
  params: { widths: [...widths] },
  portInputs: { input },
  ...(narration === undefined ? {} : { narrationOverride: narration }),
});

/** H = SHAKE256 squeezed to `outBytes`. */
const hashNode = (
  ctx: MlDsaEmbedding,
  id: string,
  input: PortBinding,
  outBytes: number,
  narration?: StepDocumentation,
): StepNode => ({
  kind: "step",
  id: nid(ctx, id),
  type: "ml-dsa.hash-h@1",
  params: { outBytes },
  portInputs: { input },
  ...(narration === undefined ? {} : { narrationOverride: narration }),
});

const nttNode = (ctx: MlDsaEmbedding, id: string, input: PortBinding, inverse = false) => ({
  kind: "step" as const,
  id: nid(ctx, id),
  type: inverse ? "ml-dsa.intt@1" : "ml-dsa.ntt@1",
  params: {},
  portInputs: { input },
});

/** An element-wise Z_q step over two vectors. */
const vecNode = (
  ctx: MlDsaEmbedding,
  id: string,
  type: "zq-vec-add@1" | "zq-vec-sub@1" | "zq-vec-mul@1",
  a: PortBinding,
  b: PortBinding,
): StepNode => ({
  kind: "step",
  id: nid(ctx, id),
  type,
  params: { ...VEC },
  portInputs: { a, b, modulus: ctx.q },
});

/**
 * `Â ∘ v̂` in the transformed domain: k rows, each `Σⱼ Â[r][j] ∘ v̂[j]`.
 *
 * **All k·l products are ONE frame.** Â is k·l polynomials row by row; v̂
 * repeated k times lines up under it exactly, and because this prime's
 * transform runs all eight layers, multiplication there is plain element-wise —
 * so a single `zq-vec-mul@1` computes all sixteen products at once. That is the
 * contrast with ML-KEM, whose degree-1 base case needs one multiply per pair and
 * per entry. Each row's sum is then a short chain of additions.
 *
 * Shared by key generation (Â·ŝ1), verification (Â·ẑ) and, in P4, signing
 * (Â·ŷ).
 */
export const matVecNodes = (
  ctx: MlDsaEmbedding,
  options: { readonly id: string; readonly matrix: PortBinding; readonly vector: PortBinding },
): { readonly nodes: StepNode[]; readonly output: PortBinding } => {
  const { id, matrix, vector } = options;
  const nodes: StepNode[] = [
    concatNode(
      ctx,
      `${id}.rep`,
      Array.from({ length: K }, () => vector),
    ),
    vecNode(ctx, `${id}.mul`, "zq-vec-mul@1", matrix, own(ctx, `${id}.rep`)),
    splitNode(
      ctx,
      `${id}.split`,
      own(ctx, `${id}.mul`),
      Array.from({ length: K * L }, () => ML_DSA_POLY_BYTES),
    ),
  ];
  const rows: PortBinding[] = [];
  for (let r = 0; r < K; r++) {
    let running = own(ctx, `${id}.split`, `output${r * L}`);
    for (let j = 1; j < L; j++) {
      const sumId = `${id}.r${r}.sum${j}`;
      nodes.push(
        vecNode(ctx, sumId, "zq-vec-add@1", running, own(ctx, `${id}.split`, `output${r * L + j}`)),
      );
      running = own(ctx, sumId);
    }
    rows.push(running);
  }
  nodes.push(concatNode(ctx, id, rows));
  return { nodes, output: own(ctx, id) };
};

/** `ml-dsa.bit-pack@1` with its range on two wires. */
const bitPackNode = (
  ctx: MlDsaEmbedding,
  id: string,
  a: PortBinding,
  lower: PortBinding,
  upper: PortBinding,
): StepNode => ({
  kind: "step",
  id: nid(ctx, id),
  type: "ml-dsa.bit-pack@1",
  params: { ...VEC },
  portInputs: { a, lower, upper, modulus: ctx.q },
});

// ─── ML-DSA.KeyGen_internal (FIPS 204 Algorithm 6) ─────────────────────────

/**
 * Key generation from the 32-byte seed ξ. Returns both halves; the caller
 * decides which to keep.
 */
export const mlDsaKeyGenNodes = (
  ctx: MlDsaEmbedding,
  seed: PortBinding,
): { readonly nodes: StepNode[]; readonly pk: PortBinding; readonly sk: PortBinding } => {
  const nodes: StepNode[] = [];
  const half = 2 ** (ML_DSA_D - 1);

  // (ρ, ρ′, K) ← H(ξ ‖ k ‖ l, 128)
  nodes.push(
    {
      kind: "step",
      id: nid(ctx, "kl"),
      type: "constant-load@1",
      params: { bytes: [K, L] },
      narrationOverride: narrKl,
    },
    concatNode(ctx, "h-in", [seed, own(ctx, "kl")]),
    hashNode(ctx, "h", own(ctx, "h-in"), 128),
    splitNode(ctx, MLDSA_SEEDS_ID, own(ctx, "h"), [32, 64, 32], narrSeeds),
  );
  const rho = own(ctx, MLDSA_SEEDS_ID, "output0");
  const rhoPrime = own(ctx, MLDSA_SEEDS_ID, "output1");
  const key = own(ctx, MLDSA_SEEDS_ID, "output2");

  // Â ← ExpandA(ρ);  (s1, s2) ← ExpandS(ρ′)
  nodes.push(
    {
      kind: "step",
      id: nid(ctx, "A"),
      type: "ml-dsa.expand-a@1",
      params: { ...VEC, k: K, l: L },
      portInputs: { input: rho, modulus: ctx.q },
    },
    {
      kind: "step",
      id: nid(ctx, "s"),
      type: "ml-dsa.expand-s@1",
      params: { ...VEC, k: K, l: L, eta: ML_DSA_44_ETA },
      portInputs: { input: rhoPrime, modulus: ctx.q },
    },
  );
  const s1 = own(ctx, "s", "s1");
  const s2 = own(ctx, "s", "s2");

  // t ← NTT⁻¹(Â ∘ NTT(s1)) + s2
  nodes.push(nttNode(ctx, "ntt.s1", s1));
  const product = matVecNodes(ctx, {
    id: "As1",
    matrix: own(ctx, "A"),
    vector: own(ctx, "ntt.s1"),
  });
  nodes.push(
    ...product.nodes,
    nttNode(ctx, "intt.As1", product.output, true),
    vecNode(ctx, "t", "zq-vec-add@1", own(ctx, "intt.As1"), s2),
  );

  // (t1, t0) ← Power2Round(t);  pk ← ρ ‖ SimpleBitPack(t1, 2^10 − 1)
  nodes.push(
    {
      kind: "step",
      id: nid(ctx, "p2r"),
      type: "ml-dsa.power2round@1",
      params: { ...VEC, d: ML_DSA_D },
      portInputs: { a: own(ctx, "t"), modulus: ctx.q },
    },
    {
      kind: "step",
      id: nid(ctx, "t1.enc"),
      type: "zq-byte-encode@1",
      params: { ...VEC, d: T1_BITS },
      portInputs: { a: own(ctx, "p2r", "high"), modulus: ctx.q },
      narrationOverride: narrT1Encode,
    },
    concatNode(ctx, MLDSA_PK_ID, [rho, own(ctx, "t1.enc")]),
    // tr ← H(pk, 64)
    hashNode(ctx, "tr", own(ctx, MLDSA_PK_ID), 64),
  );

  // sk ← ρ ‖ K ‖ tr ‖ BitPack(s1, η, η) ‖ BitPack(s2, η, η) ‖ BitPack(t0, 2^12 − 1, 2^12)
  nodes.push(
    coeffConstant(nid(ctx, "eta"), ML_DSA_44_ETA),
    coeffConstant(nid(ctx, "t0-lo"), half - 1),
    coeffConstant(nid(ctx, "t0-hi"), half),
    bitPackNode(ctx, "s1.pack", s1, own(ctx, "eta"), own(ctx, "eta")),
    bitPackNode(ctx, "s2.pack", s2, own(ctx, "eta"), own(ctx, "eta")),
    bitPackNode(ctx, "t0.pack", own(ctx, "p2r", "low"), own(ctx, "t0-lo"), own(ctx, "t0-hi")),
    concatNode(ctx, MLDSA_SK_ID, [
      rho,
      key,
      own(ctx, "tr"),
      own(ctx, "s1.pack"),
      own(ctx, "s2.pack"),
      own(ctx, "t0.pack"),
    ]),
  );

  return { nodes, pk: own(ctx, MLDSA_PK_ID), sk: own(ctx, MLDSA_SK_ID) };
};

/**
 * Key generation as a default-collapsed group: ξ in, `pk ‖ sk` out. Its own q
 * leaf lives inside because port flow stops at the group boundary.
 */
export const mlDsaKeyGenGroup = (seed: PortBinding): StepNode => {
  const prefix = `${MLDSA_KEYGEN_ID}.`;
  const constants = mlDsaConstantNodes(prefix, false);
  const ctx: MlDsaEmbedding = { prefix, q: constants.bindings.q };
  const keys = mlDsaKeyGenNodes(ctx, port(MLDSA_KEYGEN_ID, "in"));
  return {
    kind: "group",
    id: MLDSA_KEYGEN_ID,
    label: "Key generation — 32 seed bytes → the key pair",
    defaultCollapsed: true,
    seedInput: seed,
    bodyOutput: own(ctx, "pair"),
    children: [...constants.nodes, ...keys.nodes, concatNode(ctx, "pair", [keys.pk, keys.sk])],
  };
};

/** Seed leaf → key-generation group → `(pk, sk)`. Shared with P4's signing spec. */
export const mlDsaKeyMaterialNodes = (
  seed: Uint8Array,
): { readonly nodes: StepNode[]; readonly pk: PortBinding; readonly sk: PortBinding } => ({
  nodes: [
    {
      kind: "step",
      id: MLDSA_SEED_ID,
      type: "constant-load@1",
      params: { bytes: [...seed] },
      narrationOverride: narrSeed,
    },
    mlDsaKeyGenGroup(port(MLDSA_SEED_ID, "output")),
    {
      kind: "step",
      id: MLDSA_KEYPAIR_ID,
      type: "split-bytes@1",
      params: { widths: [ML_DSA_44_PK_BYTES, ML_DSA_44_SK_BYTES] },
      portInputs: { input: port(MLDSA_KEYGEN_ID, "out") },
    },
  ],
  pk: port(MLDSA_KEYPAIR_ID, "output0"),
  sk: port(MLDSA_KEYPAIR_ID, "output1"),
});

// ─── ML-DSA.Verify_internal (FIPS 204 Algorithm 8) ─────────────────────────

/**
 * Verification of `signature` on the formatted message `mPrime` under `pk`.
 * Output: one byte, 1 (valid) or 0 (invalid), from `ml-dsa.verdict@1`.
 */
export const mlDsaVerifyNodes = (
  ctx: MlDsaEmbedding,
  c: MlDsaConstants,
  options: {
    readonly pk: PortBinding;
    readonly mPrime: PortBinding;
    readonly signature: PortBinding;
  },
): { readonly nodes: StepNode[]; readonly verdict: PortBinding } => {
  const { pk, mPrime, signature } = options;
  const nodes: StepNode[] = [];

  // (ρ, t1) ← pkDecode(pk);  (c̃, z, h) ← sigDecode(σ)
  nodes.push(
    splitNode(ctx, "pk-split", pk, [32, K * T1_POLY_BYTES], narrPkSplit),
    {
      kind: "step",
      id: nid(ctx, "t1"),
      type: "zq-byte-decode@1",
      params: { ...VEC, d: T1_BITS },
      portInputs: { a: own(ctx, "pk-split", "output1"), modulus: c.q },
    },
    splitNode(
      ctx,
      MLDSA_SIG_SPLIT_ID,
      signature,
      [32, L * Z_POLY_BYTES, ML_DSA_44_OMEGA + K],
      narrSigSplit,
    ),
    {
      kind: "step",
      id: nid(ctx, "z"),
      type: "ml-dsa.bit-unpack@1",
      params: { ...VEC },
      portInputs: {
        a: own(ctx, MLDSA_SIG_SPLIT_ID, "output1"),
        lower: c.zLower,
        upper: c.gamma1,
        modulus: c.q,
      },
    },
    // A malformed hint is a `valid = 0` flag and an all-zero hint, not a throw:
    // everything below still runs, and the verdict reports it.
    {
      kind: "step",
      id: nid(ctx, MLDSA_HINT_ID),
      type: "ml-dsa.hint-unpack@1",
      params: { ...VEC },
      portInputs: { input: own(ctx, MLDSA_SIG_SPLIT_ID, "output2"), omega: c.omega },
    },
  );
  const cTilde = own(ctx, MLDSA_SIG_SPLIT_ID, "output0");
  const z = own(ctx, "z");

  // Â ← ExpandA(ρ);  tr ← H(pk, 64);  μ ← H(tr ‖ M′, 64)
  nodes.push(
    {
      kind: "step",
      id: nid(ctx, "A"),
      type: "ml-dsa.expand-a@1",
      params: { ...VEC, k: K, l: L },
      portInputs: { input: own(ctx, "pk-split", "output0"), modulus: c.q },
    },
    hashNode(ctx, "tr", pk, 64),
    concatNode(ctx, "mu-in", [own(ctx, "tr"), mPrime]),
    hashNode(ctx, "mu", own(ctx, "mu-in"), 64),
  );

  // c ← SampleInBall(c̃)
  nodes.push({
    kind: "step",
    id: nid(ctx, "c"),
    type: "ml-dsa.sample-in-ball@1",
    params: { ...VEC, tau: ML_DSA_44_TAU },
    portInputs: { input: cTilde, modulus: c.q },
  });

  // w′approx ← NTT⁻¹(Â ∘ NTT(z) − NTT(c) ∘ NTT(t1 · 2^d))
  nodes.push(nttNode(ctx, "ntt.z", z));
  const az = matVecNodes(ctx, { id: "Az", matrix: own(ctx, "A"), vector: own(ctx, "ntt.z") });
  nodes.push(
    ...az.nodes,
    nttNode(ctx, "ntt.c", own(ctx, "c")),
    coeffConstant(nid(ctx, "two-d"), 2 ** ML_DSA_D, narrTwoD),
    {
      kind: "step",
      id: nid(ctx, "t1.scaled"),
      type: "zq-vec-mul-scalar@1",
      params: { ...VEC },
      portInputs: { a: own(ctx, "t1"), scalar: own(ctx, "two-d"), modulus: c.q },
    },
    nttNode(ctx, "ntt.t1", own(ctx, "t1.scaled")),
    concatNode(
      ctx,
      "c.rep",
      Array.from({ length: K }, () => own(ctx, "ntt.c")),
    ),
    vecNode(ctx, "ct1", "zq-vec-mul@1", own(ctx, "c.rep"), own(ctx, "ntt.t1")),
    vecNode(ctx, "w-hat", "zq-vec-sub@1", az.output, own(ctx, "ct1")),
    nttNode(ctx, "w-approx", own(ctx, "w-hat"), true),
  );

  // w1′ ← UseHint(h, w′approx);  c̃′ ← H(μ ‖ w1Encode(w1′), 32)
  nodes.push(
    {
      kind: "step",
      id: nid(ctx, "w1"),
      type: "ml-dsa.use-hint@1",
      params: { ...VEC },
      portInputs: {
        h: own(ctx, MLDSA_HINT_ID),
        r: own(ctx, "w-approx"),
        gamma2: c.gamma2,
        modulus: c.q,
      },
    },
    {
      kind: "step",
      id: nid(ctx, "w1.enc"),
      type: "ml-dsa.w1-encode@1",
      params: { ...VEC },
      portInputs: { a: own(ctx, "w1"), gamma2: c.gamma2, modulus: c.q },
    },
    concatNode(ctx, "c-in", [own(ctx, "mu"), own(ctx, "w1.enc")]),
    hashNode(ctx, MLDSA_RECOMPUTED_ID, own(ctx, "c-in"), 32, narrRecomputed),
  );

  // return [[ ‖z‖∞ < γ1 − β ]] and [[ c̃ = c̃′ ]] — and the hint was well formed.
  nodes.push(
    {
      kind: "step",
      id: nid(ctx, MLDSA_Z_NORM_ID),
      type: "zq-inf-norm-below@1",
      params: { ...VEC },
      portInputs: { a: z, bound: c.zBound, modulus: c.q },
    },
    {
      kind: "step",
      id: nid(ctx, MLDSA_VERDICT_ID),
      type: "ml-dsa.verdict@1",
      params: {},
      portInputs: {
        // c̃ from the SIGNATURE against the verifier's own c̃′ — wiring both to
        // the same source would accept every signature that parses.
        challenge: cTilde,
        recomputed: own(ctx, MLDSA_RECOMPUTED_ID),
        normOk: own(ctx, MLDSA_Z_NORM_ID),
        hintValid: own(ctx, MLDSA_HINT_ID, "valid"),
      },
    },
  );

  return { nodes, verdict: own(ctx, MLDSA_VERDICT_ID) };
};

/** What a verification spec is built around: the key pair's seed and the message. */
export type MlDsaVerifyOptions = {
  readonly seed?: Uint8Array;
  readonly message?: Uint8Array;
  /** The context string, at most 255 bytes. Empty by default. */
  readonly context?: Uint8Array;
};

/**
 * ML-DSA-44 verification: signature in, verdict out.
 *
 * The key pair is generated in the spec from `seed`; the message and context
 * are the `message` leaf and the `m-prime` leaf's param.
 */
export const buildMlDsa44VerifySpec = (options: MlDsaVerifyOptions = {}): CipherSpec => {
  const seed = options.seed ?? ML_DSA_44_DEFAULT_SEED;
  const message = options.message ?? ML_DSA_44_DEFAULT_MESSAGE;
  const context = options.context ?? new Uint8Array(0);

  const constants = mlDsaConstantNodes("", true);
  const ctx: MlDsaEmbedding = { prefix: "", q: constants.bindings.q };
  const material = mlDsaKeyMaterialNodes(seed);

  const steps: StepNode[] = [
    ...constants.nodes,
    ...material.nodes,
    {
      kind: "step",
      id: MLDSA_MESSAGE_ID,
      type: "constant-load@1",
      params: { bytes: [...message] },
      narrationOverride: narrMessage,
    },
    // M′ ← 0 ‖ |ctx| ‖ ctx ‖ M — the "pure" ML-DSA prefix (FIPS 204 Algorithm 3).
    {
      kind: "step",
      id: MLDSA_MPRIME_ID,
      type: "ml-dsa.format-message@1",
      params: { context: [...context] },
      portInputs: { input: port(MLDSA_MESSAGE_ID, "output") },
    },
  ];
  const verify = mlDsaVerifyNodes(ctx, constants.bindings, {
    pk: material.pk,
    mPrime: port(MLDSA_MPRIME_ID, "output"),
    signature: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
  });
  steps.push(...verify.nodes);

  return {
    id: "ml-dsa-44-verify@1",
    name: "ML-DSA-44 verification",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    cipherConstants: { ...CONSTANTS },
    steps,
    outputFrom: verify.verdict,
  };
};
