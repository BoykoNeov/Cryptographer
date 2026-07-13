/**
 * KMAC128 / KMAC256 + KMACXOF128 / KMACXOF256 — the Keccak keyed MAC of NIST
 * SP 800-185, 2026-07-13. The app's **first keyed hash**.
 *
 * **What KMAC is.** A message authentication code built directly on cSHAKE:
 *
 * ```
 *   KMAC(K, X, L, S) = cSHAKE( newX, L, "KMAC", S )
 *     where newX = bytepad(encode_string(K), rate) || X || right_encode(L)
 * ```
 *
 * So KMAC is cSHAKE with the function name **fixed to `"KMAC"`** (never
 * user-editable — that is the domain tag that separates KMAC from every other
 * cSHAKE use), the message wrapped with a length-prefixed **key block** in front
 * and a `right_encode(L)` **length commitment** behind, and `S` left as the
 * user's optional customization. Because `N = "KMAC"` is non-empty, KMAC never
 * takes the SHAKE-reduction branch — its domain byte is always `0x04`.
 *
 * **KMACXOF** is identical except it appends `right_encode(0)` instead of
 * `right_encode(L)`. The `0` signals "no committed output length", turning KMAC
 * into an arbitrary-length XOF (the output can be squeezed to any length like a
 * plain SHAKE). That single value is the *only* KMAC↔KMACXOF difference.
 *
 * **Why the length commitment matters.** `right_encode(L)` binds the requested
 * output length (in **bits**) into the hashed input, so a 256-bit tag and the
 * first 256 bits of a 512-bit tag are guaranteed different — an attacker can't
 * truncate or extend a tag by reinterpreting its length. A consequence for
 * testing: KMAC (unlike SHAKE/cSHAKE) is **not** prefix-stable, so every output
 * length must be verified independently.
 *
 * **The key travels through aux.** KMAC is the first hash to consume a key. The
 * app seeds the key into `aux["key"]` (the same channel ciphers use), and the
 * spec reads it back with `aux-load-bytes@1` — so the key is a runtime input,
 * not baked into the spec. Its length is **variable** (SP 800-185 places no
 * upper bound on the key): the key field is the source of truth, and the number
 * of bytes the user types drives `keyByteLength`, which the builder threads into
 * `inputs.key.byteLength`, the `key.load` aux-read width, and (via
 * `encode_string`) the key's `left_encode(8·len)` bit-length prefix. The NIST
 * sample key size (32 bytes) is the default, not a limit.
 *
 * **KAT.** Byte-equal to the NIST SP 800-185 published KMAC / KMACXOF samples
 * and to pycryptodome (`tests/kmac-kat.test.ts`), driven through the runtime
 * with the key seeded into aux exactly as the app does.
 *
 * **References:**
 *   - NIST SP 800-185 §4 (KMAC), §4.3.1 (KMACXOF)
 *   - NIST SP 800-185 §3.3 (cSHAKE), §2.3 (encode_string / bytepad / right_encode)
 */

import type { CipherSpec, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { RC_BYTES, S0_BYTES, port } from "./keccak-f";
import { buildSpongeNarration, buildSpongeSqueeze } from "./sponge";

// ─── Variants + parameters ──────────────────────────────────────────────────

export type KmacVariant = "kmac128" | "kmac256" | "kmacxof128" | "kmacxof256";

/** Sponge rate in bytes per variant (128-strength = 168, 256-strength = 136). */
const RATE_BY_VARIANT: Record<KmacVariant, number> = {
  kmac128: 168,
  kmacxof128: 168,
  kmac256: 136,
  kmacxof256: 136,
};

const DISPLAY_NAME: Record<KmacVariant, string> = {
  kmac128: "KMAC128",
  kmac256: "KMAC256",
  kmacxof128: "KMACXOF128",
  kmacxof256: "KMACXOF256",
};

/** True for the XOF variants (append right_encode(0) instead of right_encode(L)). */
const IS_XOF: Record<KmacVariant, boolean> = {
  kmac128: false,
  kmac256: false,
  kmacxof128: true,
  kmacxof256: true,
};

/** The fixed cSHAKE function-name string for every KMAC variant: ASCII "KMAC". */
const KMAC_NAME_BYTES = [0x4b, 0x4d, 0x41, 0x43]; // "KMAC"

/** Default MAC key length in bytes (the NIST SP 800-185 sample key size). v1
 *  fixes this; the key *bytes* are the editable runtime input. */
export const KMAC_KEY_BYTES = 32;

// ─── Head-step narration ────────────────────────────────────────────────────

const narrConstName: StepDocumentation = {
  name: 'Function name N = "KMAC" (fixed)',
  summary: 'The literal ASCII string "KMAC" — the domain tag that makes this a KMAC.',
  detail: `Every KMAC variant sets cSHAKE's function name \`N\` to the fixed ASCII
string \`"KMAC"\` (bytes \`4B 4D 41 43\`). This is *not* user-editable — it is the
domain-separation tag that distinguishes KMAC from every other cSHAKE use, so two
different SP 800-185 functions can never collide. Only the customization string
\`S\` is the caller's to choose.`,
  references: ["NIST SP 800-185 §4 (KMAC)"],
};

const narrConstS = (S: Uint8Array): StepDocumentation => ({
  name: "Customization string S (raw bytes)",
  summary: `The optional user customization string S (${S.length} bytes).`,
  detail: `\`S\` is the caller's optional domain-separation string for this MAC —
distinct KMAC instances (e.g. different protocols using the same key) pick
different \`S\` so their tags never coincide. Empty \`S\` is the common case.`,
  references: ["NIST SP 800-185 §4 (KMAC)"],
});

const narrConcatName: StepDocumentation = {
  name: 'Concatenate encode_string("KMAC") ‖ encode_string(S)',
  summary: "Join the two length-prefixed cSHAKE customization strings.",
  detail: `KMAC delegates to cSHAKE with \`N = "KMAC"\` and the user's \`S\`. This
joins their length-prefixed encodings into the pair that \`bytepad\` aligns into
the cSHAKE customization block.`,
  references: ["NIST SP 800-185 §3.3 (cSHAKE)", "NIST SP 800-185 §4 (KMAC)"],
};

const narrBytepadName = (rate: number): StepDocumentation => ({
  name: `bytepad(…, ${rate}) — the cSHAKE customization block`,
  summary: `Align the "KMAC" ‖ S customization to a whole ${rate}-byte rate block.`,
  detail: `This is cSHAKE's customization prefix —
\`bytepad(encode_string("KMAC") ‖ encode_string(S), ${rate})\` — absorbed as whole
rate blocks before anything else. It is what makes the sponge compute *KMAC* and
not a plain SHAKE of the same bytes.`,
  references: ["NIST SP 800-185 §2.3.3 (bytepad)", "NIST SP 800-185 §4 (KMAC)"],
});

const narrKeyLoad: StepDocumentation = {
  name: "Load the MAC key K (from aux)",
  summary: "Read the secret key K that authenticates the message.",
  detail: `KMAC is a **keyed** function: the key \`K\` is what only the sender and
verifier know, so only they can produce or check a valid tag. The app supplies
\`K\` through the key field; it is read here from \`aux["key"]\` (the same channel
the block ciphers use for their key) — a runtime input, never baked into the
spec.`,
  references: ["NIST SP 800-185 §4 (KMAC)"],
};

const narrKeyEnc: StepDocumentation = {
  name: "encode_string(K) — length-prefix the key",
  summary: "Prefix the key with its bit-length so the key/message boundary is unambiguous.",
  detail: `The key is length-prefixed by its **bit** length
(\`left_encode(8·len(K)) ‖ K\`) just like the customization strings, so where the
key ends and the message begins is always recoverable.`,
  references: ["NIST SP 800-185 §2.3.2 (encode_string)"],
};

const narrKeyBytepad = (rate: number): StepDocumentation => ({
  name: `bytepad(encode_string(K), ${rate}) — the key block`,
  summary: `Align the encoded key to a whole ${rate}-byte rate block.`,
  detail: `The key block \`bytepad(encode_string(K), ${rate})\` is absorbed
**after** the cSHAKE customization block but **before** the message, on a fresh
rate boundary. Keeping the key in its own aligned block is what binds it cleanly
into the MAC.`,
  references: ["NIST SP 800-185 §2.3.3 (bytepad)", "NIST SP 800-185 §4 (KMAC)"],
});

const narrRightEncode = (variant: KmacVariant, outputLength: number): StepDocumentation => ({
  name: IS_XOF[variant]
    ? "right_encode(0) — no committed length (XOF)"
    : `right_encode(${outputLength * 8}) — commit the output length`,
  summary: IS_XOF[variant]
    ? "Append right_encode(0): the KMACXOF marker for arbitrary output length."
    : `Append right_encode(${outputLength} × 8): bind the ${outputLength}-byte output length into the tag.`,
  detail: IS_XOF[variant]
    ? `${DISPLAY_NAME[variant]} is the XOF variant: it appends \`right_encode(0)\`
instead of the output-length commitment, signalling that the output can be
squeezed to any length like a plain XOF. This single value is the only thing that
distinguishes KMACXOF from KMAC.`
    : `KMAC appends \`right_encode(L)\` where \`L\` is the output length **in
bits** (${outputLength} bytes × 8 = ${outputLength * 8}). Binding the length into
the hashed input makes KMAC **length-committing**: a ${outputLength}-byte tag is
not a prefix of a longer tag for the same key and message, so a tag can't be
truncated or extended by lying about its length.`,
  references: ["NIST SP 800-185 §2.3.1 (right_encode)", "NIST SP 800-185 §4 (KMAC)"],
});

const narrNewX: StepDocumentation = {
  name: "Assemble cSHAKE input: customization ‖ key block ‖ message ‖ length",
  summary: "Concatenate the four pieces the sponge absorbs.",
  detail: `The full pre-pad sponge input is
\`bytepad(encode_string("KMAC") ‖ encode_string(S), rate)\` ‖
\`bytepad(encode_string(K), rate)\` ‖ \`X\` ‖ \`right_encode(L)\`. The first two
are whole rate blocks, so the message \`X\` starts on a block boundary; the
length commitment rides on the end.`,
  references: ["NIST SP 800-185 §4 (KMAC)"],
};

const narrPad = (variant: KmacVariant, rate: number): StepDocumentation => ({
  name: "Pad + domain-separate (pad10*1, FIPS 202 §5.1)",
  summary: `Append the cSHAKE domain byte 0x04 and pad10*1 to a multiple of the ${rate}-byte rate.`,
  detail: `${DISPLAY_NAME[variant]} runs through cSHAKE, so it uses cSHAKE's
domain byte \`0x04\` (the two-bit \`00\` suffix + the padding's leading 1-bit),
zero-fills to a multiple of the ${rate}-byte rate, then sets the top bit of the
last byte. KMAC's \`N = "KMAC"\` is never empty, so it never takes the
SHAKE-reduction path — the domain is always \`0x04\`.`,
  references: ["FIPS 202 §5.1 (pad10*1)", "NIST SP 800-185 §3.3 (cSHAKE)"],
});

// ─── Spec builder ────────────────────────────────────────────────────────────

/**
 * Build a KMAC / KMACXOF spec. `S` is the (possibly empty) customization string;
 * `outputLength` drives the squeeze block count structurally and (for the
 * non-XOF variants) the `right_encode(L)` length commitment. `keyByteLength`
 * declares how many bytes to read from `aux["key"]` (default `KMAC_KEY_BYTES`).
 */
export const buildKmacSpec = (
  variant: KmacVariant,
  S: Uint8Array,
  outputLength: number,
  keyByteLength: number = KMAC_KEY_BYTES,
): CipherSpec => {
  const rate = RATE_BY_VARIANT[variant];
  const rightEncodeValue = IS_XOF[variant] ? 0 : outputLength * 8; // L in BITS

  const headSteps: StepNode[] = [
    // ─── cSHAKE customization block: bytepad(encode_string("KMAC") ‖ enc(S)) ─
    {
      kind: "step",
      id: "cust.N",
      type: "constant-load@1",
      params: { bytes: [...KMAC_NAME_BYTES] },
      narrationOverride: narrConstName,
    },
    {
      kind: "step",
      id: "cust.encN",
      type: "encode-string@1",
      params: {},
      portInputs: { input: port("cust.N", "output") },
    },
    {
      kind: "step",
      id: "cust.S",
      type: "constant-load@1",
      params: { bytes: Array.from(S) },
      narrationOverride: narrConstS(S),
    },
    {
      kind: "step",
      id: "cust.encS",
      type: "encode-string@1",
      params: {},
      portInputs: { input: port("cust.S", "output") },
    },
    {
      kind: "step",
      id: "cust.concat",
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: { input0: port("cust.encN", "output"), input1: port("cust.encS", "output") },
      narrationOverride: narrConcatName,
    },
    {
      kind: "step",
      id: "cust.bytepad",
      type: "bytepad@1",
      params: { w: rate },
      portInputs: { input: port("cust.concat", "output") },
      narrationOverride: narrBytepadName(rate),
    },
    // ─── Key block: bytepad(encode_string(K), rate), K from aux["key"] ───────
    {
      kind: "step",
      id: "key.load",
      type: "aux-load-bytes@1",
      params: { auxName: "key", byteLength: keyByteLength },
      narrationOverride: narrKeyLoad,
    },
    {
      kind: "step",
      id: "key.enc",
      type: "encode-string@1",
      params: {},
      portInputs: { input: port("key.load", "output") },
      narrationOverride: narrKeyEnc,
    },
    {
      kind: "step",
      id: "key.bytepad",
      type: "bytepad@1",
      params: { w: rate },
      portInputs: { input: port("key.enc", "output") },
      narrationOverride: narrKeyBytepad(rate),
    },
    // ─── Output-length commitment: right_encode(L) — or right_encode(0) XOF ──
    {
      kind: "step",
      id: "out.rightenc",
      type: "right-encode@1",
      params: { value: rightEncodeValue },
      narrationOverride: narrRightEncode(variant, outputLength),
    },
    // ─── newX = customization ‖ key block ‖ message ‖ length commitment ──────
    {
      kind: "step",
      id: "newX",
      type: "concat@1",
      params: { inputCount: 4 },
      portInputs: {
        input0: port("cust.bytepad", "output"),
        input1: port("key.bytepad", "output"),
        input2: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
        input3: port("out.rightenc", "output"),
      },
      narrationOverride: narrNewX,
    },
    // ─── Pad (cSHAKE domain 0x04) ────────────────────────────────────────────
    {
      kind: "step",
      id: "pad",
      type: "keccak.pad@1",
      params: { rate, domainByte: 0x04 },
      portInputs: { input: port("newX", "output") },
      narrationOverride: narrPad(variant, rate),
    },
  ];

  const tail = buildSpongeSqueeze(
    rate,
    outputLength,
    port("pad", "output"),
    buildSpongeNarration(DISPLAY_NAME[variant], rate, outputLength),
  );

  return {
    id: `${variant}@1`,
    name: DISPLAY_NAME[variant],
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: keyByteLength }, // KMAC — the first keyed hash
    },
    steps: [...headSteps, ...tail.steps],
    cipherConstants: { RC: RC_BYTES, S0: S0_BYTES },
    outputFrom: tail.outputFrom,
  };
};

/** The variant's rate — exported so the UI stepper can step by whole blocks. */
export const kmacRate = (variant: KmacVariant): number => RATE_BY_VARIANT[variant];

/**
 * Recover the declared MAC key length (in bytes) from a built KMAC spec. KMAC's
 * key length is variable (SP 800-185 places no upper bound); the whole key block
 * — `inputs.key.byteLength`, the `key.load` aux-read width, and
 * `encode_string(K)`'s bit-length prefix — is built from one `keyByteLength`, so
 * `inputs.key.byteLength` is the authoritative source. Used by `applyDocument`
 * to sync the key-length signal after loading a saved / shared KMAC document, so
 * a later customization edit rebuilds at the same key length.
 */
export const readKmacKeyLength = (spec: CipherSpec): number => spec.inputs.key.byteLength;

/**
 * Recover the customization string `S` from a built KMAC spec (the `cust.S`
 * constant-load param). Used by `applyDocument` to sync the customization
 * control after loading a saved / shared KMAC document.
 */
export const readKmacCustomization = (spec: CipherSpec): Uint8Array => {
  for (const node of spec.steps) {
    if (node.kind === "step" && node.id === "cust.S") {
      const b = (node.params as Record<string, unknown>).bytes;
      if (Array.isArray(b)) return Uint8Array.from(b as number[]);
    }
  }
  return new Uint8Array(0);
};
