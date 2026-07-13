/**
 * cSHAKE128 / cSHAKE256 — the **customizable** SHAKE of NIST SP 800-185,
 * 2026-07-13. The app's first SP 800-185 function and the direct base of KMAC.
 *
 * **What cSHAKE adds over SHAKE.** A cSHAKE is a SHAKE whose output is bound to
 * two extra byte strings — a function-name `N` (reserved for NIST-defined
 * functions; empty for direct use) and a user **customization** string `S`. Two
 * cSHAKEs with different `S` produce completely unrelated output for the same
 * message, so an application can domain-separate its own uses of the XOF without
 * a key. It is defined (SP 800-185 §3.3) as:
 *
 * ```
 *   cSHAKE(X, L, N, S):
 *     if N == "" and S == "":  return SHAKE(X, L)               # domain 0x1F
 *     else: return KECCAK[cap]( bytepad(encode_string(N) || encode_string(S), rate)
 *                               || X , 00…, L )                 # domain 0x04
 * ```
 *
 * So the whole of cSHAKE lives **upstream** of the sponge: build a customization
 * prefix, prepend it to the message, and flip the domain byte from SHAKE's
 * `0x1F` to `0x04`. The absorb fold + squeeze are the *identical* shared tail
 * (`buildSpongeSqueeze`); the padding is the same `keccak.pad@1`, only its
 * `domainByte` differs.
 *
 * **The empty-customization branch is exact, not approximate.** When both `N`
 * and `S` are empty, cSHAKE is *defined* to equal SHAKE — so this builder emits
 * no prefix and uses domain `0x1F`, which is byte-for-byte a SHAKE pipeline.
 * (The spec keeps its `cshake…@1` id so the UI still shows it under cSHAKE.)
 *
 * **Rates.** cSHAKE128 = 168 bytes (128-bit strength), cSHAKE256 = 136 (256-bit)
 * — unchanged from the SHAKE variants they extend.
 *
 * **KAT.** Byte-equal to the NIST SP 800-185 published cSHAKE samples and to
 * pycryptodome across message and output lengths (`tests/cshake-kat.test.ts`).
 *
 * **References:**
 *   - NIST SP 800-185 §3.3 (cSHAKE), §2.3 (encode_string / bytepad)
 *   - FIPS 202 §4 (sponge), §B.2 (domain separation)
 */

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { RC_BYTES, S0_BYTES, port } from "./keccak-f";
import { buildSpongeNarration, buildSpongeSqueeze } from "./sponge";

// ─── Variants + parameters ──────────────────────────────────────────────────

export type CshakeVariant = "cshake128" | "cshake256";

/** Sponge rate in bytes per variant (same as the underlying SHAKE). */
const RATE_BY_VARIANT: Record<CshakeVariant, number> = {
  cshake128: 168,
  cshake256: 136,
};

const DISPLAY_NAME: Record<CshakeVariant, string> = {
  cshake128: "cSHAKE128",
  cshake256: "cSHAKE256",
};

/** Domain byte for the customized case (`00` suffix + pad); SHAKE reduction uses 0x1F. */
const DOMAIN_CSHAKE = 0x04;
const DOMAIN_SHAKE = 0x1f;

// ─── Head-step narration (the customization prefix) ─────────────────────────

const narrConstN = (N: Uint8Array): StepDocumentation => ({
  name: "Function name N (raw bytes)",
  summary:
    N.length === 0
      ? "The function-name string N — empty for direct cSHAKE use."
      : `The function-name string N (${N.length} bytes), reserved by SP 800-185 for named functions.`,
  detail: `\`N\` names the function being defined on top of cSHAKE. NIST reserves
it for its own constructions (KMAC sets \`N = "KMAC"\`); for direct cSHAKE use it
is the empty string. It is the first field of the customization prefix, before
the user string \`S\`.`,
  references: ["NIST SP 800-185 §3.3 (cSHAKE)"],
});

const narrConstS = (S: Uint8Array): StepDocumentation => ({
  name: "Customization string S (raw bytes)",
  summary: `The user customization string S (${S.length} bytes) — the whole point of cSHAKE.`,
  detail: `\`S\` is the caller's **domain-separation** string. Any change to
\`S\` — even one byte — makes the output completely unrelated for the same
message, so an application can carve out its own independent instance of the XOF.
Edit it in the control above and watch every output byte change.`,
  references: ["NIST SP 800-185 §3.3 (cSHAKE)"],
});

const narrConcatCustom: StepDocumentation = {
  name: "Concatenate encode_string(N) ‖ encode_string(S)",
  summary: "Join the two length-prefixed customization strings.",
  detail: `Both customization strings are now length-prefixed (self-describing),
so joining them is unambiguous — a reader can always recover where \`N\` ends and
\`S\` begins. This pair is what \`bytepad\` will align into whole sponge blocks.`,
  references: ["NIST SP 800-185 §3.3 (cSHAKE)"],
};

const narrBytepadCustom = (rate: number): StepDocumentation => ({
  name: `bytepad(…, ${rate}) — align the customization to a rate block`,
  summary: `Prefix the block size and zero-pad the customization up to a multiple of the ${rate}-byte rate.`,
  detail: `The customization is absorbed as a **whole number of ${rate}-byte
sponge blocks before the message**. Padding it to a rate boundary means the
message always starts at the beginning of a fresh block, so the customization is
a clean prefix rather than sharing a block with the first message bytes.`,
  references: ["NIST SP 800-185 §2.3.3 (bytepad)", "NIST SP 800-185 §3.3 (cSHAKE)"],
});

const narrMsgConcat: StepDocumentation = {
  name: "Prepend the customization block to the message",
  summary: "Concatenate the padded customization prefix with the input message X.",
  detail: `The full sponge input is \`bytepad(encode_string(N) ‖ encode_string(S),
rate) ‖ X\`. Because the prefix is a whole number of rate blocks, the message X
begins on a block boundary — the sponge absorbs the customization first, then the
message, exactly as SP 800-185 §3.3 specifies.`,
  references: ["NIST SP 800-185 §3.3 (cSHAKE)"],
};

const narrPad = (variant: CshakeVariant, rate: number, customized: boolean): StepDocumentation => ({
  name: "Pad + domain-separate (pad10*1, FIPS 202 §5.1)",
  summary: customized
    ? `Append the cSHAKE domain byte 0x04 and pad with the 10*1 rule to a multiple of the ${rate}-byte rate.`
    : "Empty N and S ⇒ cSHAKE reduces to SHAKE: append the SHAKE domain byte 0x1F and pad10*1.",
  detail: customized
    ? `${DISPLAY_NAME[variant]} pads the prefixed message to a whole number of
${rate}-byte sponge blocks: append the domain byte \`0x04\` (the two-bit \`00\`
cSHAKE suffix plus the padding's leading 1-bit), zero-fill, then set the top bit
of the last byte. The \`0x04\` is what distinguishes a customized cSHAKE from a
SHAKE (\`0x1F\`). One byte short of a block, the two pad bits merge into \`0x84\`.`
    : `With empty \`N\` and \`S\`, SP 800-185 defines cSHAKE to be exactly
SHAKE — so the domain byte is SHAKE's \`0x1F\`, there is no customization prefix,
and this is byte-for-byte a SHAKE pipeline.`,
  references: ["FIPS 202 §5.1 (pad10*1)", "NIST SP 800-185 §3.3 (cSHAKE)"],
});

// ─── Spec builder ────────────────────────────────────────────────────────────

/**
 * Build a cSHAKE spec. `N`/`S` are the customization byte strings (either may be
 * empty; both empty ⇒ the SHAKE reduction). `outputLength` drives the squeeze
 * block count structurally, exactly as for SHAKE.
 */
export const buildCshakeSpec = (
  variant: CshakeVariant,
  N: Uint8Array,
  S: Uint8Array,
  outputLength: number,
): CipherSpec => {
  const rate = RATE_BY_VARIANT[variant];
  const customized = N.length !== 0 || S.length !== 0;
  const domainByte = customized ? DOMAIN_CSHAKE : DOMAIN_SHAKE;

  const headSteps: StepNode[] = [];
  let padInput: PortBinding = port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT);

  if (customized) {
    headSteps.push(
      // encode_string(N)
      {
        kind: "step",
        id: "cust.N",
        type: "constant-load@1",
        params: { bytes: Array.from(N) },
        narrationOverride: narrConstN(N),
      },
      {
        kind: "step",
        id: "cust.encN",
        type: "encode-string@1",
        params: {},
        portInputs: { input: port("cust.N", "output") },
      },
      // encode_string(S)
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
      // bytepad(encode_string(N) || encode_string(S), rate)
      {
        kind: "step",
        id: "cust.concat",
        type: "concat@1",
        params: { inputCount: 2 },
        portInputs: { input0: port("cust.encN", "output"), input1: port("cust.encS", "output") },
        narrationOverride: narrConcatCustom,
      },
      {
        kind: "step",
        id: "cust.bytepad",
        type: "bytepad@1",
        params: { w: rate },
        portInputs: { input: port("cust.concat", "output") },
        narrationOverride: narrBytepadCustom(rate),
      },
      // message = prefix || X
      {
        kind: "step",
        id: "msg",
        type: "concat@1",
        params: { inputCount: 2 },
        portInputs: {
          input0: port("cust.bytepad", "output"),
          input1: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
        },
        narrationOverride: narrMsgConcat,
      },
    );
    padInput = port("msg", "output");
  }

  headSteps.push({
    kind: "step",
    id: "pad",
    type: "keccak.pad@1",
    params: { rate, domainByte },
    portInputs: { input: padInput },
    narrationOverride: narrPad(variant, rate, customized),
  });

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
      key: { byteLength: 0 }, // cSHAKE is unkeyed (KMAC adds the key)
    },
    steps: [...headSteps, ...tail.steps],
    cipherConstants: { RC: RC_BYTES, S0: S0_BYTES },
    outputFrom: tail.outputFrom,
  };
};

/** The variant's rate — exported so the UI stepper can step by whole blocks. */
export const cshakeRate = (variant: CshakeVariant): number => RATE_BY_VARIANT[variant];

/**
 * Recover the customization strings `N` / `S` from a built cSHAKE spec (the
 * `cust.N` / `cust.S` constant-load params). Used by `applyDocument` to sync the
 * customization controls after loading a saved / shared cSHAKE document. A spec
 * in the SHAKE-reduction form (no customization steps) returns two empty
 * strings.
 */
export const readCshakeCustomization = (spec: CipherSpec): { N: Uint8Array; S: Uint8Array } => {
  const readConst = (id: string): Uint8Array => {
    for (const node of spec.steps) {
      if (node.kind === "step" && node.id === id) {
        const b = (node.params as Record<string, unknown>).bytes;
        if (Array.isArray(b)) return Uint8Array.from(b as number[]);
      }
    }
    return new Uint8Array(0);
  };
  return { N: readConst("cust.N"), S: readConst("cust.S") };
};
