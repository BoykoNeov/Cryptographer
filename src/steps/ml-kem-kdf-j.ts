/**
 * ml-kem.kdf-j — ML-KEM's `J`, which is SHAKE256 squeezed to 32 bytes
 * (FIPS 203 §4.1).
 *
 * One input port `input`, one output port `output` carrying 32 bytes.
 *
 * ## Why this is not `ml-kem.hash-h@1` with a different rate
 *
 * `H` is a hash and `J` is a key derivation function, and the reason they are
 * different primitives is the reason `J` exists at all: it is the ONLY thing in
 * ML-KEM that produces a secret from a value the attacker chose.
 *
 * When decapsulation's re-encryption check fails, the algorithm does not return
 * an error. Returning an error would tell an attacker that their tampered
 * ciphertext was rejected, and a decade of chosen-ciphertext attacks says that
 * one bit is enough. Instead it returns `J(z ‖ c)` — a secret that looks exactly
 * like a real shared secret, is deterministic for that ciphertext, and is
 * unguessable because `z` is 32 bytes of the private key that nothing else ever
 * touches.
 *
 * That is *implicit rejection*, and it is the hardest branch of ML-KEM to see in
 * a trace, because on a valid ciphertext it never runs.
 *
 * See `ml-kem-hash-g.ts` for the cross-reference-monolith note covering this
 * family.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { shake256 } from "../ciphers/keccak-compute";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

const STEP = "ml-kem.kdf-j";

/** `J` is defined as SHAKE256 squeezed to exactly this many bytes. */
const J_OUTPUT_BYTES = 32;

export const mlKemKdfJPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw", byteLength: J_OUTPUT_BYTES }]]),
};

export const mlKemKdfJ: PortedExecutor = (inputs, _params, _ctx) => {
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error(`${STEP}: requires an "input" port`);
  }
  return new Map([["output", shake256(input, J_OUTPUT_BYTES)]]);
};

export const mlKemKdfJDoc: StepDocumentation = {
  name: "J — the rejection secret (SHAKE256)",
  summary:
    "SHAKE256 squeezed to 32 bytes. Produces the plausible-looking fake secret returned when decapsulation detects a tampered ciphertext.",
  detail: `# J — the rejection secret

**SHAKE256**, squeezed to 32 bytes.

## Why failing loudly would be a vulnerability

When decapsulation re-encrypts what it decrypted and gets a different ciphertext
back, something is wrong: the ciphertext was corrupted, or forged, or crafted.
The obvious response is to return an error.

ML-KEM does not. It returns \`J(z ‖ c)\` — a 32-byte value that is
indistinguishable from a real shared secret.

The reason is a long history of attacks that need only one bit of feedback. An
attacker who can submit ciphertexts and learn *whether each one decrypted
cleanly* can, over many queries, walk that single bit all the way back to the
private key. So the algorithm makes the two cases look identical from outside:
the caller gets 32 bytes either way and cannot tell which happened.

The fake secret has to be
- **deterministic** — the same bad ciphertext must always give the same answer,
  or repeating a query would itself be a signal;
- **unguessable** — hence \`z\`, which is 32 bytes of the private key reserved
  for exactly this and used nowhere else;
- **bound to the ciphertext** — hence \`c\` in the input, so two different
  forgeries do not collide.

This is called **implicit rejection**, and it is why decapsulation has no error
path to look at.

## Why it is a KDF and not the H step

\`H\` hashes public values for binding. \`J\` derives a secret from something the
attacker chose. Same sponge underneath; different job, different name in the
specification, and worth keeping apart on the canvas.

Its sponge is the one under **Hash → SHAKE256** in the algorithm selector, where
you can watch all 216 frames of it.`,
  params: new Map(),
  references: [
    "FIPS 203 §4.1 — J is SHAKE256 squeezed to 32 bytes",
    "FIPS 203 Algorithm 18 — ML-KEM.Decaps_internal, the implicit-rejection branch",
    "FIPS 202 §6.2 — SHAKE256",
  ],
};
