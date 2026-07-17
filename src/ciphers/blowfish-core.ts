/**
 * Blowfish as a `BlockCipherCore` — the second cipher to gain every mode of
 * operation, and the first with a block that isn't 16 bytes.
 *
 * This file is the *only* place the mode machine learns Blowfish's specifics:
 * that its block is 8 bytes and its key (v1) is 8 bytes. Like `aes-core.ts`, it
 * reimplements no cipher logic — it re-expresses the existing spec builder
 * through the contract.
 *
 * ## Why this one matters more than "one more cipher"
 *
 * Phases A + B made the mode machine block-size-generic, but every core shipped
 * was AES, whose block IS 16 — so a stray hardcoded `16` anywhere in the
 * generalized arithmetic would have passed the whole suite. AES-192/256 didn't
 * help (also 16-byte). Blowfish is the first core whose block width actually
 * exercises `blockByteLength`: the iterate splits at 8, CBC's `fetch-iv` reads
 * 8, and the padding overlay fills to 8. `tests/block-size-generic-modes.test.ts`
 * pins the same paths with a fake 8-byte core, but a fake core's body is a
 * passthrough leaf — this is the real cipher behind the same arithmetic.
 *
 * ## Padding in single-block mode
 *
 * Registering this core also enables the padding overlay for Blowfish's
 * single-block spec, because "has a core" is the one gate for both facts (it
 * means "we know your block size"). That is deliberate — see
 * `docs/plans/foamy-prancing-wren.md` "Phase C must decide". Blowfish is the
 * first cipher able to show a pad filling to 8 bytes rather than 16, which is a
 * lesson the three AES variants structurally cannot teach.
 *
 * References: Schneier, "Description of a New Variable-Length Key, 64-Bit Block
 * Cipher (Blowfish)", FSE 1993. NIST SP 800-38A for the modes themselves.
 */

import type { PortBinding } from "../core/types";
import type { BlockCipherCore, CipherBody } from "./block-cipher-core";
import { buildBlowfishBody, buildKeySetup } from "./blowfish-spec-builder";

/** Blowfish's block is 64 bits (Schneier 1993 §1). */
const BLOWFISH_BLOCK_BYTES = 8;

/**
 * Blowfish takes a variable-length key (32..448 bits) in the real cipher; this
 * build fixes it at 8 bytes, matching the single-block spec's
 * `inputs.key.byteLength` and the key-setup group's two-key-word alternation.
 * Widening the key is out of scope here (`docs/plans/blowfish.md`).
 */
const BLOWFISH_KEY_BYTES = 8;

/**
 * Build the `BlockCipherCore` for Blowfish.
 *
 * Unlike `aesCore(variant)` this takes no argument: Blowfish is one variant at
 * this key width, so there is one core rather than a family of three.
 */
export function blowfishCore(): BlockCipherCore {
  return {
    id: "blowfish",
    displayName: "Blowfish",
    // Same as `displayName` here — there is no variant suffix to drop. The two
    // fields diverge only for families like AES ("AES-128" vs "AES").
    familyName: "Blowfish",
    blockByteLength: BLOWFISH_BLOCK_BYTES,
    keyByteLength: BLOWFISH_KEY_BYTES,
    // The 18 visible `key ⊕ P` XORs + the opaque 521-self-encryption monolith,
    // which publishes the P-array and four S-boxes to aux. Runs once per RUN,
    // not once per block: the schedule depends on the key alone.
    buildKeySchedule: () => buildKeySetup(),
    buildEncryptBody: (seed: PortBinding): CipherBody => buildBlowfishBody("encrypt", seed),
    // Blowfish decrypts by running the SAME network with the P-array consumed in
    // reverse — no inverse S-boxes and no separate code path. So the "inverse
    // body" is the same builder under the other direction.
    buildDecryptBody: (seed: PortBinding): CipherBody => buildBlowfishBody("decrypt", seed),
  };
}
