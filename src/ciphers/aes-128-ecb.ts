/**
 * AES-128 in ECB mode (Electronic Codebook), encrypt direction.
 *
 * Multi-block extension of `aes-128.ts`. ECB encrypts each plaintext block
 * **independently** — same plaintext block always produces the same
 * ciphertext block under a fixed key. That property is what makes ECB the
 * canonical "what NOT to do" example: any repetition in the plaintext
 * leaks through to the ciphertext (the famous Tux-image demonstration).
 *
 * Lives here as a thin wrapper around the generic `buildEcbSpec` so the spec
 * literal stays terse and the actual structure is one cipher-agnostic mode
 * builder shared across every cipher × variant × direction combination.
 */

import { aesCore } from "./aes-core";
import { buildEcbSpec } from "./modes/ecb";

export const aes128EcbSpec = buildEcbSpec(aesCore("aes-128"), "encrypt");
