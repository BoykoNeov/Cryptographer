/**
 * AES-128 in CBC mode (Cipher Block Chaining), encrypt direction.
 *
 * Builds the multi-block CBC spec via `buildAesCbcSpec`. Differs from
 * `aes-128-ecb.ts` only in the per-block iterate body — the per-block
 * AES round structure is identical (shared via `aes-round-builder`).
 *
 * Headline pedagogical use: type a multi-block plaintext, watch each
 * iteration's first XOR fold in the previous ciphertext (or IV for
 * block 0); identical plaintext blocks now produce DIFFERENT ciphertext
 * blocks because the chain state diverges.
 *
 * NIST SP 800-38A §F.2.1 supplies the known-answer test for this spec
 * — see `tests/aes-128-cbc-kat.test.ts`.
 */

import { buildAesCbcSpec } from "./aes-cbc-builder";

export const aes128CbcSpec = buildAesCbcSpec("aes-128", "encrypt");
