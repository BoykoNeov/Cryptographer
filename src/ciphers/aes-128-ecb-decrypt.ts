/**
 * AES-128 in ECB mode, decrypt direction.
 *
 * The inverse of `aes-128-ecb.ts`. Decrypt each ciphertext block
 * independently — same body as encrypt with `buildAesDecryptBody` swapped
 * in for the per-block round sequence. Round keys are derived by the
 * same forward `aes.key-expansion@1` executor (consuming the same user
 * key) and then consumed in reverse via the AddRoundKey aux references
 * inside the inverse body.
 */

import { buildAesEcbSpec } from "./aes-ecb-builder";

export const aes128EcbDecryptSpec = buildAesEcbSpec("aes-128", "decrypt");
