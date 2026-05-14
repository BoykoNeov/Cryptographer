/**
 * AES-128 in CBC mode, decrypt direction.
 *
 * Inverse of `aes-128-cbc.ts`. The per-block iterate body snapshots the
 * incoming ciphertext into `aux["next-chain"]`, runs the AES inverse
 * round body, XORs in `aux["chain"]` (the previous block's ciphertext
 * or the IV for block 0), then advances `chain := next-chain` for the
 * next iteration via `aux-copy`. See `buildAesCbcSpec` for the full
 * dance.
 *
 * NIST SP 800-38A §F.2.2 supplies the known-answer test for this spec
 * — covered in `tests/aes-128-cbc-kat.test.ts`.
 */

import { buildAesCbcSpec } from "./aes-cbc-builder";

export const aes128CbcDecryptSpec = buildAesCbcSpec("aes-128", "decrypt");
