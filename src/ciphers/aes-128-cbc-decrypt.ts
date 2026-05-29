/**
 * AES-128 in CBC mode, decrypt direction.
 *
 * Inverse of `aes-128-cbc.ts`. Byte-native (Slice B1.4b): the per-block
 * iterate body runs the AES inverse round body on the raw ciphertext block,
 * then XORs in the chain (`port("cbc-blocks","chain")` — the previous block's
 * ciphertext, or the IV for block 0) to recover the plaintext. The chain
 * rides the iterate's `chainInput`/`chainFeedback` ports, not an aux slot;
 * decrypt's `chainFeedback` is the raw input block. See `buildAesCbcSpec`.
 *
 * NIST SP 800-38A §F.2.2 supplies the known-answer test for this spec
 * — covered in `tests/aes-128-cbc-kat.test.ts`.
 */

import { buildAesCbcSpec } from "./aes-cbc-builder";

export const aes128CbcDecryptSpec = buildAesCbcSpec("aes-128", "decrypt");
