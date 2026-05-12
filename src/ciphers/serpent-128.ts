/**
 * Serpent-128 forward cipher spec. 128-bit key, single-block, encrypt.
 *
 * One-liner over `buildSerpentSpec`. Variant identity (128 vs 192 vs 256)
 * is carried in the key-expansion step's `keyByteLength` param and the
 * spec's declared `inputs.key.byteLength` — round body is identical
 * across all three Serpent key sizes.
 */

import { buildSerpentSpec } from "./serpent-spec-builder";

export const serpent128Spec = buildSerpentSpec(16, "encrypt");
