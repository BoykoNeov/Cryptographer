/**
 * Serpent-128 inverse cipher spec. 128-bit key, single-block, decrypt.
 */

import { buildSerpentSpec } from "./serpent-spec-builder";

export const serpent128DecryptSpec = buildSerpentSpec(16, "decrypt");
