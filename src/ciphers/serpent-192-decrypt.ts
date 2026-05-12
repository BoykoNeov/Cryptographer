/**
 * Serpent-192 inverse cipher spec. 192-bit key, single-block, decrypt.
 */

import { buildSerpentSpec } from "./serpent-spec-builder";

export const serpent192DecryptSpec = buildSerpentSpec(24, "decrypt");
