/**
 * Serpent-256 inverse cipher spec. 256-bit key, single-block, decrypt.
 */

import { buildSerpentSpec } from "./serpent-spec-builder";

export const serpent256DecryptSpec = buildSerpentSpec(32, "decrypt");
