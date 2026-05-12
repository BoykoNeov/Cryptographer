/**
 * Serpent-256 forward cipher spec. 256-bit key, single-block, encrypt.
 *
 * 256-bit (32-byte) keys skip the padding step in key expansion — the
 * input bits already fill the prekey buffer exactly.
 */

import { buildSerpentSpec } from "./serpent-spec-builder";

export const serpent256Spec = buildSerpentSpec(32, "encrypt");
