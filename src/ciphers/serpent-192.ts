/**
 * Serpent-192 forward cipher spec. 192-bit key, single-block, encrypt.
 *
 * Internally pads the 192-bit key to 256 bits before the prekey recurrence;
 * everything else is identical to Serpent-128 / 256. See
 * `serpent-key-expansion.ts` for the padding rule.
 */

import { buildSerpentSpec } from "./serpent-spec-builder";

export const serpent192Spec = buildSerpentSpec(24, "encrypt");
