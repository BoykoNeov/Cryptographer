/**
 * Blowfish decrypt spec (Schneier 1993). Blowfish decrypts by running the SAME
 * Feistel network with the P-array applied in reverse (rounds consume P[17]
 * down to P[2]; whitening consumes P[0], P[1]) — no inverse S-boxes, no
 * separate code path. See `blowfish-spec-builder.ts` for the direction
 * parameterization.
 */

import { buildBlowfishSpec } from "./blowfish-spec-builder";

export const blowfishDecryptSpec = buildBlowfishSpec("decrypt");
