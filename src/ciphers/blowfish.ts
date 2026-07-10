/**
 * Blowfish encrypt spec (Schneier 1993). See `blowfish-spec-builder.ts` for
 * the full structure + the direction parameterization; this file is the thin
 * canonical-spec export the store's `defaults` table references.
 */

import { buildBlowfishSpec } from "./blowfish-spec-builder";

export const blowfishSpec = buildBlowfishSpec("encrypt");
