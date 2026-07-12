/**
 * Twofish encrypt spec (Schneier et al. 1998). See `twofish-spec-builder.ts`
 * for the full structure + the direction parameterization; this file is the
 * thin canonical-spec export the store's `defaults` table references.
 */

import { buildTwofishSpec } from "./twofish-spec-builder";

export const twofishSpec = buildTwofishSpec("encrypt");
