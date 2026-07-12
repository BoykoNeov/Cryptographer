/**
 * Twofish decrypt spec (Schneier et al. 1998). Thin export of the decrypt
 * direction; see `twofish-spec-builder.ts` for the shared builder.
 */

import { buildTwofishSpec } from "./twofish-spec-builder";

export const twofishDecryptSpec = buildTwofishSpec("decrypt");
