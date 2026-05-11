/**
 * Speck32/64 forward cipher, BE-paper byte convention.
 * See speck-32-64-builder.ts for the layout details.
 */

import { buildSpeck32_64Spec } from "./speck-32-64-builder";

export const speck32_64BeSpec = buildSpeck32_64Spec("be-paper", "encrypt");
