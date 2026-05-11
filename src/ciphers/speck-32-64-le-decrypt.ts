/**
 * Speck32/64 inverse cipher, LE-NSA byte convention.
 */

import { buildSpeck32_64Spec } from "./speck-32-64-builder";

export const speck32_64LeDecryptSpec = buildSpeck32_64Spec("le-nsa", "decrypt");
