/**
 * Speck32/64 forward cipher, LE-NSA byte convention.
 * Same word-level computation as the BE variant; differs only in how the
 * bytes at the input and output boundaries are serialised.
 */

import { buildSpeck32_64Spec } from "./speck-32-64-builder";

export const speck32_64LeSpec = buildSpeck32_64Spec("le-nsa", "encrypt");
