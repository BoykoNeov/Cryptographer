/**
 * Speck32/64 inverse cipher, BE-paper byte convention.
 * Round keys are consumed in reverse; the same forward key-schedule runs.
 */

import { buildSpeck32_64Spec } from "./speck-32-64-builder";

export const speck32_64BeDecryptSpec = buildSpeck32_64Spec("be-paper", "decrypt");
