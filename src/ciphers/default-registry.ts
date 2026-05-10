import { StepRegistry } from "../core/registry";
import { addRoundKey } from "../steps/add-round-key";
import { byteSubstitution } from "../steps/byte-substitution";
import { keyExpansion } from "../steps/key-expansion";
import { mixColumns } from "../steps/mix-columns";
import { shiftRows } from "../steps/shift-rows";

/** Registers every step type referenced by the built-in cipher specs. */
export const buildDefaultRegistry = (): StepRegistry => {
  const r = new StepRegistry();
  r.register("generic.byte-substitution@1", byteSubstitution);
  r.register("generic.shift-rows@1", shiftRows);
  r.register("generic.mix-columns@1", mixColumns);
  r.register("generic.add-round-key@1", addRoundKey);
  r.register("aes.key-expansion@1", keyExpansion);
  return r;
};
