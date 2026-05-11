/**
 * Default registry: pairs every step type referenced by the built-in
 * cipher specs with its executor and (educational) documentation.
 *
 * Adding a new cipher: import its step types from src/steps/<name>.ts and
 * register them here with their docs. The UI will pick them up
 * automatically — no UI changes needed for new step types unless their
 * params can't be edited by the existing ParamEditor blocks.
 */

import { StepRegistry } from "../core/registry";
import { addRoundKey, addRoundKeyDoc } from "../steps/add-round-key";
import { byteSubstitution, byteSubstitutionDoc } from "../steps/byte-substitution";
import { keyExpansion, keyExpansionDoc } from "../steps/key-expansion";
import { loadBlock, loadBlockDoc } from "../steps/load-block";
import { mixColumns, mixColumnsDoc } from "../steps/mix-columns";
import { pkcs7Pad, pkcs7PadDoc } from "../steps/pkcs7-pad";
import { pkcs7Unpad, pkcs7UnpadDoc } from "../steps/pkcs7-unpad";
import { shiftRows, shiftRowsDoc } from "../steps/shift-rows";
import { storeBlock, storeBlockDoc } from "../steps/store-block";

export const buildDefaultRegistry = (): StepRegistry => {
  const r = new StepRegistry();
  r.register("generic.byte-substitution@1", {
    executor: byteSubstitution,
    doc: byteSubstitutionDoc,
  });
  r.register("generic.shift-rows@1", { executor: shiftRows, doc: shiftRowsDoc });
  r.register("generic.mix-columns@1", { executor: mixColumns, doc: mixColumnsDoc });
  r.register("generic.add-round-key@1", { executor: addRoundKey, doc: addRoundKeyDoc });
  r.register("aes.key-expansion@1", { executor: keyExpansion, doc: keyExpansionDoc });
  // ─── Padding chain (Phase: plaintext input + visible PKCS#7) ────────────
  // BytesState ↔ MatrixState boundary steps plus the pad/unpad pair. Each
  // is generic over `blockSize` so they drop into future block ciphers
  // (DES/3DES, Twofish, Serpent) by parameter, not by code change.
  r.register("generic.pkcs7-pad@1", { executor: pkcs7Pad, doc: pkcs7PadDoc });
  r.register("generic.pkcs7-unpad@1", { executor: pkcs7Unpad, doc: pkcs7UnpadDoc });
  r.register("generic.load-block@1", { executor: loadBlock, doc: loadBlockDoc });
  r.register("generic.store-block@1", { executor: storeBlock, doc: storeBlockDoc });
  return r;
};
