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
import { iso78164Pad, iso78164PadDoc } from "../steps/iso7816-4-pad";
import { iso78164Unpad, iso78164UnpadDoc } from "../steps/iso7816-4-unpad";
import { keyExpansion, keyExpansionDoc } from "../steps/key-expansion";
import { loadBlock, loadBlockDoc } from "../steps/load-block";
import { mixColumns, mixColumnsDoc } from "../steps/mix-columns";
import { pkcs7Pad, pkcs7PadDoc } from "../steps/pkcs7-pad";
import { pkcs7Unpad, pkcs7UnpadDoc } from "../steps/pkcs7-unpad";
import { shiftRows, shiftRowsDoc } from "../steps/shift-rows";
import { speckKeySchedule, speckKeyScheduleDoc } from "../steps/speck-key-schedule";
import { speckRound, speckRoundDoc } from "../steps/speck-round";
import { speckRoundInverse, speckRoundInverseDoc } from "../steps/speck-round-inverse";
import { storeBlock, storeBlockDoc } from "../steps/store-block";
import { zeroPad, zeroPadDoc } from "../steps/zero-pad";
import { zeroUnpad, zeroUnpadDoc } from "../steps/zero-unpad";

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
  // ─── Padding chain (Phase: plaintext input + visible padding) ──────────
  // BytesState ↔ MatrixState boundary steps plus three pad/unpad pairs.
  // Each pair is generic over `blockSize` so they drop into future block
  // ciphers (DES/3DES, Twofish, Serpent) by parameter, not by code change.
  //
  // Three schemes are registered so the UI can A/B their behavior in the
  // trace: PKCS#7 (RFC 5652), zero-pad (ISO/IEC 9797-1 method 1, lossy),
  // and ISO 7816-4 (sentinel-marked). Each pair's `doc.detail` calls out
  // the trade-offs vs. the others so the educational story is captured.
  r.register("generic.pkcs7-pad@1", { executor: pkcs7Pad, doc: pkcs7PadDoc });
  r.register("generic.pkcs7-unpad@1", { executor: pkcs7Unpad, doc: pkcs7UnpadDoc });
  r.register("generic.zero-pad@1", { executor: zeroPad, doc: zeroPadDoc });
  r.register("generic.zero-unpad@1", { executor: zeroUnpad, doc: zeroUnpadDoc });
  r.register("generic.iso7816-4-pad@1", { executor: iso78164Pad, doc: iso78164PadDoc });
  r.register("generic.iso7816-4-unpad@1", { executor: iso78164Unpad, doc: iso78164UnpadDoc });
  r.register("generic.load-block@1", { executor: loadBlock, doc: loadBlockDoc });
  r.register("generic.store-block@1", { executor: storeBlock, doc: storeBlockDoc });
  // ─── Speck (ARX block cipher, second cipher family) ────────────────────
  // Three step types complete a full Speck cipher: a key-schedule that
  // expands an m-word master key into `rounds` round-key words, a forward
  // ARX round, and its inverse. Speck32/64 ships as two cipher specs in
  // the UI (BE-paper and LE-NSA byte orders), but the step code is one
  // copy parametric on `byteOrder`. The conventions compute the same
  // word-level cipher; only byte serialization at the boundary differs.
  r.register("speck.key-schedule@1", { executor: speckKeySchedule, doc: speckKeyScheduleDoc });
  r.register("speck.round@1", { executor: speckRound, doc: speckRoundDoc });
  r.register("speck.round-inverse@1", { executor: speckRoundInverse, doc: speckRoundInverseDoc });
  return r;
};
