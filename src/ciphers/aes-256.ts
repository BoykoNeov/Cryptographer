/**
 * AES-256 forward cipher, FIPS-197 §5.1 (single-block).
 *
 * **Byte-native (scaffolding-suppression Phase B Slice B1.3, 2026-05-29).**
 * Structurally identical to byte-native AES-128/192: the per-block body
 * composes from port-native primitives whose ports are all `layout:"raw"` —
 * `byte-substitute@1` (SubBytes), `permute@1` (ShiftRows),
 * `gf-matrix-multiply@1` (MixColumns), `aux-load-bytes@1` + `xor@1`
 * (AddRoundKey) — built by the variant-agnostic `buildAesEncryptBodyNative`.
 * The only differences from AES-128 are Nk=8 (32-byte cipher key) and
 * ROUNDS=14. Nk=8 (Nk>6) is also what triggers the extra "SubWord every Nk/2
 * words" branch inside `aes.key-expansion@1` — that branch fires solely for
 * AES-256. See the key-expansion source comments + doc block for the
 * FIPS-197 §5.2 reference.
 *
 * The 16-byte working state carries port-to-port between round groups via the
 * A3b `StepGroup` `seedInput`/`bodyOutput` contract; the plaintext arrives on
 * the reserved `$input` source and the cipher exit is named by `outputFrom`.
 * Key expansion stays the monolithic `aes.key-expansion@1` (A4-clean),
 * writing `roundKey.0..14` into the aux map once total.
 */

import type { CipherSpec } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";
import { aesNativeOutputFrom, buildAesEncryptBodyNative } from "./aes-round-builder-native";

const ROUNDS = 14;

export const aes256Spec: CipherSpec = {
  id: "aes-256@1",
  name: "AES-256",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 32 },
  },
  steps: [
    {
      kind: "step",
      id: "key-expansion",
      type: "aes.key-expansion@1",
      params: {
        keyAuxName: "key",
        outputPrefix: "roundKey",
        sbox: [...AES_SBOX],
        rcon: [...AES_RCON],
        rounds: ROUNDS,
      },
    },
    ...buildAesEncryptBodyNative(ROUNDS),
  ],
  outputFrom: aesNativeOutputFrom(ROUNDS),
};
