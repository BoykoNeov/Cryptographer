/**
 * AES-128 forward cipher, FIPS-197 §5.1 (single-block).
 *
 * **Byte-native (scaffolding-suppression Phase B Slice B1, 2026-05-29).** The
 * per-block body now composes from port-native primitives whose ports are all
 * `layout:"raw"` — `byte-substitute@1` (SubBytes), `permute@1` (ShiftRows),
 * `gf-matrix-multiply@1` (MixColumns), `aux-load-bytes@1` + `xor@1`
 * (AddRoundKey) — instead of threading a `MatrixState` through the legacy
 * `generic.{byte-substitution,shift-rows,mix-columns,add-round-key}@1` lifts.
 * The 16-byte working state carries port-to-port between round groups via the
 * A3b `StepGroup` `seedInput`/`bodyOutput` contract (no `state` thread, no
 * `state-to-bytes`/`bytes-to-state` bridges). The plaintext arrives on the
 * reserved `$input` source (A3a) and the cipher exit is named by `outputFrom`.
 * Body construction lives in `aes-round-builder-native.ts` so the ECB / CBC
 * factories can reuse it verbatim in Slice B1.4.
 *
 * Key expansion stays the monolithic `aes.key-expansion@1` (already A4-clean,
 * and it ALSO consumes the forward S-box for SubWord — moving only the round
 * S-box to `cipherConstants` would diverge the two consumers, so the S-box
 * stays a leaf param in B1; unify in the later key-expansion-decomposition
 * slice). It runs once total — never inside the per-block loop regardless of
 * mode — writing `roundKey.0..10` into the aux map.
 *
 * The decrypt side (`aes128DecryptSpec`) and the ECB/CBC modes remain
 * matrix-shaped until Slices B1.2 / B1.4 — `main` never holds a half-converted
 * cipher, but a single feature branch may carry a mixed encrypt(byte-native) /
 * decrypt(matrix) window mid-rebuild.
 */

import type { CipherSpec } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";
import { aesNativeOutputFrom, buildAesEncryptBodyNative } from "./aes-round-builder-native";

const ROUNDS = 10;

export const aes128Spec: CipherSpec = {
  id: "aes-128@1",
  name: "AES-128",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 16 },
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
