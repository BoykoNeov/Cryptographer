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
 * Key expansion is the DECOMPOSED port-native schedule
 * (`buildAesKeyScheduleNative`, key-schedule-decomposition plan Slice K1a) —
 * the FIPS-197 §5.2 RotWord / SubWord / Rcon / word-XOR recurrence is now a
 * tree of visible primitive frames instead of one monolithic executor. It
 * still runs once total — never inside the per-block loop regardless of mode —
 * publishing `roundKey.0..10` into the aux map via its `aes.publish-round-keys@1`
 * tail, so the round-body AddRoundKey consumers are unchanged (B-minimal).
 *
 * The decrypt side (`aes128DecryptSpec`) and the ECB/CBC modes remain
 * matrix-shaped until Slices B1.2 / B1.4 — `main` never holds a half-converted
 * cipher, but a single feature branch may carry a mixed encrypt(byte-native) /
 * decrypt(matrix) window mid-rebuild.
 */

import type { CipherSpec } from "../core/types";
import { buildAesKeyScheduleNative } from "./aes-key-schedule-builder-native";
import { aesNativeOutputFrom, buildAesEncryptBodyNative } from "./aes-round-builder-native";

const ROUNDS = 10;
const NK = 4; // 16-byte key / 4 bytes per word

export const aes128Spec: CipherSpec = {
  id: "aes-128@1",
  name: "AES-128",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 16 },
  },
  steps: [buildAesKeyScheduleNative(ROUNDS, NK), ...buildAesEncryptBodyNative(ROUNDS)],
  outputFrom: aesNativeOutputFrom(ROUNDS),
};
