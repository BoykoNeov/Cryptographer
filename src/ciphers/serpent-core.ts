/**
 * Serpent as a `BlockCipherCore` — the third cipher family to gain every mode
 * of operation, and the first to arrive after Blowfish proved the mode machine
 * is block-size-generic.
 *
 * Like `aes-core.ts`, this file is a thin re-expression of the existing byte-
 * native Serpent builders through the `BlockCipherCore` contract — no cipher
 * logic is reimplemented, and the specs the modes generate from this core are
 * byte-identical to running the single-block Serpent spec once per block.
 *
 * ## Why Serpent is an AES-shaped core, not a Blowfish-shaped one
 *
 * Serpent's block is 16 bytes (like AES, unlike Blowfish's 8), and its body is
 * a flat list of round groups wrapped between IP and FP — structurally an AES
 * body, not a Feistel one. So the seed-threading Phase C templated on Blowfish
 * was already 90% done here: `buildSerpentEncryptBody`/`buildSerpentDecryptBody`
 * threaded every round group's block through sibling `state` bindings back in
 * Slice 5.3b, leaving only the IP leaf hardcoding `$input`. Adding the
 * `inputSource` parameter (mirroring `aes-round-builder-native.ts`) is the whole
 * of the work; this file just wires it up per variant.
 *
 * ## One family, three cores
 *
 * Serpent-128/192/256 differ ONLY in key length — same block, same round body,
 * same S-box cycling, same 32 rounds. So this is a `serpentCore(keyByteLength)`
 * family exactly like `aesCore(variant)`, not a single core like Blowfish.
 *
 * ## Padding in single-block mode
 *
 * Registering these cores also enables the padding overlay for single-block
 * Serpent, because "has a core" is the one gate for both facts (it means "we
 * know your block size") — the Blowfish "padding follows core-presence" policy
 * (`docs/plans/foamy-prancing-wren.md` Phase C). Serpent's 16-byte block makes
 * this identical to AES padding; the IV/split/pad arithmetic is byte-for-byte
 * the AES path, so the 8-byte edge cases Blowfish exercised do not recur here.
 *
 * References: Anderson, Biham, Knudsen, "Serpent: A Proposal for the Advanced
 * Encryption Standard" (AES submission, 1998). NIST SP 800-38A for the modes.
 */

import type { PortBinding } from "../core/types";
import type { BlockCipherCore, CipherBody } from "./block-cipher-core";
import { buildSerpentKeyScheduleNative } from "./serpent-key-schedule-builder-native";
import {
  buildSerpentDecryptBody,
  buildSerpentEncryptBody,
  serpentBodyOutputFrom,
} from "./serpent-round-builder";

/** The three Serpent key lengths. Each is its own `BlockCipherCore`. */
export type SerpentKeyByteLength = 16 | 24 | 32;

/** Serpent's block is 128 bits for every key length (AES-submission fixed). */
const SERPENT_BLOCK_BYTES = 16;

/** Map a key byte length to its variant's display / family strings. */
const displayFor = (keyByteLength: SerpentKeyByteLength): string => `Serpent-${keyByteLength * 8}`;

/**
 * Build the `BlockCipherCore` for one Serpent variant.
 *
 * The bodies are seed-parameterized: `build*Body` accept an input source
 * (defaulting to `$input` for the single-block spec), so a mode hands them the
 * iterate's injected block port instead. Both directions exit at the same FP
 * `state` port — `serpentBodyOutputFrom()` is shared (unlike AES, whose forward
 * and inverse exits are different group ids).
 */
export function serpentCore(keyByteLength: SerpentKeyByteLength): BlockCipherCore {
  return {
    // `id` matches the `Cipher` union string so the registry key + spec id agree.
    id: `serpent-${keyByteLength * 8}`,
    displayName: displayFor(keyByteLength),
    // Narration prose says "Serpent", not "Serpent-128" — the key length is
    // irrelevant to how a mode chains blocks.
    familyName: "Serpent",
    blockByteLength: SERPENT_BLOCK_BYTES,
    keyByteLength,
    // The decomposed (port-native) key schedule — one node, publishes
    // `aux["roundKey.0..32"]` once outside the per-block loop. Aux is global, so
    // those round keys reach every block's body across the iterate boundary.
    buildKeySchedule: () => buildSerpentKeyScheduleNative(keyByteLength),
    buildEncryptBody: (seed: PortBinding): CipherBody => ({
      nodes: buildSerpentEncryptBody(seed),
      output: serpentBodyOutputFrom(),
    }),
    buildDecryptBody: (seed: PortBinding): CipherBody => ({
      nodes: buildSerpentDecryptBody(seed),
      output: serpentBodyOutputFrom(),
    }),
  };
}
