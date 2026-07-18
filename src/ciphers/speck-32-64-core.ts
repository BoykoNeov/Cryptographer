/**
 * Speck32/64 as a `BlockCipherCore` — the fourth cipher family to gain every
 * mode of operation, and the first with a block **smaller than 8 bytes**.
 *
 * Like `aes-core.ts` / `serpent-core.ts`, this file reimplements no cipher
 * logic: it re-expresses the existing byte-native Speck builders
 * (`speck-32-64-builder.ts`) through the contract. The specs the modes generate
 * from this core are byte-identical to running the single-block Speck spec once
 * per block.
 *
 * ## Why Speck32/64 is the strongest block-size test yet
 *
 * Phases A + B made the mode machine block-size-generic, and Blowfish (8 bytes)
 * was the first core to exercise that past AES's 16. But 8 is still a "round"
 * width — a stray `>= 8` floor, or arithmetic that only works for even
 * block/word counts, would survive it. Speck32/64's **4-byte block** is the
 * first to push below: the iterate splits at 4, CBC's IV is 4 bytes wide (the
 * narrowest chain value the app has ever chained), and the padding overlay
 * fills to a 4-byte boundary. `tests/speck-modes-kat.test.ts` exercises all
 * three — including a non-multiple input padded up to 4, the surface an
 * exact-multiple round-trip never touches.
 *
 * ## One family, two cores (the byte-order pair)
 *
 * Speck32/64 ships under two byte conventions — BE-paper (Beaulieu et al. 2013
 * visual order) and LE-NSA (the NSA reference serialization). They are the same
 * word-level cipher; only how the 4 block bytes and the round-key bytes
 * serialize differs. So this is a `speck32_64Core(byteOrder)` family of two
 * (like `aesCore(variant)`), NOT one core — each carries its `byteOrder` into
 * the round params and the key schedule, and registers under its own `Cipher`
 * key (`speck-32-64-be` / `speck-32-64-le`).
 *
 * ## Padding in single-block mode
 *
 * Registering these cores also enables the padding overlay for single-block
 * Speck, because "has a core" is the one gate for both facts (it means "we know
 * your block size") — the same core-presence policy Blowfish established
 * (`docs/plans/foamy-prancing-wren.md` Phase C). Speck is the first cipher able
 * to show a pad filling to 4 bytes rather than 8 or 16.
 *
 * References: Beaulieu, Shors, Smith, Treatman-Clark, Weeks, Wingers, "The
 * SIMON and SPECK Families of Lightweight Block Ciphers" (2013), §3 + Table 4.1.
 * NIST SP 800-38A for the modes themselves.
 */

import type { PortBinding } from "../core/types";
import type { SpeckByteOrder } from "../steps/speck-word-codec";
import type { BlockCipherCore, CipherBody } from "./block-cipher-core";
import {
  SPECK_32_64_BLOCK_BYTES,
  SPECK_32_64_KEY_BYTES,
  buildSpeck32_64Body,
  buildSpeck32_64KeySchedule,
} from "./speck-32-64-builder";

/** Map a byte order to its `Cipher`-union id and display strings. */
const idFor = (byteOrder: SpeckByteOrder): string =>
  byteOrder === "be-paper" ? "speck-32-64-be" : "speck-32-64-le";

const displayFor = (byteOrder: SpeckByteOrder): string =>
  `Speck 32/64 (${byteOrder === "be-paper" ? "BE, paper" : "LE, NSA"})`;

/**
 * Build the `BlockCipherCore` for one Speck32/64 byte convention.
 *
 * The bodies are seed-parameterized via `buildSpeck32_64Body`: the single-block
 * spec passes `$input`, so a mode hands them the iterate's injected block port
 * instead. Both directions exit at the last round's `state` port — the builder
 * names it (the round id differs per direction: `round.22` vs
 * `round-inverse.22`), so there is no shared `outputFrom` helper to reach for.
 */
export function speck32_64Core(byteOrder: SpeckByteOrder): BlockCipherCore {
  return {
    // `id` matches the `Cipher` union string so the registry key + spec id agree.
    id: idFor(byteOrder),
    displayName: displayFor(byteOrder),
    // Narration prose says "Speck", not "Speck 32/64 (BE, paper)" — the byte
    // convention is irrelevant to how a mode chains blocks.
    familyName: "Speck",
    blockByteLength: SPECK_32_64_BLOCK_BYTES,
    keyByteLength: SPECK_32_64_KEY_BYTES,
    // The decomposed (port-native) ARX key schedule — one node, publishes
    // `aux["roundKey.0..21"]` once outside the per-block loop. Aux is global, so
    // those round keys reach every block's body across the iterate boundary.
    buildKeySchedule: () => buildSpeck32_64KeySchedule(byteOrder),
    buildEncryptBody: (seed: PortBinding): CipherBody =>
      buildSpeck32_64Body(byteOrder, "encrypt", seed),
    // Speck decrypts by running the inverse round (`speck.round-inverse@1`) with
    // the round keys consumed in reverse leaf order — the builder owns both.
    buildDecryptBody: (seed: PortBinding): CipherBody =>
      buildSpeck32_64Body(byteOrder, "decrypt", seed),
  };
}
