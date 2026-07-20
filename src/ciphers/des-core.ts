/**
 * DES as a `BlockCipherCore` — the fifth cipher family to gain every mode of
 * operation, and the last of the two ciphers that were single-block only
 * because they lacked a core rather than because of anything about their shape.
 *
 * Like `aes-core.ts` / `serpent-core.ts` / `speck-32-64-core.ts`, this file
 * reimplements no cipher logic: it re-expresses the existing byte-native DES
 * builders (`des.ts` / `des-decrypt.ts`) through the contract. The specs the
 * modes generate from this core are byte-identical to running the single-block
 * DES spec once per block.
 *
 * ## Breadth, not block-size confidence
 *
 * DES's block is 8 bytes — the same width Blowfish already proved the mode
 * machine handles, and comfortably above Speck32/64's 4. So this core adds
 * *breadth* (a fifth family under the modes) rather than new confidence in the
 * block-size-generic arithmetic, exactly as Serpent's three AES-shaped cores
 * did. Nothing here exercises a width the suite has not already run.
 *
 * ## What DES *does* exercise first: a nested port-mode group inside an iterate
 *
 * Every prior core's body is a flat list — Serpent's round groups are siblings
 * between IP and FP, Blowfish's sixteen rounds are siblings before the
 * whitening. DES wraps its sixteen rounds in an outer port-mode `rounds` group
 * (it exists for graph-view collapse and the linear-view section header), which
 * carries its own `seedInput`/`bodyOutput`. Under a mode of operation that
 * group sits one scope deeper than any core has placed one before: the mode's
 * `iterate` seeds the body, IP reads the injected block, and the `rounds` group
 * re-seeds from IP's `state` *inside* the loop. `tests/des-modes-kat.test.ts`
 * runs multi-block vectors precisely so that boundary executes for real — a
 * single-block round-trip would pass without ever crossing it.
 *
 * ## Seed-threading was one binding
 *
 * The B4 port-native rebuild (universal-port Phase 4d) already had every round
 * chaining off its predecessor's published `"out"` port, and the `rounds` group
 * already seeding from IP across its own boundary. The Initial Permutation leaf
 * was the single node still naming `$input`, so `buildDesEncryptBody` /
 * `buildDesDecryptBody` taking a seed is the whole of the work — the Serpent
 * story, not the Blowfish one.
 *
 * ## Padding in single-block mode
 *
 * Registering this core also enables the padding overlay for single-block DES,
 * because "has a core" is the one gate for both facts (it means "we know your
 * block size") — the core-presence policy Blowfish established
 * (`docs/plans/foamy-prancing-wren.md` Phase C). DES's 8-byte pad is
 * byte-for-byte the Blowfish path.
 *
 * References: FIPS 46-3 (Data Encryption Standard). NIST SP 800-38A for the
 * modes themselves.
 */

import type { PortBinding } from "../core/types";
import type { BlockCipherCore, CipherBody } from "./block-cipher-core";
import { buildDesEncryptBody } from "./des";
import { buildDesDecryptBody } from "./des-decrypt";
import { buildDesKeyScheduleNative } from "./des-key-schedule-builder-native";

/** DES is 64 bits in, 64 bits out, under a 64-bit key (8 parity bits inside). */
const DES_BLOCK_BYTES = 8;
const DES_KEY_BYTES = 8;

/**
 * Build the DES `BlockCipherCore`.
 *
 * A single core, not a family: DES has exactly one key length and one block
 * size, so there is no variant axis to parameterize (unlike `aesCore(variant)`,
 * `serpentCore(keyByteLength)`, or `speck32_64Core(byteOrder)`). It is still a
 * function rather than a const for consistency with the other cores — and
 * because it is cheap, holding only closures until a mode asks for a body.
 */
export function desCore(): BlockCipherCore {
  return {
    // `id` matches the `Cipher` union string so the registry key + spec id agree.
    id: "des",
    displayName: "DES",
    familyName: "DES",
    blockByteLength: DES_BLOCK_BYTES,
    keyByteLength: DES_KEY_BYTES,
    // The decomposed (port-native) key schedule — PC-1 → 16× rotate-halves →
    // PC-2 → publish tail (key-schedule-decomposition K4a). One node, publishing
    // `aux["roundKey.0..15"]` once outside the per-block loop. Aux is global, so
    // those round keys reach every block's body across the iterate boundary.
    //
    // DES runs the SAME schedule in both directions — only the per-round
    // consumption order flips (decrypt round r reads `roundKey.{16-r}`), and
    // that lives in the round wiring, not here.
    buildKeySchedule: () => buildDesKeyScheduleNative(),
    buildEncryptBody: (seed: PortBinding): CipherBody => buildDesEncryptBody(seed),
    buildDecryptBody: (seed: PortBinding): CipherBody => buildDesDecryptBody(seed),
  };
}
