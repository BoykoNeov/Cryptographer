/**
 * Twofish as a `BlockCipherCore` — the **last** cipher family to gain modes of
 * operation, and the one that finishes the `N ciphers + M modes` story.
 *
 * Like `aes-core.ts` / `serpent-core.ts` / `speck-32-64-core.ts` / `des-core.ts`,
 * this file reimplements no cipher logic: it re-expresses the existing
 * port-native Twofish builders (`twofish-spec-builder.ts`) through the contract.
 * The specs the modes generate are byte-identical to running the single-block
 * Twofish spec once per block.
 *
 * ## What registering this core closes
 *
 * Until now Twofish was the only cipher stuck in single-block mode, and its
 * reason was never a block-size limitation — 16 bytes is AES's width, already
 * the best-covered case. The blocker was purely that its body hardcoded its
 * input source, so it could not be handed a block from an arbitrary port. That
 * turned out to be **one binding** (the input-whitening head's `permute@1`), the
 * same shape Serpent and Speck had: everything downstream already threaded a
 * seed round to round, and every subkey already reached its round through
 * **aux** (`aux-load-bytes@1` on `twofish.K.*`) rather than a port edge into the
 * key-setup group. That aux routing is what lets the schedule run once outside
 * the per-block loop while the rounds run inside it — a port edge across the
 * iterate's scope boundary would throw.
 *
 * ## Why Twofish is a weak block-size test but a real breadth test
 *
 * Its 16-byte block proves nothing new about the block-size-generic arithmetic
 * (Blowfish's 8 and Speck's 4 did that). What it does exercise is the mode
 * machine over the most structurally unusual body in the app: a 4-rail round
 * whose canonical graph layout is recognized by shape (`twofish-shape.ts`), now
 * nested one scope deeper inside a mode's `iterate`. Under CTR it is also the
 * last core to have its FORWARD body re-seeded from the counter on the `chain`
 * port — the block never enters the cipher at all.
 *
 * ## One core, not a family
 *
 * Twofish v1 is 128-bit-key only (192/256 deferred), so unlike `aesCore(variant)`
 * or `speck32_64Core(byteOrder)` this is a single exported constant rather than a
 * factory. A future 192/256 build would convert it to a family the same way.
 *
 * ## Padding in single-block mode
 *
 * Registering this core also enables the padding overlay for single-block
 * Twofish — "has a core" is the one gate for both facts, because it means "we
 * know your block size" (the core-presence policy from
 * `docs/plans/foamy-prancing-wren.md` Phase C).
 *
 * References: Schneier, Kelsey, Whiting, Wagner, Hall, Ferguson, "Twofish: A
 * 128-Bit Block Cipher" (1998). NIST SP 800-38A for the modes themselves.
 */

import type { PortBinding } from "../core/types";
import type { BlockCipherCore, CipherBody } from "./block-cipher-core";
import { TWOFISH_BLOCK_BYTES, TWOFISH_KEY_BYTES } from "./twofish-constants";
import { buildTwofishBody, buildTwofishKeySchedule } from "./twofish-spec-builder";

/**
 * The Twofish `BlockCipherCore` (128-bit key, v1).
 *
 * Both bodies exit at the output-whitening tail's final `permute@1` — the
 * builder names that binding, so there is no positional last-leaf assumption for
 * the iterate's required `bodyOutput` to lean on.
 */
export const twofishCore: BlockCipherCore = {
  // `id` matches the `Cipher` union string so the registry key + spec id agree.
  id: "twofish",
  displayName: "Twofish",
  familyName: "Twofish",
  blockByteLength: TWOFISH_BLOCK_BYTES,
  keyByteLength: TWOFISH_KEY_BYTES,
  // The key setup group — the opaque `twofish.h-expand@1` plus the 20 visible
  // PHT blocks — publishing `aux["twofish.K.0..39"]` and the key-dependent
  // S-boxes once, outside the per-block loop. Aux is global, so those reach
  // every block's rounds across the iterate boundary.
  buildKeySchedule: () => buildTwofishKeySchedule(),
  buildEncryptBody: (seed: PortBinding): CipherBody => buildTwofishBody("encrypt", seed),
  // Twofish decrypts by running the same network with the rotations inverted and
  // the round order, subkey consumption, and whitening indices reversed — the
  // builder owns all four, keyed off the direction.
  buildDecryptBody: (seed: PortBinding): CipherBody => buildTwofishBody("decrypt", seed),
};
