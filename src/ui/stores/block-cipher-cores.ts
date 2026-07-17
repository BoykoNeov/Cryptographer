/**
 * `Cipher` → `BlockCipherCore` registry — the consumption-layer half of the
 * cipher-agnostic mode machine.
 *
 * `src/ciphers/block-cipher-core.ts` defines what a core *is*, deliberately
 * without knowing the `Cipher` union: nothing in `src/ciphers/` imports from
 * `src/ui/`, and a mode builder that enumerated the cipher list would be the
 * very machine that seam exists to delete. But *something* has to map the
 * user's current selection to a core, and that mapping is legitimately
 * UI-layer knowledge — this store layer already owns "which cipher is active".
 * So the union-keyed lookup lives here, on the consuming side of the seam.
 *
 * Its own module rather than hung off `stores/spec.ts` because
 * `stores/padding.ts` and `stores/iv.ts` need `blockByteLength` too, and
 * `padding.ts` importing `spec.ts` would close an import cycle (`spec.ts`
 * already imports `padding.ts`). A leaf module both can read is the fix.
 *
 * ## Absence is meaningful, not unfinished
 *
 * `Partial<Record<…>>` is not a placeholder for a table someone forgot to
 * finish. A cipher is absent until its body is **seed-parameterized** — able
 * to read its block from an arbitrary port instead of hardcoding `$input` —
 * which is the per-cipher work Phase C templates on Blowfish. So presence
 * here answers a real question: *can this cipher run a mode of operation?*
 * Absence is exactly what keeps the other eight ciphers single-block, and a
 * total record would force all eleven cores to exist at once.
 *
 * Registering a core is therefore a deliberate act with three consequences:
 * the cipher gains ECB/CBC (given a `defaults` entry + a
 * `SUPPORTED_CIPHER_MODES_BY_CIPHER` row), `paddingLimits` starts deriving
 * its block size from the core rather than the fixed per-cipher switch, and
 * the padding overlay becomes reachable for it. See `docs/plans/foamy-prancing-wren.md`.
 */

import { aesCore } from "@/ciphers/aes-core";
import type { BlockCipherCore } from "@/ciphers/block-cipher-core";
import { blowfishCore } from "@/ciphers/blowfish-core";
import type { Cipher } from "./cipher";

/**
 * Every cipher whose body a mode of operation can drive.
 *
 * AES was first because it was the one cipher already seed-parameterized (Phase
 * A). Blowfish followed in Phase C and is the one that matters for confidence:
 * it is the first core whose block is **not 16 bytes**, so it is the first to
 * actually exercise the block-size-generic arithmetic Phase B introduced.
 * Everything before it could have hidden a stray hardcoded 16.
 *
 * Each `…Core()` call is cheap — the returned object holds closures, so no spec
 * is built until a mode builder asks for a body.
 */
const BLOCK_CIPHER_CORES: Partial<Record<Cipher, BlockCipherCore>> = {
  "aes-128": aesCore("aes-128"),
  "aes-192": aesCore("aes-192"),
  "aes-256": aesCore("aes-256"),
  blowfish: blowfishCore(),
};

/**
 * The core for a cipher, or `undefined` when it has none (⇒ single-block
 * only, and no padding overlay).
 */
export const blockCipherCoreFor = (cipher: Cipher): BlockCipherCore | undefined =>
  BLOCK_CIPHER_CORES[cipher];

/**
 * Shorthand for the common read: a cipher's block width in bytes, or
 * `undefined` when it has no core.
 *
 * `undefined` is the honest answer rather than a `16` default — it flows into
 * `applyPaddingScheme`'s `blockByteLength` param, where absence is what
 * *disables* the padding overlay. Defaulting here would silently splice a
 * 16-byte pad into a cipher whose block isn't 16.
 */
export const blockByteLengthFor = (cipher: Cipher): number | undefined =>
  BLOCK_CIPHER_CORES[cipher]?.blockByteLength;

/** True when a cipher has a core — i.e. can run ECB/CBC and take padding. */
export const hasBlockCipherCore = (cipher: Cipher): boolean =>
  BLOCK_CIPHER_CORES[cipher] !== undefined;
