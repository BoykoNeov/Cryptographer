/**
 * The cipher-agnostic block-cipher contract — the seam that makes modes of
 * operation cost `N ciphers + M modes` instead of `N × M`.
 *
 * A **mode of operation** (ECB, CBC, CTR, …) is a rule for repeating a block
 * cipher over a message longer than one block. That rule is *identical* for
 * every cipher: CBC XORs each plaintext block with the previous ciphertext
 * block and encrypts the result, whether the "encrypt" underneath is AES,
 * Blowfish, or DES. Historically this app spelled that rule out once per
 * cipher (`aes-ecb-builder.ts`, `aes-cbc-builder.ts`), so a sixth cipher meant
 * re-typing every mode. This interface is the alternative: a mode builder takes
 * a `BlockCipherCore` and knows nothing else about the cipher.
 *
 * ## What a core must supply
 *
 * Everything a mode needs and nothing it doesn't: an identity (for spec ids and
 * prose), a block size (for the iterate's `blockByteLength` and the padding
 * overlay), a key size, a key schedule, and the two directional bodies.
 *
 * **The bodies are seed-parameterized.** A mode wraps the cipher body in a
 * port-mode `iterate`, which injects each block as `port(<iterate>,"in")`. A
 * body that hardcodes `$input` at its head throws inside an iterate body — the
 * runtime seeds `$input` at top scope only. So `buildEncryptBody` takes the
 * seed binding as an argument; the single-block specs pass `$input`, the modes
 * pass the injected block port.
 *
 * **The bodies return an explicit `output` binding.** The iterate's
 * `bodyOutput` is required and cannot use the runtime's implicit last-leaf
 * output rule, so a core must name its exit port rather than relying on
 * position. (Serpent and Speck have no `outputFrom` today for exactly this
 * reason — they'll need one when their cores land.)
 *
 * ## Why `id` is a `string` and not the `Cipher` union
 *
 * Deliberate. `Cipher` lives in `src/ui/stores/cipher.ts`, and nothing in
 * `src/ciphers/` imports from `src/ui/` — the dependency runs one way. Typing
 * `id` as `Cipher` would invert that layering for no gain: no mode builder
 * branches on *which* cipher it has, it only interpolates the id into a spec
 * id. A machine that enumerates the cipher list is the very thing this
 * interface exists to eliminate. The `Cipher`-keyed registry that maps a
 * *selected* cipher to its core lives at the consumption layer
 * (`src/ui/stores/block-cipher-cores.ts`), where knowing the union is correct.
 *
 * ## Designed against CTR, not just ECB/CBC
 *
 * CTR/CFB/OFB use the **forward cipher only** — CTR *decryption* still
 * encrypts the counter and XORs it with the ciphertext — and they need no
 * padding. So this contract deliberately does NOT bake in "decrypt ⇒ inverse
 * body" or "padding always applies". Both bodies are exposed independently and
 * padding is a per-mode flag, so adding CTR is a new `modes/ctr.ts` and zero
 * changes here. Baking CBC's assumptions in would mean rewriting the interface
 * on the second mode — reintroducing the N×M tax this removes.
 *
 * References: NIST SP 800-38A (block cipher modes of operation).
 */

import type { CipherSpec, PortBinding, StepNode } from "../core/types";

/**
 * Which way the cipher runs. Generic across every cipher and mode — it lived
 * in `aes-ecb-builder.ts` until the mode machine gave it a proper home.
 */
export type CipherDirection = "encrypt" | "decrypt";

/**
 * A cipher body plus the port its result leaves on. Modes need the binding
 * explicitly: the iterate's `bodyOutput` can't fall back to the runtime's
 * implicit last-leaf rule.
 *
 * `nodes` is `readonly` to match what the `build*BodyNative` builders return.
 */
export interface CipherBody {
  readonly nodes: readonly StepNode[];
  readonly output: PortBinding;
}

/**
 * One block cipher, reduced to what a mode of operation needs.
 *
 * A core is a *variant*, not a family: AES-128 and AES-256 are two cores (they
 * differ in `keyByteLength` and round count), while both report `familyName`
 * "AES".
 */
export interface BlockCipherCore {
  /**
   * Stable identity, interpolated into generated spec ids (`aes-128` →
   * `aes-128-cbc@1`). Matches the `Cipher` union's string value so the
   * registry key and the spec id agree, but see the header for why this is
   * typed `string`.
   */
  readonly id: string;
  /**
   * Full display name including the variant — "AES-128", "Blowfish". Used for
   * the generated spec's `name` ("AES-128 CBC").
   */
  readonly displayName: string;
  /**
   * Family name *without* the variant — "AES", "Blowfish". Used in narration
   * prose, where "encrypted with AES" reads correctly but "encrypted with
   * AES-128" would be needlessly specific about a detail the mode ignores.
   */
  readonly familyName: string;
  /** Block width in bytes: 16 AES/Serpent/Twofish, 8 DES/Blowfish, 4 Speck. */
  readonly blockByteLength: number;
  /** Key width in bytes. Drives the generated spec's `inputs.key.byteLength`. */
  readonly keyByteLength: number;
  /**
   * The key schedule as a single node, run once *outside* the per-block loop.
   * Every shipped schedule publishes its round keys to aux, and aux is global
   * — it crosses the iterate's scope boundary freely, which is exactly why
   * schedule-outside / body-inside works.
   */
  buildKeySchedule(): StepNode;
  /**
   * The forward cipher, reading its block from `seed`.
   * CTR/CFB/OFB call this for **both** directions.
   */
  buildEncryptBody(seed: PortBinding): CipherBody;
  /** The inverse cipher, reading its block from `seed`. */
  buildDecryptBody(seed: PortBinding): CipherBody;
}

/**
 * A mode of operation: the rule for repeating a core over a multi-block
 * message. Implemented once in `modes/`, consumed by every core.
 *
 * The two flags let the UI decide what to show without knowing the mode:
 * whether to enable the padding selector, and whether to show the IV field.
 */
export interface BlockMode {
  readonly id: string;
  /** ECB/CBC: true (the message must reach a block boundary). CTR: false. */
  readonly requiresPadding: boolean;
  /** CBC/CTR: true. ECB: false. */
  readonly requiresIv: boolean;
  build(core: BlockCipherCore, direction: CipherDirection): CipherSpec;
}

/** Terse `PortBinding` constructor — the mode builders wire a lot of ports. */
export const port = (node: string, portName: string): PortBinding => ({ node, port: portName });
