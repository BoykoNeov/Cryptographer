/**
 * CFB known-answer tests across **every** `BlockCipherCore`.
 *
 * ## What CFB tests that CTR doesn't
 *
 * CTR proved every core's forward body can be seeded from the iterate's `chain`
 * port rather than `in`. CFB re-uses that (the register also rides `chain`), so
 * as a *core* exercise it adds little. What it adds is a **mode** property no
 * other shipped mode has: encrypt and decrypt run the same leaves in the same
 * order and differ in exactly one wire — which port refills the feedback
 * register.
 *
 *   encrypt: register ← cfb-xor.output   (the ciphertext we EMIT)
 *   decrypt: register ← port(it,"in")    (the ciphertext that ARRIVED)
 *
 * ## Why a round-trip is not enough here — the trap this file exists for
 *
 * Get *one* of those two wires wrong and the round-trip breaks loudly. But get
 * **both** wrong in a matched way — say encrypt feeds back its input and
 * decrypt feeds back its output, so both registers hold the plaintext — and
 * encrypt/decrypt remain perfect inverses of each other while implementing a
 * mode that is not CFB and that no other implementation can read.
 *
 * So round-trip is asserted last and counts for least. The weight is carried by
 * two things a self-consistent-but-wrong pair cannot satisfy:
 *
 * 1. **External, for AES** — `node:crypto`'s `aes-{128,192,256}-cfb`. Note this
 *    is CFB128 (full-block feedback), which is what this mode builds; node's
 *    `-cfb8` / `-cfb1` are different modes and must not be substituted.
 * 2. **Constructed-from-ECB, for every core** — the register sequence is
 *    rebuilt below from first principles and each register encrypted through
 *    the core's *own already-KAT-verified* ECB spec. Not circular: ECB is
 *    pinned against published vectors in the per-cipher KAT files, and the
 *    feedback rule is re-implemented here independently of the builder.
 *
 * A third, structural check backs them up: CFB's signature **error
 * propagation** — corrupting one ciphertext byte damages exactly two plaintext
 * blocks and nothing after them. That shape follows only if the register truly
 * holds the previous ciphertext block, and it is checked per core.
 *
 * References: NIST SP 800-38A §6.3 (CFB).
 */

import { createCipheriv, createDecipheriv } from "node:crypto";
import { aesCore } from "@/ciphers/aes-core";
import type { BlockCipherCore, CipherDirection } from "@/ciphers/block-cipher-core";
import { blowfishCore } from "@/ciphers/blowfish-core";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desCore } from "@/ciphers/des-core";
import { buildCfbSpec } from "@/ciphers/modes/cfb";
import { buildEcbSpec } from "@/ciphers/modes/ecb";
import { serpentCore } from "@/ciphers/serpent-core";
import { speck32_64Core } from "@/ciphers/speck-32-64-core";
import { twofishCore } from "@/ciphers/twofish-core";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { hasBlockCipherCore } from "@/ui/stores/block-cipher-cores";
import type { Cipher } from "@/ui/stores/cipher";
import { isCipherModeSupported } from "@/ui/stores/cipher-mode";
import { paddingLimits } from "@/ui/stores/padding";
import { describe, expect, it } from "vitest";

// ─── The cores under test ─────────────────────────────────────────────────────

/**
 * Mirrors `BLOCK_CIPHER_CORES` in `stores/block-cipher-cores.ts` (which isn't
 * exported). The "covers every cored cipher" test below fails if the two drift,
 * so a new core cannot land without gaining CFB coverage here.
 */
const CORES: ReadonlyArray<{ cipher: Cipher; core: BlockCipherCore }> = [
  { cipher: "aes-128", core: aesCore("aes-128") },
  { cipher: "aes-192", core: aesCore("aes-192") },
  { cipher: "aes-256", core: aesCore("aes-256") },
  { cipher: "speck-32-64-be", core: speck32_64Core("be-paper") },
  { cipher: "speck-32-64-le", core: speck32_64Core("le-nsa") },
  { cipher: "blowfish", core: blowfishCore() },
  { cipher: "des", core: desCore() },
  { cipher: "serpent-128", core: serpentCore(16) },
  { cipher: "serpent-192", core: serpentCore(24) },
  { cipher: "serpent-256", core: serpentCore(32) },
  { cipher: "twofish", core: twofishCore },
];

const ALL_CIPHERS: readonly Cipher[] = [
  "aes-128",
  "aes-192",
  "aes-256",
  "speck-32-64-be",
  "speck-32-64-le",
  "blowfish",
  "des",
  "serpent-128",
  "serpent-192",
  "serpent-256",
  "twofish",
];

// ─── Deterministic per-core test material ─────────────────────────────────────

/** A fixed, nonzero, non-patterned byte at index i — no accidental symmetry. */
const fillByte = (i: number): number => (i * 37 + 11) & 0xff;
const fillHex = (n: number): string =>
  Array.from({ length: n }, (_, i) => fillByte(i).toString(16).padStart(2, "0")).join("");

const keyFor = (core: BlockCipherCore): string => fillHex(core.keyByteLength);

/** Initial feedback register S₀, one block wide. */
const ivFor = (core: BlockCipherCore): string => fillHex(core.blockByteLength);

/**
 * Four blocks, with blocks 0 and 2 identical. Under ECB those would encrypt
 * identically; under CFB the register differs, so they must not — the chaining
 * half of the mode's identity.
 */
const plaintextFor = (core: BlockCipherCore): string => {
  const b = core.blockByteLength;
  const blk0 = fillHex(b);
  const blk1 = fillHex(b).split("").reverse().join("");
  const blk3 = "a".repeat(b * 2);
  return `${blk0}${blk1}${blk0}${blk3}`;
};

// ─── Running the app's real specs ─────────────────────────────────────────────

const runMode = (spec: CipherSpec, inputHex: string, keyHex: string, ivHex?: string): string => {
  const aux = new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]);
  if (ivHex !== undefined) aux.set("iv", bytesFromHex(ivHex));
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: aux,
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return hexFromBytes(trace.finalState.bytes);
};

// ─── The constructed oracle: CFB rebuilt on top of the core's verified ECB ────

/**
 * Expected CFB output, built from first principles.
 *
 * Walks the message a block at a time, encrypting the current register through
 * the core's ECB spec to get that block's keystream, XORing (trimmed to the
 * block's real width, so a ragged tail is handled), and then refilling the
 * register with **the ciphertext block** — which is the *output* when
 * encrypting and the *input* when decrypting. That direction-dependent line is
 * the thing under test, spelled out here independently of the builder.
 *
 * Necessarily serial: unlike CTR's counter sequence, register i+1 isn't known
 * until block i's ciphertext exists, so this is one ECB call per block.
 */
const cfbOracle = (
  core: BlockCipherCore,
  inputHex: string,
  keyHex: string,
  ivHex: string,
  direction: CipherDirection,
): string => {
  const b = core.blockByteLength;
  const input = bytesFromHex(inputHex);
  const ecb = buildEcbSpec(core, "encrypt");

  let register = bytesFromHex(ivHex);
  const out = new Uint8Array(input.length);

  for (let off = 0; off < input.length; off += b) {
    const block = input.subarray(off, Math.min(off + b, input.length));
    // The register is ALWAYS a full block wide — that is what keeps the core
    // untouched by the ragged tail.
    const keystream = bytesFromHex(runMode(ecb, hexFromBytes(register), keyHex));
    for (let i = 0; i < block.length; i++) {
      out[off + i] = (block[i] as number) ^ (keystream[i] as number);
    }
    // Refill with the ciphertext block: what we produced (encrypt) or what
    // arrived (decrypt). A final short block never feeds anything.
    const cipherBlock = direction === "encrypt" ? out.subarray(off, off + block.length) : block;
    register = new Uint8Array(cipherBlock);
  }
  return hexFromBytes(out);
};

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("CFB across every BlockCipherCore", () => {
  it("covers every cipher that has a core (guards against a new core skipping CFB)", () => {
    const cored = ALL_CIPHERS.filter((c) => hasBlockCipherCore(c));
    expect(CORES.map((e) => e.cipher).sort()).toEqual([...cored].sort());
  });

  it("every cored cipher advertises CFB in the mode table", () => {
    for (const { cipher } of CORES) {
      expect(isCipherModeSupported(cipher, "cfb")).toBe(true);
    }
  });

  // ── The external oracle: AES vs node:crypto ────────────────────────────────
  describe("AES — byte-equal to node:crypto's aes-*-cfb (external oracle)", () => {
    for (const variant of ["aes-128", "aes-192", "aes-256"] as const) {
      const core = aesCore(variant);
      const key = keyFor(core);
      const iv = ivFor(core);
      const pt = plaintextFor(core);

      it(`${variant} encrypt matches node's ${variant}-cfb`, () => {
        // node's `-cfb` is CFB128 — full-block feedback, the variant this mode
        // builds. `-cfb8`/`-cfb1` are different modes and would not match.
        const c = createCipheriv(`${variant}-cfb`, bytesFromHex(key), bytesFromHex(iv));
        const expected = Buffer.concat([c.update(Buffer.from(pt, "hex")), c.final()]).toString(
          "hex",
        );
        expect(runMode(buildCfbSpec(core, "encrypt"), pt, key, iv)).toBe(expected);
      });

      it(`${variant} decrypt matches node's ${variant}-cfb decipher`, () => {
        // THE assertion that pins the decrypt-side feedback wire. A decrypt that
        // refilled its register from the plaintext it produced (rather than the
        // ciphertext that arrived) can still be a perfect inverse of a
        // matching-wrong encrypt — and would fail only here, against a real
        // independent implementation.
        const ct = runMode(buildCfbSpec(core, "encrypt"), pt, key, iv);
        const d = createDecipheriv(`${variant}-cfb`, bytesFromHex(key), bytesFromHex(iv));
        const expected = Buffer.concat([d.update(Buffer.from(ct, "hex")), d.final()]).toString(
          "hex",
        );
        expect(runMode(buildCfbSpec(core, "decrypt"), ct, key, iv)).toBe(expected);
      });

      it(`${variant} decrypt of an ARBITRARY buffer matches node (not just of its own ciphertext)`, () => {
        // Decrypting a buffer that was never a ciphertext removes the last way
        // encrypt and decrypt could be conspiring: there is no encrypt run
        // involved at all.
        const d = createDecipheriv(`${variant}-cfb`, bytesFromHex(key), bytesFromHex(iv));
        const expected = Buffer.concat([d.update(Buffer.from(pt, "hex")), d.final()]).toString(
          "hex",
        );
        expect(runMode(buildCfbSpec(core, "decrypt"), pt, key, iv)).toBe(expected);
      });
    }
  });

  // ── The constructed oracle + structural properties, per core ───────────────
  for (const { cipher, core } of CORES) {
    describe(`${cipher} (${core.blockByteLength}-byte block)`, () => {
      const key = keyFor(core);
      const iv = ivFor(core);
      const pt = plaintextFor(core);
      const b = core.blockByteLength;
      const hexBlock = b * 2; // hex chars per block

      it("encrypts to keystream ⊕ message, the keystream being its own ECB over IV, C₀, C₁, …", () => {
        expect(runMode(buildCfbSpec(core, "encrypt"), pt, key, iv)).toBe(
          cfbOracle(core, pt, key, iv, "encrypt"),
        );
      });

      it("decrypt refills the register from the ARRIVING ciphertext, not the plaintext it emits", () => {
        // The core-generic counterpart of the node-oracle decrypt test above:
        // the oracle re-implements the feedback rule, so a decrypt spec wired to
        // feed back `cfb-xor.output` fails here even though it would round-trip.
        const ct = runMode(buildCfbSpec(core, "encrypt"), pt, key, iv);
        expect(runMode(buildCfbSpec(core, "decrypt"), ct, key, iv)).toBe(
          cfbOracle(core, ct, key, iv, "decrypt"),
        );
      });

      it("runs the FORWARD cipher in both directions (decrypt never invokes the inverse body)", () => {
        // Both directions' keystreams come from `buildEncryptBody`, so block 0's
        // keystream is identical — and block 0 uses the same register (the IV)
        // in both. Hence encrypting X and decrypting X agree on block 0
        // regardless of what the feedback does afterwards.
        const enc = runMode(buildCfbSpec(core, "encrypt"), pt, key, iv);
        const dec = runMode(buildCfbSpec(core, "decrypt"), pt, key, iv);
        expect(dec.slice(0, hexBlock)).toBe(enc.slice(0, hexBlock));
        // …and they must diverge afterwards, because the registers differ from
        // block 1 on. If these matched too, both directions would be feeding
        // back the same port — the matched-pair bug this file guards.
        expect(dec.slice(hexBlock)).not.toBe(enc.slice(hexBlock));
      });

      it("round-trips plaintext → ciphertext → plaintext", () => {
        const ct = runMode(buildCfbSpec(core, "encrypt"), pt, key, iv);
        expect(runMode(buildCfbSpec(core, "decrypt"), ct, key, iv)).toBe(pt);
        expect(ct).not.toBe(pt);
      });

      it("does NOT leak the repeated plaintext block that ECB leaks", () => {
        // Blocks 0 and 2 are identical plaintext. CFB chains, so they must not
        // encrypt identically — the CBC half of the mode's inheritance.
        const ct = runMode(buildCfbSpec(core, "encrypt"), pt, key, iv);
        expect(ct.slice(0, hexBlock)).not.toBe(ct.slice(2 * hexBlock, 3 * hexBlock));
      });

      it("propagates a one-byte ciphertext corruption into exactly two plaintext blocks", () => {
        // CFB's signature error behaviour, and a structural proof that the
        // register holds the previous CIPHERTEXT block:
        //   • block 1 is damaged in one byte  — it is XORed with the damaged
        //     keystream position? No: block 1 is XORed with E(C_1) …
        // Concretely, flipping a byte in ciphertext block 1 damages
        //   - plaintext block 1 in that byte alone (XOR is positional), and
        //   - plaintext block 2 entirely (its register is that corrupted block),
        // while blocks 0 and 3 recover untouched. A register fed from anything
        // other than the previous ciphertext gives a different damage pattern.
        const ct = bytesFromHex(runMode(buildCfbSpec(core, "encrypt"), pt, key, iv));
        const corrupted = new Uint8Array(ct);
        corrupted[b] = (corrupted[b] as number) ^ 0x80; // first byte of block 1
        const got = bytesFromHex(
          runMode(buildCfbSpec(core, "decrypt"), hexFromBytes(corrupted), key, iv),
        );
        const clean = bytesFromHex(pt);

        // Block 0: untouched (its register is the IV, its keystream unaffected).
        expect(hexFromBytes(got.subarray(0, b))).toBe(hexFromBytes(clean.subarray(0, b)));
        // Block 1: exactly the flipped bit, nothing else.
        expect(got[b]).toBe((clean[b] as number) ^ 0x80);
        expect(hexFromBytes(got.subarray(b + 1, 2 * b))).toBe(
          hexFromBytes(clean.subarray(b + 1, 2 * b)),
        );
        // Block 2: wholly garbled — its register IS the corrupted block.
        expect(hexFromBytes(got.subarray(2 * b, 3 * b))).not.toBe(
          hexFromBytes(clean.subarray(2 * b, 3 * b)),
        );
        // Block 3: recovered. Self-synchronization — CFB re-syncs after one
        // block, which is the property that distinguishes it from CBC's
        // permanent divergence and CTR's single-block-only damage.
        expect(hexFromBytes(got.subarray(3 * b, 4 * b))).toBe(
          hexFromBytes(clean.subarray(3 * b, 4 * b)),
        );
      });

      it("a different IV changes the entire ciphertext", () => {
        const ctA = runMode(buildCfbSpec(core, "encrypt"), pt, key, iv);
        const zeroIv = "00".repeat(b);
        const ctB = runMode(buildCfbSpec(core, "encrypt"), pt, key, zeroIv);
        expect(ctB).not.toBe(ctA);
        expect(ctB).toBe(cfbOracle(core, pt, key, zeroIv, "encrypt"));
      });

      it("needs NO padding — a short message encrypts to an equally short ciphertext", () => {
        const short = "7e".repeat(b - 1);
        const ct = runMode(buildCfbSpec(core, "encrypt"), short, key, iv);
        expect(ct.length / 2).toBe(b - 1);
        expect(ct).toBe(cfbOracle(core, short, key, iv, "encrypt"));
        expect(runMode(buildCfbSpec(core, "decrypt"), ct, key, iv)).toBe(short);
      });

      it("handles a message that is neither a whole block nor shorter than one", () => {
        // The genuinely ragged case: a full block plus a remainder, so both the
        // full-width path and the trim path run in the same trace.
        const ragged = `${fillHex(b)}7e7e`;
        const ct = runMode(buildCfbSpec(core, "encrypt"), ragged, key, iv);
        expect(ct.length).toBe(ragged.length);
        expect(ct).toBe(cfbOracle(core, ragged, key, iv, "encrypt"));
        expect(runMode(buildCfbSpec(core, "decrypt"), ct, key, iv)).toBe(ragged);
      });

      it("paddingLimits gives CFB the stream-mode bounds, not CBC's block-aligned ones", () => {
        expect(paddingLimits("decrypt", "none", cipher, "cfb").min).toBe(1);
        expect(paddingLimits("encrypt", "none", cipher, "cfb").min).toBe(1);
        // CBC keeps the block floor — the relaxation must not have leaked.
        expect(paddingLimits("decrypt", "none", cipher, "cbc").min).toBe(b);
      });

      it("the cipher body is seeded from the REGISTER, never from the message block", () => {
        // Block 0's register is the IV in every run, so block 0's keystream is
        // key-and-IV-only. Two different plaintexts must therefore differ in
        // block 0 by exactly their own difference. (Only block 0: from block 1
        // on the registers diverge, which is the chaining.)
        const altPt = "00".repeat(pt.length / 2);
        const a = bytesFromHex(runMode(buildCfbSpec(core, "encrypt"), pt, key, iv));
        const z = bytesFromHex(runMode(buildCfbSpec(core, "encrypt"), altPt, key, iv));
        const p = bytesFromHex(pt);
        for (let i = 0; i < b; i++) {
          expect((a[i] as number) ^ (z[i] as number)).toBe(p[i] as number);
        }
      });
    });
  }
});
