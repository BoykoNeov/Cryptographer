/**
 * DES ECB + CBC known-answer tests — the proof that the cipher-agnostic mode
 * machine drives DES's Feistel body once per 8-byte block, including across the
 * one structure DES introduces that no earlier core had: a **port-mode group
 * nested inside the mode's iterate**.
 *
 * ## What this file adds over the existing coverage
 *
 * DES's single-block specs are already KAT-verified (`des-vectors.test.ts`),
 * and the mode machine is already generic-verified (AES + Blowfish + a fake
 * 8-byte core in `block-size-generic-modes.test.ts`). DES's 8-byte block is
 * Blowfish's, so width is NOT what this file buys — it is breadth, plus one
 * genuinely new structural surface.
 *
 * That surface: every prior core's body is a flat list of siblings (Serpent's
 * round groups between IP and FP, Blowfish's sixteen rounds before the
 * whitening). DES wraps its sixteen rounds in an outer port-mode `rounds` group
 * carrying its own `seedInput`/`bodyOutput`. Under a mode that group sits one
 * scope deeper than any core has placed one: the iterate seeds the body, IP
 * reads the injected block, and `rounds` re-seeds from IP's `state` *inside*
 * the loop. **Every vector here is therefore multi-block** — a single-block
 * round-trip would pass without that boundary ever executing more than once.
 *
 * ## The oracle: real, external DES via 3DES with a tripled key
 *
 * OpenSSL 3 moved single-DES to the legacy provider, so `createCipheriv("des-ecb")`
 * throws in this environment. But 3DES-EDE is `E_K3(D_K2(E_K1(m)))`, so with
 * `K1 = K2 = K3 = K` the two inner operations cancel and EDE **is** single DES:
 * `des-ede3` under `K‖K‖K` reproduces the classic Davies worked example
 * (`0123456789abcdef` under `133457799bbcdff1` → `85e813540f0ab405`), which is
 * asserted below as a guard on the oracle itself. `des-ede3-cbc` under the same
 * tripled key oracles DES-CBC. So unlike the Speck/Serpent/Blowfish mode KATs —
 * which had to compose a trusted single-block spec because no external oracle
 * existed — this file checks against a genuinely independent implementation for
 * every mode vector.
 *
 * Padding is oracled separately from the transform (`setAutoPadding(false)`
 * everywhere, with the padded bytes built here by hand): otherwise a PKCS-scheme
 * disagreement between node and the app would masquerade as a cipher bug.
 *
 * References: FIPS 46-3; NIST SP 800-38A §6.1-6.2 (ECB, CBC).
 */

import { createCipheriv, createDecipheriv } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { desCore } from "@/ciphers/des-core";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { buildCbcSpec } from "@/ciphers/modes/cbc";
import { buildEcbSpec } from "@/ciphers/modes/ecb";
import { deriveAuxGraph, validateGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { applyPaddingScheme } from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import type { Cipher } from "@/ui/stores/cipher";
import { paddingLimits } from "@/ui/stores/padding";
import { describe, expect, it } from "vitest";

/** DES: 64-bit block, 64-bit key. */
const B = 8;

const core = desCore();

/** The Davies worked-example key — the same one `des-vectors.test.ts` uses. */
const KEY = "133457799bbcdff1";

/** A nonzero IV. All-zero would hide a chain value that never got read. */
const IV = "0a0b0c0d0e0f1011";

/**
 * Four 8-byte blocks. Blocks 0 and 2 are IDENTICAL on purpose (ECB leaks them,
 * CBC hides them). Block 0 is the published Davies plaintext, so ECB block 0
 * lands on a published constant.
 */
const ANCHOR_PT = "0123456789abcdef";
const ANCHOR_CT = "85e813540f0ab405";
const PT_4_BLOCKS = `${ANCHOR_PT}fedcba9876543210${ANCHOR_PT}00112233445566ff`;

// ─── The external oracle: node:crypto 3DES under a tripled key ────────────────

/** `K‖K‖K` — the 24-byte 3DES key that degenerates EDE to single DES. */
const tripled = (keyHex: string): Buffer => {
  const k = Buffer.from(keyHex, "hex");
  return Buffer.concat([k, k, k]);
};

/** Raw (unpadded) transform through node's 3DES. `ivHex` null ⇒ ECB. */
const nodeOracle = (inputHex: string, encrypt: boolean, ivHex: string | null): string => {
  const algo = ivHex === null ? "des-ede3" : "des-ede3-cbc";
  const iv = ivHex === null ? null : Buffer.from(ivHex, "hex");
  const c = encrypt
    ? createCipheriv(algo, tripled(KEY), iv)
    : createDecipheriv(algo, tripled(KEY), iv);
  // Padding is asserted separately — the oracle only ever runs the raw transform.
  c.setAutoPadding(false);
  return Buffer.concat([c.update(Buffer.from(inputHex, "hex")), c.final()]).toString("hex");
};

// ─── Running the app's real mode specs ────────────────────────────────────────

const runMode = (spec: CipherSpec, inputHex: string, ivHex: string | null): string => {
  const aux = new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]);
  if (ivHex) aux.set("iv", bytesFromHex(ivHex));
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: aux,
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return hexFromBytes(trace.finalState.bytes);
};

const blocksOf = (hex: string): string[] => {
  const out: string[] = [];
  for (let i = 0; i < hex.length; i += B * 2) out.push(hex.slice(i, i + B * 2));
  return out;
};

describe("DES modes — the Feistel body driven per 8-byte block by the generic machine", () => {
  it("the 3DES-with-tripled-key oracle really is single DES (Davies vector)", () => {
    // Guards the oracle itself before anything is measured against it. If
    // OpenSSL ever stopped degenerating EDE under equal keys, every assertion
    // below would be checking the app against 3DES — and this fails first.
    expect(nodeOracle(ANCHOR_PT, true, null)).toBe(ANCHOR_CT);
  });

  it("the core reports DES's real geometry (8-byte block, 8-byte key)", () => {
    expect(core.blockByteLength).toBe(8);
    expect(core.keyByteLength).toBe(8);
    expect(core.id).toBe("des");
  });

  describe("ECB — every block independently (SP 800-38A §6.1)", () => {
    it("encrypts 4 blocks byte-equal to node's DES", () => {
      const got = runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, null);
      expect(got).toBe(nodeOracle(PT_4_BLOCKS, true, null));
      expect(got.length / 2).toBe(32);
    });

    it("decrypts 4 blocks byte-equal to node's DES, and inverts encrypt", () => {
      const ct = runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, null);
      expect(runMode(buildEcbSpec(core, "decrypt"), ct, null)).toBe(nodeOracle(ct, false, null));
      expect(runMode(buildEcbSpec(core, "decrypt"), ct, null)).toBe(PT_4_BLOCKS);
    });

    it("its anchor block lands on the PUBLISHED Davies DES vector", () => {
      // ECB encrypts each block independently, so a published single-block
      // vector IS a published ECB-block vector.
      const ct = blocksOf(runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, null));
      expect(ct[0]).toBe(ANCHOR_CT);
    });

    it("leaks identical plaintext blocks as identical ciphertext blocks", () => {
      const ct = blocksOf(runMode(buildEcbSpec(core, "encrypt"), PT_4_BLOCKS, null));
      expect(ct[0]).toBe(ct[2]);
    });
  });

  describe("CBC — chaining across the iterate boundary (SP 800-38A §6.2)", () => {
    it("encrypts 4 blocks byte-equal to node's DES-CBC under a nonzero IV", () => {
      // The chain value has to survive three iterate boundaries to match. This
      // is also the assertion that most directly exercises the nested `rounds`
      // group re-seeding inside the loop: a body that mis-seeded on iteration
      // ≥1 would still match on block 0 and diverge here.
      const got = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, IV);
      expect(got).toBe(nodeOracle(PT_4_BLOCKS, true, IV));
    });

    it("decrypts byte-equal to node's DES-CBC, and inverts encrypt", () => {
      const ct = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, IV);
      expect(runMode(buildCbcSpec(core, "decrypt"), ct, IV)).toBe(nodeOracle(ct, false, IV));
      expect(runMode(buildCbcSpec(core, "decrypt"), ct, IV)).toBe(PT_4_BLOCKS);
    });

    it("hides the repeated plaintext block that ECB leaks", () => {
      const ct = blocksOf(runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, IV));
      expect(ct[0]).not.toBe(ct[2]);
    });

    it("a different IV changes the whole ciphertext, still matching node", () => {
      const ctA = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, IV);
      const ctB = runMode(buildCbcSpec(core, "encrypt"), PT_4_BLOCKS, "0000000000000000");
      expect(ctB).not.toBe(ctA);
      expect(ctB).toBe(nodeOracle(PT_4_BLOCKS, true, "0000000000000000"));
    });
  });

  describe("padding overlay — reachable now that DES has a core", () => {
    /** PKCS#7 (RFC 5652 §6.3), spelled out so the test doesn't reuse the code under test. */
    const pkcs7Pad = (bytes: Uint8Array): Uint8Array => {
      const n = B - (bytes.length % B);
      return Uint8Array.from([...bytes, ...Array.from({ length: n }, () => n)]);
    };

    /** 5 bytes — a non-multiple, so PKCS#7 appends three 0x03s. */
    const FIVE = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x01]);

    it("multi-block ECB pads 12 bytes up to 16 (two 8-byte blocks), matching node", () => {
      const twelve = Uint8Array.from({ length: 12 }, (_, i) => i + 1);
      const spec = applyPaddingScheme(
        buildEcbSpec(core, "encrypt"),
        "encrypt",
        "pkcs7",
        core.blockByteLength,
      );
      const ct = runMode(spec, hexFromBytes(twelve), null);
      expect(ct.length / 2).toBe(16);
      // The oracle sees the hand-padded bytes, so a PKCS disagreement can't hide.
      expect(ct).toBe(nodeOracle(hexFromBytes(pkcs7Pad(twelve)), true, null));
    });

    it("single-block PKCS#7 pads 5 bytes up to ONE 8-byte block, matching node", () => {
      const padded = applyPaddingScheme(desSpec, "encrypt", "pkcs7", core.blockByteLength);
      const ct = runMode(padded, hexFromBytes(FIVE), null);
      expect(ct.length / 2).toBe(8);
      expect(ct).toBe(nodeOracle(hexFromBytes(pkcs7Pad(FIVE)), true, null));
    });

    it("round-trips a short input: encrypt(pad) then decrypt(unpad) returns the original", () => {
      const enc = applyPaddingScheme(desSpec, "encrypt", "pkcs7", core.blockByteLength);
      const dec = applyPaddingScheme(desDecryptSpec, "decrypt", "pkcs7", core.blockByteLength);
      expect(runMode(dec, runMode(enc, hexFromBytes(FIVE), null), null)).toBe(hexFromBytes(FIVE));
    });

    it("paddingLimits derives DES's bounds from its 8-byte core, not the coreless switch", () => {
      // Pre-core this returned a fixed {8,8}; now the single-block PKCS#7
      // encrypt bound is 0..7 (blockSize-1).
      expect(paddingLimits("encrypt", "pkcs7", core.id as Cipher, "single-block")).toEqual({
        min: 0,
        max: 7,
      });
    });
  });

  describe("mode traces stay well-formed", () => {
    const traceFor = (spec: CipherSpec, ivHex: string | null) => {
      const aux = new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]);
      if (ivHex) aux.set("iv", bytesFromHex(ivHex));
      return runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(PT_4_BLOCKS)),
        initialAux: aux,
      });
    };

    it.each([
      ["ecb", () => buildEcbSpec(core, "encrypt"), null],
      ["cbc", () => buildCbcSpec(core, "encrypt"), IV],
    ] as const)("%s: per-iteration frames carry :b{i} stepId suffixes", (_name, build, ivHex) => {
      const trace = traceFor(build(), ivHex);
      for (let i = 0; i < 4; i++) {
        expect(trace.frames.some((f) => f.stepId.endsWith(`:b${i}`))).toBe(true);
      }
      expect(trace.frames.some((f) => f.stepId.endsWith(":b4"))).toBe(false);
      expect(trace.frames.some((f) => f.blockIndex === 3)).toBe(true);
    });

    it.each([
      ["ecb", () => buildEcbSpec(core, "encrypt"), null],
      ["cbc", () => buildCbcSpec(core, "encrypt"), IV],
    ] as const)(
      "%s: the nested `rounds` group runs inside every iteration",
      (_name, build, ivHex) => {
        // DES's structural first: a port-mode group one scope deeper than any
        // earlier core placed one. If it only ran for block 0, the KATs above
        // would fail — this asserts the shape directly so a failure names it.
        const trace = traceFor(build(), ivHex);
        for (let i = 0; i < 4; i++) {
          expect(
            trace.frames.some(
              (f) => f.stepId.startsWith("round.16.") && f.stepId.endsWith(`:b${i}`),
            ),
          ).toBe(true);
        }
      },
    );

    it.each([
      ["ecb", () => buildEcbSpec(core, "encrypt"), null],
      ["cbc", () => buildCbcSpec(core, "encrypt"), IV],
    ] as const)("%s: the derived aux graph has no warnings", (_name, build, ivHex) => {
      const spec = build();
      const trace = traceFor(spec, ivHex);
      // Orphaned reads / unused writes / cycles would mean the key schedule's
      // aux publish isn't reaching the body across the iterate's scope boundary.
      expect(validateGraph(deriveAuxGraph(trace, spec), trace)).toEqual([]);
    });
  });
});
