/**
 * The padding overlay over Blowfish — the first cipher whose pad fills to 8
 * bytes rather than 16.
 *
 * ## Why this file exists
 *
 * Registering `blowfishCore()` enables the padding overlay for Blowfish, because
 * "has a core" is the single gate for both "can run ECB/CBC" and "the overlay
 * knows your block size". That coupling was a deliberate Phase C decision
 * (`docs/plans/foamy-prancing-wren.md`): the alternative needed a second gate
 * that could only have encoded "AES is special" — either by resurrecting
 * `isAesCipher` (the cipher-enumerating anti-pattern Phases A+B deleted) or by
 * a `supportsSingleBlockPadding` flag true for AES and false for Blowfish for no
 * discoverable reason. So Blowfish gains PKCS#7 in single-block, exactly as AES
 * has had since May 2026.
 *
 * ## Two hazards, both invisible to a param check
 *
 * 1. **A floating pad.** The overlay splices a pad reading `$input` and repoints
 *    `$input`'s consumers at it. AES single-block's consumer is a LEAF
 *    `portInputs` binding; Blowfish's round 1 is a port-mode `group` seeded via
 *    `seedInput`, with no leaf referencing `$input` at all. If the repoint missed
 *    `seedInput`, the pad would sit in the spec, unconsumed, while the body read
 *    raw unpadded bytes — and the run would SUCCEED with wrong output.
 * 2. **Padding to the wrong width.** A stray 16 pads a 20-byte input to 32 bytes
 *    instead of 24.
 *
 * Asserting `params.blockSize === 8` catches neither. So every test here asserts
 * OUTPUT BYTES against the independently-composed oracle.
 */

import { blowfishSpec } from "@/ciphers/blowfish";
import {
  blowfishEncryptWords,
  blowfishKeySchedule,
  bytesBEToU32,
  u32ToBytesBE,
} from "@/ciphers/blowfish-constants";
import { blowfishCore } from "@/ciphers/blowfish-core";
import { blowfishDecryptSpec } from "@/ciphers/blowfish-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildEcbSpec } from "@/ciphers/modes/ecb";
import { runSpec } from "@/core/runtime";
import { applyPaddingScheme } from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { paddingLimits } from "@/ui/stores/padding";
import { describe, expect, it } from "vitest";

const KEY = "0123456789abcdef";
const B = 8;
const core = blowfishCore();

/** PKCS#7 (RFC 5652 §6.3), spelled out here so the test doesn't reuse the code under test. */
const pkcs7Pad = (bytes: Uint8Array, blockSize: number): Uint8Array => {
  const n = blockSize - (bytes.length % blockSize);
  return Uint8Array.from([...bytes, ...Array.from({ length: n }, () => n)]);
};

/** One block through the raw Feistel network (P reversed ⇒ decrypt). */
const oracleBlock = (block: Uint8Array, encrypt: boolean): Uint8Array => {
  const { P, S } = blowfishKeySchedule(bytesFromHex(KEY));
  const [xl, xr] = blowfishEncryptWords(
    bytesBEToU32(block, 0),
    bytesBEToU32(block, 4),
    encrypt ? P : [...P].reverse(),
    S,
  );
  const out = new Uint8Array(B);
  out.set(u32ToBytesBE(xl), 0);
  out.set(u32ToBytesBE(xr), 4);
  return out;
};

const oracleEcbEncrypt = (bytes: Uint8Array): string => {
  const out: number[] = [];
  for (let i = 0; i < bytes.length; i += B)
    out.push(...oracleBlock(bytes.subarray(i, i + B), true));
  return hexFromBytes(Uint8Array.from(out));
};

const run = (spec: CipherSpec, input: Uint8Array): Uint8Array => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(input),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return trace.finalState.bytes;
};

describe("padding overlay on Blowfish single-block", () => {
  // 5 bytes — under one 8-byte block, so PKCS#7 appends three 0x03s.
  const FIVE = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x42]);

  it("pads a short input to ONE 8-byte block and matches the oracle", () => {
    const padded = applyPaddingScheme(blowfishSpec, "encrypt", "pkcs7", core.blockByteLength);
    const ct = run(padded, FIVE);

    // The oracle pads to 8 independently. If the pad were floating, the body
    // would have read 5 raw bytes and thrown on the [4,4] split; if it padded to
    // 16, this would be two blocks and the length alone diverges.
    expect(hexFromBytes(ct)).toBe(oracleEcbEncrypt(pkcs7Pad(FIVE, B)));
    expect(ct.length).toBe(8);
  });

  it("round-trips: encrypt then decrypt returns the original short input", () => {
    const enc = applyPaddingScheme(blowfishSpec, "encrypt", "pkcs7", core.blockByteLength);
    const dec = applyPaddingScheme(blowfishDecryptSpec, "decrypt", "pkcs7", core.blockByteLength);
    expect(hexFromBytes(run(dec, run(enc, FIVE)))).toBe(hexFromBytes(FIVE));
  });

  it("the pad changes the outcome — it is not a floating leaf (control)", () => {
    // The control that gives the test above its teeth, and the reason hazard 1
    // deserves an output assertion in the first place.
    //
    // A floating pad does NOT announce itself here: `split-bytes [4,4]` coerces
    // a short input rather than throwing (the project's deliberate warn-and-run
    // stance), so an unconsumed pad would leave the body encrypting the raw 5
    // bytes and the run would SUCCEED with wrong output. The only way to see the
    // difference is to compare the bytes both ways.
    const canonical = run(blowfishSpec, FIVE);
    const padded = run(
      applyPaddingScheme(blowfishSpec, "encrypt", "pkcs7", core.blockByteLength),
      FIVE,
    );
    expect(hexFromBytes(padded)).not.toBe(hexFromBytes(canonical));
  });

  it("scheme=none leaves the canonical spec, which still matches the raw oracle", () => {
    const canonical = applyPaddingScheme(blowfishSpec, "encrypt", "none", core.blockByteLength);
    const EIGHT = bytesFromHex("1122334455667788");
    expect(hexFromBytes(run(canonical, EIGHT))).toBe(hexFromBytes(oracleBlock(EIGHT, true)));
  });
});

describe("padding overlay on Blowfish ECB (multi-block)", () => {
  it("appends a whole extra block when the input is already aligned", () => {
    // PKCS#7 never no-ops: an aligned input gains a full block of `blockSize`,
    // which is what keeps unpad unambiguous. 8 bytes ⇒ 16, i.e. TWO Blowfish
    // blocks — so this needs a multi-block spec.
    //
    // (Single-block + an aligned input is deliberately out of contract:
    // `paddingLimits` caps single-block PKCS#7 at `blockSize - 1` precisely
    // because the padded bytes would overflow the one block the body reads.
    // Same for AES at 16 — not a Blowfish-specific limit.)
    const EIGHT = bytesFromHex("1122334455667788");
    const spec = applyPaddingScheme(
      buildEcbSpec(core, "encrypt"),
      "encrypt",
      "pkcs7",
      core.blockByteLength,
    );
    const ct = run(spec, EIGHT);
    expect(ct.length).toBe(16);
    expect(hexFromBytes(ct)).toBe(oracleEcbEncrypt(pkcs7Pad(EIGHT, B)));
  });

  it("pads 20 bytes up to 24 (three 8-byte blocks), not 32", () => {
    // The clearest "8, not 16" assertion available: 20 bytes pads to 24 at an
    // 8-byte block and to 32 at a 16-byte one. The length is decisive on its own.
    const twenty = Uint8Array.from({ length: 20 }, (_, i) => i);
    const spec = applyPaddingScheme(
      buildEcbSpec(core, "encrypt"),
      "encrypt",
      "pkcs7",
      core.blockByteLength,
    );
    const ct = run(spec, twenty);
    expect(ct.length).toBe(24);
    expect(hexFromBytes(ct)).toBe(oracleEcbEncrypt(pkcs7Pad(twenty, B)));
  });
});

describe("paddingLimits derives Blowfish's bounds from its core", () => {
  it("single-block PKCS#7 encrypt bounds at 0..7, not 0..15", () => {
    // Pre-Phase-C this returned a fixed {8,8} from the coreless switch.
    expect(paddingLimits("encrypt", "pkcs7", "blowfish", "single-block")).toEqual({
      min: 0,
      max: 7,
    });
  });

  it("multi-block bounds are counted in 8-byte blocks", () => {
    // MAX_BLOCKS_UI (16) × 8 = 128, vs AES's 256. The UI cap is counted in
    // BLOCKS on purpose — what degrades is frame count, which scales with blocks.
    expect(paddingLimits("decrypt", "none", "blowfish", "cbc")).toEqual({ min: 8, max: 128 });
    expect(paddingLimits("encrypt", "pkcs7", "blowfish", "ecb")).toEqual({ min: 0, max: 127 });
  });
});
