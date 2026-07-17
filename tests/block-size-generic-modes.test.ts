/**
 * The block-size-generic paths, proven on a NON-16 block.
 *
 * ## Why this file exists
 *
 * Phase B of `docs/plans/foamy-prancing-wren.md` replaced five hardcoded `16`s
 * with a block width read from a `BlockCipherCore`. Every shipped core is AES,
 * whose block IS 16 — so every one of those paths would still pass if the
 * generalization were subtly wrong (a stray `16`, an off-by-one in a bound, a
 * `% 16` left behind). The AES-192/256 rollout in the same phase doesn't help:
 * those are 16-byte blocks too. **Nothing in the app exercises a non-16 block
 * until Blowfish's core lands in Phase C.**
 *
 * So this file supplies the missing width itself: a fake core with an 8-byte
 * block, fed to the real mode builders and the real padding overlay. If any of
 * them still assume 16, the assertions here fail while every AES test in the
 * suite stays green.
 *
 * ## What this file does NOT prove
 *
 * That an 8-byte-block cipher *works in the app*. The fake core's body is a
 * single passthrough leaf, not a cipher — this checks the plumbing carries the
 * width, not that any real 8-byte cipher encrypts correctly. That is Phase C's
 * job (a composed Blowfish CBC KAT + a browser smoke).
 */

import type { BlockCipherCore, CipherBody } from "@/ciphers/block-cipher-core";
import { buildCbcSpec } from "@/ciphers/modes/cbc";
import { buildEcbSpec } from "@/ciphers/modes/ecb";
import { applyPaddingScheme } from "@/core/spec-mutations";
import type { CipherSpec, IterateGroup, PortBinding, StepLeaf, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

const BLOCK = 8;

/**
 * A stand-in for an 8-byte-block cipher. The body is one `permute@1` identity
 * leaf: enough to be a real, wireable node with a named output port, without
 * dragging in a cipher's worth of structure. What matters is the width.
 */
const fakeCore: BlockCipherCore = {
  id: "fake-8",
  displayName: "Fake-8",
  familyName: "Fake",
  blockByteLength: BLOCK,
  keyByteLength: BLOCK,
  buildKeySchedule: (): StepNode => ({
    kind: "step",
    id: "key-schedule",
    type: "aux-load-bytes@1",
    params: { auxName: "key", byteLength: BLOCK },
  }),
  buildEncryptBody: (seed: PortBinding): CipherBody => ({
    nodes: [
      {
        kind: "step",
        id: "body",
        type: "permute@1",
        params: { mapping: [0, 1, 2, 3, 4, 5, 6, 7] },
        portInputs: { input: seed },
      },
    ],
    output: { node: "body", port: "output" },
  }),
  buildDecryptBody: (seed: PortBinding): CipherBody => ({
    nodes: [
      {
        kind: "step",
        id: "body",
        type: "permute@1",
        params: { mapping: [0, 1, 2, 3, 4, 5, 6, 7] },
        portInputs: { input: seed },
      },
    ],
    output: { node: "body", port: "output" },
  }),
};

const findIterate = (spec: CipherSpec): IterateGroup | undefined =>
  spec.steps.find((n): n is IterateGroup => n.kind === "iterate");

const findLeaf = (spec: CipherSpec, type: string): StepLeaf | undefined =>
  spec.steps.find((n): n is StepLeaf => n.kind === "step" && n.type === type);

/** By id — the fake key schedule is an `aux-load-bytes@1` too, so type alone
 *  would match it instead of the IV read. */
const findLeafById = (spec: CipherSpec, id: string): StepLeaf | undefined =>
  spec.steps.find((n): n is StepLeaf => n.kind === "step" && n.id === id);

describe("mode builders carry the core's block width, not AES's", () => {
  it("ECB's iterate splits into 8-byte blocks", () => {
    // The iterate's `blockByteLength` is what chops the message up. A 16 here
    // would silently encrypt two blocks at a time as one.
    expect(findIterate(buildEcbSpec(fakeCore, "encrypt"))?.blockByteLength).toBe(BLOCK);
    expect(findIterate(buildEcbSpec(fakeCore, "decrypt"))?.blockByteLength).toBe(BLOCK);
  });

  it("CBC's iterate splits into 8-byte blocks", () => {
    expect(findIterate(buildCbcSpec(fakeCore, "encrypt"))?.blockByteLength).toBe(BLOCK);
    expect(findIterate(buildCbcSpec(fakeCore, "decrypt"))?.blockByteLength).toBe(BLOCK);
  });

  it("CBC's fetch-iv reads an 8-byte IV", () => {
    // The IV XORs with a block, so it is exactly one block wide. Reading 16
    // bytes of an 8-byte aux value is where a hardcoded IV length would surface.
    for (const dir of ["encrypt", "decrypt"] as const) {
      const iv = findLeafById(buildCbcSpec(fakeCore, dir), "fetch-iv");
      expect(iv?.params).toMatchObject({ auxName: "iv", byteLength: BLOCK });
    }
  });
});

describe("the padding overlay pads to the caller's block width", () => {
  it("pads an 8-byte-block cipher to 8, not 16", () => {
    // The heart of the Phase-B change: `blockSize` used to be a module-level
    // `AES_BLOCK_SIZE = 16` here. Padding an 8-byte-block cipher to 16 would
    // produce a plausible-looking spec that encrypts the wrong bytes.
    const padded = applyPaddingScheme(buildEcbSpec(fakeCore, "encrypt"), "encrypt", "pkcs7", BLOCK);
    expect(findLeaf(padded, "generic.pkcs7-pad@1")?.params).toEqual({ blockSize: BLOCK });
  });

  it("unpads an 8-byte-block cipher to 8 on decrypt", () => {
    const padded = applyPaddingScheme(buildEcbSpec(fakeCore, "decrypt"), "decrypt", "pkcs7", BLOCK);
    expect(findLeaf(padded, "generic.pkcs7-unpad@1")?.params).toEqual({ blockSize: BLOCK });
  });

  it("skips the overlay entirely when the caller names no block width", () => {
    // `undefined` is how a cipher with no core, a hash, or RSA reaches this
    // function. It must come back canonical rather than padded on a guess.
    const spec = buildEcbSpec(fakeCore, "encrypt");
    const result = applyPaddingScheme(spec, "encrypt", "pkcs7", undefined);
    expect(findLeaf(result, "generic.pkcs7-pad@1")).toBeUndefined();
    expect(result.steps.map((s) => s.id)).toEqual(spec.steps.map((s) => s.id));
  });

  it("re-applying with a different width replaces the pad rather than stacking", () => {
    // Idempotency has to survive the width becoming a parameter: the overlay
    // strips before it splices, so a cipher swap (8-byte → 16-byte) must leave
    // exactly one pad, carrying the NEW width.
    const once = applyPaddingScheme(buildEcbSpec(fakeCore, "encrypt"), "encrypt", "pkcs7", BLOCK);
    const twice = applyPaddingScheme(once, "encrypt", "pkcs7", 16);
    const pads = twice.steps.filter((s) => s.kind === "step" && s.type === "generic.pkcs7-pad@1");
    expect(pads).toHaveLength(1);
    expect(findLeaf(twice, "generic.pkcs7-pad@1")?.params).toEqual({ blockSize: 16 });
  });
});
