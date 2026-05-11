import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { applyPaddingScheme } from "@/core/spec-mutations";
import type { CipherSpec, StepLeaf, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

// Walk the spec tree and return top-level leaf types in order. Padding
// overlay leaves are always top-level, so this is the right granularity.
const topLevelLeafTypes = (spec: CipherSpec): string[] =>
  spec.steps.filter((n): n is StepLeaf => n.kind === "step").map((n) => n.type);

const findFirstLeaf = (spec: CipherSpec, type: string): StepLeaf | null => {
  const visit = (nodes: readonly StepNode[]): StepLeaf | null => {
    for (const node of nodes) {
      if (node.kind === "step") {
        if (node.type === type) return node;
      } else {
        const found = visit(node.children);
        if (found) return found;
      }
    }
    return null;
  };
  return visit(spec.steps);
};

describe("applyPaddingScheme(spec, encrypt, 'none')", () => {
  it("returns a spec structurally equivalent to the canonical one", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "none");
    // No pad/load leaves at top level.
    const types = topLevelLeafTypes(result);
    expect(types).not.toContain("generic.pkcs7-pad@1");
    expect(types).not.toContain("generic.load-block@1");
    // Canonical structure preserved: key-expansion is the first top-level
    // leaf in the encrypt spec.
    expect(types[0]).toBe("aes.key-expansion@1");
    // Input shape stays matrix.
    expect(result.inputs.plaintext.shape).toBe("matrix4x4-bytes");
  });
});

describe("applyPaddingScheme(spec, encrypt, 'pkcs7')", () => {
  it("prepends pkcs7-pad and load-block in that order", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    const types = topLevelLeafTypes(result);
    expect(types[0]).toBe("generic.pkcs7-pad@1");
    expect(types[1]).toBe("generic.load-block@1");
    expect(types[2]).toBe("aes.key-expansion@1");
  });

  it("declares input shape as 'bytes' so the runtime accepts BytesState", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    expect(result.inputs.plaintext.shape).toBe("bytes");
  });

  it("uses blockSize=16 in pad/load params", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    const pad = findFirstLeaf(result, "generic.pkcs7-pad@1");
    expect(pad?.params).toEqual({ blockSize: 16 });
    const load = findFirstLeaf(result, "generic.load-block@1");
    expect(load?.params).toEqual({ blockSize: 16 });
  });
});

describe("applyPaddingScheme(spec, decrypt, 'pkcs7')", () => {
  it("appends store-block and pkcs7-unpad in that order", () => {
    const result = applyPaddingScheme(aes128DecryptSpec, "decrypt", "pkcs7");
    const types = topLevelLeafTypes(result);
    expect(types[types.length - 2]).toBe("generic.store-block@1");
    expect(types[types.length - 1]).toBe("generic.pkcs7-unpad@1");
    // Input shape stays matrix (ciphertext is one block).
    expect(result.inputs.plaintext.shape).toBe("matrix4x4-bytes");
  });
});

describe("applyPaddingScheme idempotency", () => {
  it("calling twice with the same scheme produces a structurally equivalent spec", () => {
    const once = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    const twice = applyPaddingScheme(once, "encrypt", "pkcs7");
    expect(topLevelLeafTypes(twice)).toEqual(topLevelLeafTypes(once));
    // Same step count overall.
    expect(twice.steps.length).toBe(once.steps.length);
  });

  it("strips existing overlay leaves before re-applying — pkcs7 → none returns canonical-equivalent", () => {
    const padded = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    const unpadded = applyPaddingScheme(padded, "encrypt", "none");
    const types = topLevelLeafTypes(unpadded);
    expect(types).not.toContain("generic.pkcs7-pad@1");
    expect(types).not.toContain("generic.load-block@1");
    expect(types[0]).toBe("aes.key-expansion@1");
    expect(unpadded.inputs.plaintext.shape).toBe("matrix4x4-bytes");
  });

  it("decrypt → encrypt scheme swap: pkcs7 decrypt strips, then applies as encrypt", () => {
    const decryptPadded = applyPaddingScheme(aes128DecryptSpec, "decrypt", "pkcs7");
    // Strip and re-apply as encrypt — overlay leaves move from tail to head.
    // (This is what happens internally when the user flips encrypt↔decrypt
    // and the active padding scheme is re-applied.)
    const reApplied = applyPaddingScheme(decryptPadded, "encrypt", "pkcs7");
    const types = topLevelLeafTypes(reApplied);
    expect(types[0]).toBe("generic.pkcs7-pad@1");
    expect(types[1]).toBe("generic.load-block@1");
    expect(types).not.toContain("generic.store-block@1");
    expect(types).not.toContain("generic.pkcs7-unpad@1");
  });
});

describe("applyPaddingScheme preserves user edits to canonical AES leaves", () => {
  it("does not touch round groups when applying overlay", () => {
    // Round groups (round.1, round.2, ...) carry the per-round sub-bytes /
    // shift-rows / mix-columns / add-round-key leaves. The overlay should
    // not affect them. Spot check that they're reference-equal to the
    // canonical groups.
    const padded = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    const canonicalRoundGroups = aes128Spec.steps.filter((n) => n.kind === "group");
    const paddedRoundGroups = padded.steps.filter((n) => n.kind === "group");
    expect(paddedRoundGroups.length).toBe(canonicalRoundGroups.length);
    for (let i = 0; i < canonicalRoundGroups.length; i++) {
      // The overlay function spreads `...stripped` for the original steps,
      // so individual nodes preserve reference equality.
      expect(paddedRoundGroups[i]).toBe(canonicalRoundGroups[i]);
    }
  });
});
