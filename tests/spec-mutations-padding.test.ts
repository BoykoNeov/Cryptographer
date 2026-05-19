import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
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
      } else if (node.kind === "feistel-round") {
        for (const track of node.tracks) {
          const found = visit(track.children);
          if (found) return found;
        }
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

describe("applyPaddingScheme(spec, encrypt, 'zero-pad')", () => {
  it("prepends zero-pad and load-block in that order", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "zero-pad");
    const types = topLevelLeafTypes(result);
    expect(types[0]).toBe("generic.zero-pad@1");
    expect(types[1]).toBe("generic.load-block@1");
    expect(types[2]).toBe("aes.key-expansion@1");
  });

  it("declares input shape as 'bytes' so the runtime accepts BytesState", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "zero-pad");
    expect(result.inputs.plaintext.shape).toBe("bytes");
  });

  it("uses blockSize=16 in zero-pad/load params", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "zero-pad");
    const pad = findFirstLeaf(result, "generic.zero-pad@1");
    expect(pad?.params).toEqual({ blockSize: 16 });
  });
});

describe("applyPaddingScheme(spec, decrypt, 'zero-pad')", () => {
  it("appends store-block and zero-unpad in that order", () => {
    const result = applyPaddingScheme(aes128DecryptSpec, "decrypt", "zero-pad");
    const types = topLevelLeafTypes(result);
    expect(types[types.length - 2]).toBe("generic.store-block@1");
    expect(types[types.length - 1]).toBe("generic.zero-unpad@1");
    expect(result.inputs.plaintext.shape).toBe("matrix4x4-bytes");
  });
});

describe("applyPaddingScheme(spec, encrypt, 'iso7816-4')", () => {
  it("prepends iso7816-4-pad and load-block in that order", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "iso7816-4");
    const types = topLevelLeafTypes(result);
    expect(types[0]).toBe("generic.iso7816-4-pad@1");
    expect(types[1]).toBe("generic.load-block@1");
    expect(types[2]).toBe("aes.key-expansion@1");
  });

  it("declares input shape as 'bytes'", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "iso7816-4");
    expect(result.inputs.plaintext.shape).toBe("bytes");
  });

  it("uses blockSize=16 in pad params", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "iso7816-4");
    const pad = findFirstLeaf(result, "generic.iso7816-4-pad@1");
    expect(pad?.params).toEqual({ blockSize: 16 });
  });
});

describe("applyPaddingScheme(spec, decrypt, 'iso7816-4')", () => {
  it("appends store-block and iso7816-4-unpad in that order", () => {
    const result = applyPaddingScheme(aes128DecryptSpec, "decrypt", "iso7816-4");
    const types = topLevelLeafTypes(result);
    expect(types[types.length - 2]).toBe("generic.store-block@1");
    expect(types[types.length - 1]).toBe("generic.iso7816-4-unpad@1");
  });
});

describe("applyPaddingScheme cross-scheme swaps", () => {
  it("pkcs7 → zero-pad strips PKCS#7 leaves before inserting zero-pad", () => {
    const pkcs7 = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    const zero = applyPaddingScheme(pkcs7, "encrypt", "zero-pad");
    const types = topLevelLeafTypes(zero);
    // No PKCS#7 residue.
    expect(types).not.toContain("generic.pkcs7-pad@1");
    expect(types).not.toContain("generic.pkcs7-unpad@1");
    // New zero-pad chain present.
    expect(types[0]).toBe("generic.zero-pad@1");
    expect(types[1]).toBe("generic.load-block@1");
  });

  it("iso7816-4 → none returns canonical-equivalent (no overlay leaves)", () => {
    const iso = applyPaddingScheme(aes128Spec, "encrypt", "iso7816-4");
    const canonical = applyPaddingScheme(iso, "encrypt", "none");
    const types = topLevelLeafTypes(canonical);
    expect(types).not.toContain("generic.iso7816-4-pad@1");
    expect(types).not.toContain("generic.load-block@1");
    expect(types[0]).toBe("aes.key-expansion@1");
    expect(canonical.inputs.plaintext.shape).toBe("matrix4x4-bytes");
  });

  it("all three non-none schemes produce structurally parallel encrypt overlays", () => {
    // Same leaf ORDER and leaf COUNT for all three; only the scheme-
    // specific pad-step type differs. This pins the generic shape: any
    // future scheme should look the same from the outside.
    const a = topLevelLeafTypes(applyPaddingScheme(aes128Spec, "encrypt", "pkcs7"));
    const b = topLevelLeafTypes(applyPaddingScheme(aes128Spec, "encrypt", "zero-pad"));
    const c = topLevelLeafTypes(applyPaddingScheme(aes128Spec, "encrypt", "iso7816-4"));
    expect(a.length).toBe(b.length);
    expect(b.length).toBe(c.length);
    // Position 0 = the pad step (differs by scheme); 1 = load-block; rest =
    // canonical AES tail and is identical across schemes.
    expect(a.slice(1)).toEqual(b.slice(1));
    expect(b.slice(1)).toEqual(c.slice(1));
  });
});

describe("applyPaddingScheme is a no-op for non-AES (non-matrix4x4-bytes) specs", () => {
  it("returns the Speck spec without inserting AES padding leaves", () => {
    // Speck32/64's spec has stateShape="bytes" and its own 4-byte block.
    // The padding overlay's load-block is hardcoded for blockSize=16, so
    // applyPaddingScheme must silently skip it — otherwise switching to
    // Speck while padding=pkcs7 is persisted would crash on every Run.
    const result = applyPaddingScheme(speck32_64BeSpec, "encrypt", "pkcs7");
    const types = topLevelLeafTypes(result);
    // No padding-overlay leaves got inserted.
    expect(types).not.toContain("generic.pkcs7-pad@1");
    expect(types).not.toContain("generic.load-block@1");
    // First leaf is still Speck's key-schedule, as in the canonical spec.
    expect(types[0]).toBe("speck.key-schedule@1");
    // Input shape preserved (Speck consumes BytesState directly).
    expect(result.inputs.plaintext.shape).toBe("bytes");
  });

  it("strips any stale AES overlay leaves on a non-AES spec", () => {
    // Simulate a spec that somehow had AES overlay leaves smuggled in (e.g.
    // a future regression where applyPaddingScheme didn't early-return).
    // Calling applyPaddingScheme(., ., 'none') on a non-AES spec should
    // strip them clean.
    const tampered: CipherSpec = {
      ...speck32_64BeSpec,
      steps: [
        { kind: "step", id: "stale-pad", type: "generic.pkcs7-pad@1", params: { blockSize: 16 } },
        ...speck32_64BeSpec.steps,
      ],
    };
    const result = applyPaddingScheme(tampered, "encrypt", "none");
    expect(topLevelLeafTypes(result)).not.toContain("generic.pkcs7-pad@1");
    expect(topLevelLeafTypes(result)[0]).toBe("speck.key-schedule@1");
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
