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
    // No pad/load leaves at top level. (Byte-native AES never had a
    // load-block; the port graph reads `$input` directly — Slice B1.)
    const types = topLevelLeafTypes(result);
    expect(types).not.toContain("generic.pkcs7-pad@1");
    expect(types).not.toContain("generic.load-block@1");
    // Canonical structure preserved: key-expansion is the first top-level
    // leaf in the encrypt spec.
    expect(types[0]).toBe("aes.key-expansion@1");
    // Byte-native AES carries a flat 16-byte state on raw ports.
    expect(result.inputs.plaintext.shape).toBe("bytes");
  });
});

describe("applyPaddingScheme(spec, encrypt, 'pkcs7')", () => {
  it("prepends ONLY pkcs7-pad before key-expansion (no load-block, byte-native B1)", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    const types = topLevelLeafTypes(result);
    expect(types[0]).toBe("generic.pkcs7-pad@1");
    // No bytes↔matrix bridge: byte-native AES has no load-block.
    expect(types).not.toContain("generic.load-block@1");
    expect(types[1]).toBe("aes.key-expansion@1");
  });

  it("declares input shape as 'bytes' so the runtime accepts BytesState", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    expect(result.inputs.plaintext.shape).toBe("bytes");
  });

  it("uses blockSize=16 in the pad params", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    const pad = findFirstLeaf(result, "generic.pkcs7-pad@1");
    expect(pad?.params).toEqual({ blockSize: 16 });
  });

  it("wires the pad to read $input and repoints the body's $input consumer to the pad", () => {
    // The byte-native branch splices the pad directly into the port graph:
    // the pad reads the raw plaintext from `$input` on its `state` input
    // port, and the initial AddRoundKey (which read `$input` directly) is
    // repointed to the pad's `state` output port.
    const result = applyPaddingScheme(aes128Spec, "encrypt", "pkcs7");
    const pad = findFirstLeaf(result, "generic.pkcs7-pad@1");
    expect(pad?.portInputs).toEqual({ state: { node: "$input", port: "out" } });

    // No leaf anywhere still reads the raw $input source — the pad owns it.
    const readsRawInput = (nodes: readonly StepNode[]): boolean =>
      nodes.some((n) => {
        const pi = n.portInputs;
        const here =
          pi !== undefined &&
          Object.values(pi).some((b) => b.node === "$input" && b.port === "out");
        if (here) return true;
        if (n.kind === "feistel-round") return n.tracks.some((t) => readsRawInput(t.children));
        if (n.kind !== "step") return readsRawInput(n.children);
        return false;
      });
    // The pad itself reads $input; every OTHER node must not.
    const withoutPad = result.steps.filter((n) => n.id !== "pkcs7-pad");
    expect(readsRawInput(withoutPad)).toBe(false);
    // The initial AddRoundKey now reads the pad's output.
    const initialArk = findFirstLeaf(result, "xor@1");
    expect(initialArk?.portInputs?.operand0).toEqual({ node: "pkcs7-pad", port: "state" });
  });
});

describe("applyPaddingScheme(spec, decrypt, 'pkcs7')", () => {
  it("appends ONLY pkcs7-unpad (no store-block, byte-native B1.2)", () => {
    const result = applyPaddingScheme(aes128DecryptSpec, "decrypt", "pkcs7");
    const types = topLevelLeafTypes(result);
    // Byte-native decrypt: no bytes↔matrix bridge (store-block), the unpad is
    // spliced directly onto the port graph at the tail.
    expect(types).not.toContain("generic.store-block@1");
    expect(types[types.length - 1]).toBe("generic.pkcs7-unpad@1");
    // Shape stays bytes (byte-native carries a flat 16-byte block).
    expect(result.inputs.plaintext.shape).toBe("bytes");
  });

  it("wires the unpad to read the old cipher exit and repoints outputFrom to it", () => {
    // The byte-native branch appends an unpad reading the spec's prior
    // `outputFrom` (the final inverse round's `out` port) on its `state` input
    // port, then moves `outputFrom` onto the unpad's `state` output port.
    const result = applyPaddingScheme(aes128DecryptSpec, "decrypt", "pkcs7");
    const unpad = findFirstLeaf(result, "generic.pkcs7-unpad@1");
    expect(unpad?.portInputs).toEqual({ state: { node: "inv-round.0", port: "out" } });
    expect(result.outputFrom).toEqual({ node: "pkcs7-unpad", port: "state" });
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
    expect(unpadded.inputs.plaintext.shape).toBe("bytes");
  });

  it("decrypt → encrypt scheme swap: pkcs7 decrypt strips, then applies as encrypt", () => {
    const decryptPadded = applyPaddingScheme(aes128DecryptSpec, "decrypt", "pkcs7");
    // Strip and re-apply as encrypt — overlay leaves move from tail to head.
    // (This is what happens internally when the user flips encrypt↔decrypt
    // and the active padding scheme is re-applied.) Byte-native (B1.2): the
    // unpad at the tail is stripped (and `outputFrom` restored to the canonical
    // cipher exit), then a pad is prepended at the head — no load/store-block
    // bridge in either direction.
    const reApplied = applyPaddingScheme(decryptPadded, "encrypt", "pkcs7");
    const types = topLevelLeafTypes(reApplied);
    expect(types[0]).toBe("generic.pkcs7-pad@1");
    expect(types).not.toContain("generic.load-block@1");
    expect(types).not.toContain("generic.store-block@1");
    expect(types).not.toContain("generic.pkcs7-unpad@1");
  });
});

describe("applyPaddingScheme(spec, encrypt, 'zero-pad')", () => {
  it("prepends ONLY zero-pad before key-expansion (no load-block, byte-native B1)", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "zero-pad");
    const types = topLevelLeafTypes(result);
    expect(types[0]).toBe("generic.zero-pad@1");
    expect(types).not.toContain("generic.load-block@1");
    expect(types[1]).toBe("aes.key-expansion@1");
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
  it("appends ONLY zero-unpad (no store-block, byte-native B1.2)", () => {
    const result = applyPaddingScheme(aes128DecryptSpec, "decrypt", "zero-pad");
    const types = topLevelLeafTypes(result);
    expect(types).not.toContain("generic.store-block@1");
    expect(types[types.length - 1]).toBe("generic.zero-unpad@1");
    expect(result.inputs.plaintext.shape).toBe("bytes");
  });
});

describe("applyPaddingScheme(spec, encrypt, 'iso7816-4')", () => {
  it("prepends ONLY iso7816-4-pad before key-expansion (no load-block, byte-native B1)", () => {
    const result = applyPaddingScheme(aes128Spec, "encrypt", "iso7816-4");
    const types = topLevelLeafTypes(result);
    expect(types[0]).toBe("generic.iso7816-4-pad@1");
    expect(types).not.toContain("generic.load-block@1");
    expect(types[1]).toBe("aes.key-expansion@1");
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
  it("appends ONLY iso7816-4-unpad (no store-block, byte-native B1.2)", () => {
    const result = applyPaddingScheme(aes128DecryptSpec, "decrypt", "iso7816-4");
    const types = topLevelLeafTypes(result);
    expect(types).not.toContain("generic.store-block@1");
    expect(types[types.length - 1]).toBe("generic.iso7816-4-unpad@1");
    expect(result.inputs.plaintext.shape).toBe("bytes");
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
    // New zero-pad chain present (byte-native: pad only, no load-block).
    expect(types[0]).toBe("generic.zero-pad@1");
    expect(types).not.toContain("generic.load-block@1");
    expect(types[1]).toBe("aes.key-expansion@1");
    // The initial AddRoundKey was repointed onto the NEW pad, not the old one.
    const initialArk = findFirstLeaf(zero, "xor@1");
    expect(initialArk?.portInputs?.operand0).toEqual({ node: "zero-pad", port: "state" });
  });

  it("iso7816-4 → none returns canonical-equivalent (no overlay leaves)", () => {
    const iso = applyPaddingScheme(aes128Spec, "encrypt", "iso7816-4");
    const canonical = applyPaddingScheme(iso, "encrypt", "none");
    const types = topLevelLeafTypes(canonical);
    expect(types).not.toContain("generic.iso7816-4-pad@1");
    expect(types).not.toContain("generic.load-block@1");
    expect(types[0]).toBe("aes.key-expansion@1");
    expect(canonical.inputs.plaintext.shape).toBe("bytes");
    // The initial AddRoundKey's $input wiring was restored on strip.
    const initialArk = findFirstLeaf(canonical, "xor@1");
    expect(initialArk?.portInputs?.operand0).toEqual({ node: "$input", port: "out" });
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
    // Position 0 = the pad step (differs by scheme); the rest is the
    // canonical byte-native AES tail (key-expansion, …) — identical across
    // schemes (no load-block under byte-native, Slice B1).
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
