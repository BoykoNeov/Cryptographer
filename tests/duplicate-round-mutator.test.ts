/**
 * Unit tests for `duplicateRoundGroup` from `src/core/spec-mutations.ts`.
 *
 * Six property bundles drive the file. Each bundle is one describe block:
 *
 *   1. Forward (encrypt) — canonical AES-128 single-block.
 *   2. Forward (encrypt) — AES-128 ECB, round groups nested inside the
 *      multi-block `iterate` body. Key-expansion at the top level still
 *      gets bumped.
 *   3. Reverse (decrypt) — canonical AES-128-decrypt single-block.
 *   4. Rename map is exhaustive — every renamed group AND child leaf is
 *      keyed.
 *   5. Reference equality on untouched branches — same hygiene as the
 *      other spec mutators.
 *   6. Error paths — bad source id, source isn't a group, no key-
 *      expansion, direction/id mismatch.
 *
 * The end-to-end "duplicated AES round produces a valid ciphertext that
 * round-trips" test lives in `aes-duplicate-round.test.ts` once the
 * remaining phases (store action + UI trigger) land.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { duplicateRoundGroup, findStep } from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, CipherSpec, IterateGroup, StepGroup, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Helpers ─────────────────────────────────────────────────────────────

/** Find a group node by id, anywhere in the spec tree. */
const findGroup = (spec: CipherSpec, id: string): StepGroup | null => {
  const visit = (nodes: readonly StepNode[]): StepGroup | null => {
    for (const node of nodes) {
      if (node.kind === "group" && node.id === id) return node;
      if (node.kind !== "step") {
        const found = visit(node.children);
        if (found) return found;
      }
    }
    return null;
  };
  return visit(spec.steps);
};

/** Find the iterate node (multi-block ECB/CBC/CTR). */
const findIterate = (spec: CipherSpec): IterateGroup | null => {
  for (const node of spec.steps) {
    if (node.kind === "iterate") return node;
  }
  return null;
};

/** Extract a leaf's auxName param (for AddRoundKey). */
const auxNameOf = (spec: CipherSpec, leafId: string): string | undefined => {
  const leaf = findStep(spec, leafId);
  if (!leaf) return undefined;
  const p = leaf.params as { auxName?: unknown };
  return typeof p.auxName === "string" ? p.auxName : undefined;
};

/** Extract key-expansion's `rounds` param value. */
const keyExpansionRounds = (spec: CipherSpec): number => {
  const leaf = findStep(spec, "key-expansion");
  if (!leaf) throw new Error("test setup: no key-expansion leaf");
  const p = leaf.params as { rounds?: unknown };
  if (typeof p.rounds !== "number") throw new Error("test setup: rounds is not a number");
  return p.rounds;
};

const keyExpansionType = (spec: CipherSpec): string => {
  const leaf = findStep(spec, "key-expansion");
  if (!leaf) throw new Error("test setup: no key-expansion leaf");
  return leaf.type;
};

// ─── 1. Forward, canonical AES-128 single-block ──────────────────────────

describe("duplicateRoundGroup — forward (AES-128 single-block)", () => {
  it("inserts a clone of round.2 as the new round.3 and shifts subsequent rounds up", () => {
    const { spec, renames } = duplicateRoundGroup(aes128Spec, "round.2", "forward");

    // Round structure: round.1 .. round.11 (11 rounds now).
    for (let n = 1; n <= 11; n++) {
      expect(findGroup(spec, `round.${n}`)).not.toBeNull();
    }
    // No leftover round.12 (we only inserted one).
    expect(findGroup(spec, "round.12")).toBeNull();

    // round.2 still reads roundKey.2 (unchanged).
    expect(auxNameOf(spec, "round.2.add-round-key")).toBe("roundKey.2");
    // The clone (now round.3) reads roundKey.3.
    expect(auxNameOf(spec, "round.3.add-round-key")).toBe("roundKey.3");
    // round.4 (was round.3) reads roundKey.4 (was .3).
    expect(auxNameOf(spec, "round.4.add-round-key")).toBe("roundKey.4");
    // round.11 (was round.10, the final) reads roundKey.11.
    expect(auxNameOf(spec, "round.11.add-round-key")).toBe("roundKey.11");

    // The rename map must include every shifted round and its children.
    expect(renames.get("round.3")).toBe("round.4");
    expect(renames.get("round.10")).toBe("round.11");
    expect(renames.get("round.3.sub-bytes")).toBe("round.4.sub-bytes");
    expect(renames.get("round.10.add-round-key")).toBe("round.11.add-round-key");
    // The clone itself is NOT a rename — its id is new, not migrated from
    // anything.
    expect(renames.get("round.2")).toBeUndefined();
  });

  it("bumps key-expansion's rounds param and morphs the type to @2", () => {
    const { spec } = duplicateRoundGroup(aes128Spec, "round.2", "forward");
    expect(keyExpansionRounds(spec)).toBe(11);
    expect(keyExpansionType(spec)).toBe("aes.key-expansion@2");
  });

  it("preserves the final round's no-MixColumns shape on the shifted final", () => {
    // The old round.10 (final round, no MixColumns) became round.11. Its
    // children should still be sub-bytes, shift-rows, add-round-key — no
    // mix-columns leaf.
    const { spec } = duplicateRoundGroup(aes128Spec, "round.2", "forward");
    const finalGroup = findGroup(spec, "round.11");
    expect(finalGroup).not.toBeNull();
    const childTypes = finalGroup?.children.map((c) => (c.kind === "step" ? c.type : "group"));
    expect(childTypes).toEqual([
      "generic.byte-substitution@1",
      "generic.shift-rows@1",
      "generic.add-round-key@1",
    ]);
  });

  it("re-labels shifted rounds when they follow the canonical 'Round N' pattern", () => {
    const { spec } = duplicateRoundGroup(aes128Spec, "round.5", "forward");
    expect(findGroup(spec, "round.6")?.label).toBe("Round 6");
    // The original "Round 10 (final, no MixColumns)" suffix carries over
    // to the renumbered "Round 11" label, since the regex anchors only at
    // the leading "Round N" prefix.
    expect(findGroup(spec, "round.11")?.label).toBe("Round 11 (final, no MixColumns)");
  });
});

// ─── 2. Forward, AES-128 ECB (round groups inside iterate) ───────────────

describe("duplicateRoundGroup — forward (AES-128 ECB, nested inside iterate)", () => {
  it("inserts the clone inside the iterate body, not at the top level", () => {
    const { spec } = duplicateRoundGroup(aes128EcbSpec, "round.2", "forward");
    const iterate = findIterate(spec);
    expect(iterate).not.toBeNull();
    // Iterate now contains round.1 .. round.11 plus the initial AddRoundKey
    // leaf. Confirm round.3 is the clone and round.11 is the (renumbered)
    // final.
    const roundIds = iterate?.children.filter((n) => n.kind === "group").map((n) => n.id);
    expect(roundIds).toEqual([
      "round.1",
      "round.2",
      "round.3",
      "round.4",
      "round.5",
      "round.6",
      "round.7",
      "round.8",
      "round.9",
      "round.10",
      "round.11",
    ]);
    // Verify the clone reads roundKey.3 (not .2 — easy bug if the auxName
    // bump on the clone itself is forgotten).
    expect(auxNameOf(spec, "round.3.add-round-key")).toBe("roundKey.3");
  });

  it("still bumps the top-level key-expansion (outside the iterate)", () => {
    const { spec } = duplicateRoundGroup(aes128EcbSpec, "round.2", "forward");
    expect(keyExpansionRounds(spec)).toBe(11);
    expect(keyExpansionType(spec)).toBe("aes.key-expansion@2");
  });

  it("does not rename top-level multi-block plumbing (split/concat/iterate)", () => {
    const { renames } = duplicateRoundGroup(aes128EcbSpec, "round.2", "forward");
    expect(renames.get("split-blocks")).toBeUndefined();
    expect(renames.get("compute-block-count")).toBeUndefined();
    expect(renames.get("concat-blocks")).toBeUndefined();
    expect(renames.get("ecb-blocks")).toBeUndefined();
    expect(renames.get("key-expansion")).toBeUndefined();
  });
});

// ─── 3. Reverse, AES-128-decrypt single-block ────────────────────────────

describe("duplicateRoundGroup — reverse (AES-128 decrypt single-block)", () => {
  it("inserts the clone BEFORE source and renumbers earlier siblings", () => {
    const { spec, renames } = duplicateRoundGroup(aes128DecryptSpec, "inv-round.2", "reverse");

    // 11 inverse rounds expected: inv-round.0 (final) .. inv-round.10.
    for (let n = 0; n <= 10; n++) {
      expect(findGroup(spec, `inv-round.${n}`)).not.toBeNull();
    }
    expect(findGroup(spec, "inv-round.11")).toBeNull();

    // The original inv-round.2 stays as inv-round.2, reading roundKey.2.
    expect(auxNameOf(spec, "inv-round.2.add-round-key")).toBe("roundKey.2");
    // The clone (inv-round.3) reads roundKey.3.
    expect(auxNameOf(spec, "inv-round.3.add-round-key")).toBe("roundKey.3");
    // What was inv-round.3 is now inv-round.4 and reads roundKey.4.
    expect(auxNameOf(spec, "inv-round.4.add-round-key")).toBe("roundKey.4");
    // What was inv-round.9 (the highest in 10-round AES) is now inv-round.10.
    expect(auxNameOf(spec, "inv-round.10.add-round-key")).toBe("roundKey.10");
    // inv-round.0 / inv-round.1 are untouched (they have lower indexes
    // than source).
    expect(auxNameOf(spec, "inv-round.0.add-round-key")).toBe("roundKey.0");
    expect(auxNameOf(spec, "inv-round.1.add-round-key")).toBe("roundKey.1");

    // Rename map covers the shifted earlier siblings.
    expect(renames.get("inv-round.3")).toBe("inv-round.4");
    expect(renames.get("inv-round.9")).toBe("inv-round.10");
    expect(renames.get("inv-round.3.inv-sub-bytes")).toBe("inv-round.4.inv-sub-bytes");
  });

  it("bumps inv-initial.add-round-key auxName roundKey.{rounds} → roundKey.{rounds+1}", () => {
    const { spec } = duplicateRoundGroup(aes128DecryptSpec, "inv-round.2", "reverse");
    // 10 rounds → 11, so inv-initial reads roundKey.11 after the bump.
    expect(auxNameOf(spec, "inv-initial.add-round-key")).toBe("roundKey.11");
  });

  it("bumps key-expansion's rounds + morphs type to @2 in reverse mode too", () => {
    const { spec } = duplicateRoundGroup(aes128DecryptSpec, "inv-round.2", "reverse");
    expect(keyExpansionRounds(spec)).toBe(11);
    expect(keyExpansionType(spec)).toBe("aes.key-expansion@2");
  });
});

// ─── 4. Rename-map exhaustiveness ─────────────────────────────────────────

describe("duplicateRoundGroup — rename map exhaustiveness", () => {
  it("forward: contains every renamed group AND every renamed child leaf", () => {
    const { renames } = duplicateRoundGroup(aes128Spec, "round.3", "forward");
    // Affected rounds: round.4..round.10 (originally) → round.5..round.11.
    // Each round has 4 children except the final (3 children).
    let expectedEntries = 0;
    for (let n = 4; n <= 9; n++) {
      expectedEntries += 1 + 4; // group + 4 leaves
    }
    expectedEntries += 1 + 3; // round.10 (final) → round.11 group + 3 leaves
    expect(renames.size).toBe(expectedEntries);
  });

  it("reverse: contains every renamed inv-round + inv-round children, but NOT inv-initial leaf", () => {
    const { renames } = duplicateRoundGroup(aes128DecryptSpec, "inv-round.3", "reverse");
    // Affected: inv-round.4..inv-round.9 (each has 4 children).
    let expectedEntries = 0;
    for (let n = 4; n <= 9; n++) {
      expectedEntries += 1 + 4;
    }
    // inv-initial.add-round-key has its auxName bumped (a PARAM change),
    // but its ID doesn't change — so it's correctly absent from the
    // rename map. The map only tracks layout-relevant id rewrites.
    expect(renames.size).toBe(expectedEntries);
    expect(renames.get("inv-initial.add-round-key")).toBeUndefined();
  });
});

// ─── 5. Reference equality / immutability ─────────────────────────────────

describe("duplicateRoundGroup — does not mutate the input spec", () => {
  it("forward: original spec serializes identically before and after", () => {
    const before = JSON.stringify(aes128Spec);
    duplicateRoundGroup(aes128Spec, "round.2", "forward");
    expect(JSON.stringify(aes128Spec)).toBe(before);
  });

  it("reverse: original decrypt spec serializes identically before and after", () => {
    const before = JSON.stringify(aes128DecryptSpec);
    duplicateRoundGroup(aes128DecryptSpec, "inv-round.2", "reverse");
    expect(JSON.stringify(aes128DecryptSpec)).toBe(before);
  });
});

// ─── 5b. End-to-end runtime correctness (forward × reverse round-trip) ──

describe("duplicateRoundGroup — end-to-end round-trip on a duplicated AES-128", () => {
  it("a forward-duplicated encrypt + reverse-duplicated decrypt round-trips the plaintext", () => {
    // Use the canonical FIPS-197 §A.1 (plaintext, key) pair. The
    // ciphertext won't match standard AES-128 (the modified spec has 11
    // rounds), so we don't compare against published bytes — we just
    // verify that decrypt-of-encrypt returns the original plaintext.
    const plaintextHex = "00112233445566778899aabbccddeeff";
    const keyHex = "000102030405060708090a0b0c0d0e0f";

    // Forward: duplicate round.2 in the encrypt spec.
    const { spec: encryptSpec } = duplicateRoundGroup(aes128Spec, "round.2", "forward");
    // Reverse: duplicate inv-round.2 in the decrypt spec (the matching
    // mirror operation — duplicating the round that consumes the same
    // key index produces an inverse of the encrypt modification).
    const { spec: decryptSpec } = duplicateRoundGroup(aes128DecryptSpec, "inv-round.2", "reverse");

    const registry = buildDefaultRegistry();

    // Run the encrypt.
    const encryptTrace = runSpec(encryptSpec, registry, {
      initialState: matrixFromBytes(bytesFromHex(plaintextHex)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
    });
    expect(encryptTrace.finalState.shape).toBe("matrix4x4-bytes");
    if (encryptTrace.finalState.shape !== "matrix4x4-bytes") return;
    const ciphertextBytes = encryptTrace.finalState.bytes;
    expect(ciphertextBytes.length).toBe(16);

    // Run the decrypt on the ciphertext we just produced.
    const decryptTrace = runSpec(decryptSpec, registry, {
      initialState: matrixFromBytes(ciphertextBytes),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
    });
    expect(decryptTrace.finalState.shape).toBe("matrix4x4-bytes");
    if (decryptTrace.finalState.shape !== "matrix4x4-bytes") return;
    expect(hexFromBytes(decryptTrace.finalState.bytes)).toBe(plaintextHex);
  });

  it("the duplicated spec computes a DIFFERENT ciphertext from canonical AES-128", () => {
    // Sanity that the duplicate actually changed the cipher's behavior —
    // without this, a buggy mutator that returned `spec` unchanged could
    // still pass the round-trip test.
    const plaintextHex = "00112233445566778899aabbccddeeff";
    const keyHex = "000102030405060708090a0b0c0d0e0f";
    const canonicalCiphertext = "69c4e0d86a7b0430d8cdb78070b4c55a"; // FIPS-197 §C.1

    const { spec: encryptSpec } = duplicateRoundGroup(aes128Spec, "round.2", "forward");
    const registry = buildDefaultRegistry();

    const trace = runSpec(encryptSpec, registry, {
      initialState: matrixFromBytes(bytesFromHex(plaintextHex)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
    });
    if (trace.finalState.shape !== "matrix4x4-bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).not.toBe(canonicalCiphertext);
  });
});

// ─── 6. Error paths ───────────────────────────────────────────────────────

describe("duplicateRoundGroup — error paths", () => {
  it("throws on unknown source id", () => {
    expect(() => duplicateRoundGroup(aes128Spec, "round.99", "forward")).toThrow(/no node/);
  });

  it("throws when source isn't a group", () => {
    // round.2.sub-bytes is a leaf, not a group.
    expect(() => duplicateRoundGroup(aes128Spec, "round.2.sub-bytes", "forward")).toThrow(
      /must be a group/,
    );
  });

  it("throws on direction/id-pattern mismatch (reverse on round.N)", () => {
    expect(() => duplicateRoundGroup(aes128Spec, "round.2", "reverse")).toThrow(
      /doesn't match the round-id format/,
    );
  });

  it("throws on direction/id-pattern mismatch (forward on inv-round.N)", () => {
    expect(() => duplicateRoundGroup(aes128DecryptSpec, "inv-round.2", "forward")).toThrow(
      /doesn't match the round-id format/,
    );
  });
});
