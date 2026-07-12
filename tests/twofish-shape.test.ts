/**
 * Twofish 4-rail round-shape recognition (`src/core/twofish-shape.ts`) — the
 * separate analyzer that lets the graph view lay Twofish rounds out as the
 * textbook 4-rail cell (two g boxes, PHT, R2/R3 mix rails, 4-way swap) instead
 * of a generic vertical stack.
 *
 * These pin the wiring-derived partition (g0/g1/rolR1/PHT/mix) for a REAL
 * encrypt AND decrypt round — the two differ only in the 1-bit rotation leaves,
 * so recognizing both proves the analyzer keys off structure, not leaf ids —
 * plus a null-sweep proving it never mis-fires on the 2-way (DES/Blowfish),
 * AES, or SHA-256 shapes.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { blowfishSpec } from "@/ciphers/blowfish";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { twofishSpec } from "@/ciphers/twofish";
import { twofishDecryptSpec } from "@/ciphers/twofish-decrypt";
import { runSpec } from "@/core/runtime";
import { findStepAndParent } from "@/core/spec-mutations";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { analyzeTwofishRound, findActiveTwofishRound } from "@/core/twofish-shape";
import type { AuxValue, CipherSpec, StepGroup } from "@/core/types";
import { describe, expect, it } from "vitest";

const roundGroup = (spec: CipherSpec, id: string): StepGroup => {
  const located = findStepAndParent(spec, id);
  if (!located || located.node.kind !== "group") throw new Error(`expected a group at ${id}`);
  return located.node;
};

// Walk every group in a spec (for null-sweeps).
const allGroups = (spec: CipherSpec): StepGroup[] => {
  const out: StepGroup[] = [];
  const walk = (nodes: readonly CipherSpec["steps"][number][]): void => {
    for (const node of nodes) {
      if (node.kind === "group") {
        out.push(node);
        walk(node.children);
      } else if (node.kind !== "step") {
        // iterate / for-each containers carry children too.
        walk((node as { children?: readonly CipherSpec["steps"][number][] }).children ?? []);
      }
    }
  };
  walk(spec.steps);
  return out;
};

describe("analyzeTwofishRound — encrypt round recognition", () => {
  const shape = analyzeTwofishRound(roundGroup(twofishSpec, "round.0"));

  it("recognizes a Twofish round and names its structural parts", () => {
    expect(shape).not.toBeNull();
    if (!shape) return;
    expect(shape.splitId).toBe("round.0.split");
    expect(shape.recombineId).toBe("round.0.recombine");
    expect(shape.rolNodeId).toBe("round.0.rolR1");
    // Both g stacks are 8 leaves (split + 4 S-boxes + concat + MDS + perm).
    expect(shape.g0Ids).toHaveLength(8);
    expect(shape.g1Ids).toHaveLength(8);
    // g0 wraps R0's stack; g1 wraps ROL(R1)'s stack, rolR1 excluded.
    expect(shape.g0Ids).toContain("round.0.g0.split");
    expect(shape.g0Ids).toContain("round.0.g0.perm");
    expect(shape.g1Ids).toContain("round.0.g1.split");
    expect(shape.g1Ids).toContain("round.0.g1.perm");
    expect(shape.g1Ids).not.toContain("round.0.rolR1");
  });

  it("captures the PHT anchor (loadK0/K1, f0, dbl2T1, f1)", () => {
    expect(shape).not.toBeNull();
    if (!shape) return;
    expect(new Set(shape.phtIds)).toEqual(
      new Set(["round.0.loadK0", "round.0.loadK1", "round.0.f0", "round.0.dbl2T1", "round.0.f1"]),
    );
    expect(shape.fIds).toEqual(["round.0.f0", "round.0.f1"]);
  });

  it("captures the R2/R3 mix rails feeding the recombine (encrypt: r2x/r2p, r3r/r3p)", () => {
    expect(shape).not.toBeNull();
    if (!shape) return;
    expect(new Set(shape.r2MixIds)).toEqual(new Set(["round.0.r2x", "round.0.r2p"]));
    expect(new Set(shape.r3MixIds)).toEqual(new Set(["round.0.r3r", "round.0.r3p"]));
  });

  it("derives the 4-way swap roles: mixed inputs 0/1, carried inputs 2/3 from split output0/1", () => {
    expect(shape).not.toBeNull();
    if (!shape) return;
    expect(shape.mixedInputPorts).toEqual(["input0", "input1"]);
    expect(shape.carriedInputPorts).toEqual(["input2", "input3"]);
    expect(shape.carriedSplitPorts).toEqual(["output0", "output1"]);
  });
});

describe("analyzeTwofishRound — decrypt round recognition (same structure, inverted rotations)", () => {
  it("recognizes a decrypt round with the mirror mix rails (r2r/r2p, r3x/r3p)", () => {
    const shape = analyzeTwofishRound(roundGroup(twofishDecryptSpec, "round.0"));
    expect(shape).not.toBeNull();
    if (!shape) return;
    // Same partition — the analyzer keys off wiring, not the rotation-leaf ids.
    expect(shape.g0Ids).toHaveLength(8);
    expect(shape.g1Ids).toHaveLength(8);
    expect(shape.rolNodeId).toBe("round.0.rolR1");
    expect(new Set(shape.phtIds)).toEqual(
      new Set(["round.0.loadK0", "round.0.loadK1", "round.0.f0", "round.0.dbl2T1", "round.0.f1"]),
    );
    // Decrypt inverts the two rotations: r2r (rotate) then r2p (xor); r3x (xor)
    // then r3p (rotate). Still two leaves per rail.
    expect(new Set(shape.r2MixIds)).toEqual(new Set(["round.0.r2r", "round.0.r2p"]));
    expect(new Set(shape.r3MixIds)).toEqual(new Set(["round.0.r3x", "round.0.r3p"]));
  });

  it("recognizes every one of the 16 rounds (encrypt and decrypt)", () => {
    for (let r = 0; r < 16; r++) {
      expect(
        analyzeTwofishRound(roundGroup(twofishSpec, `round.${r}`)),
        `enc round.${r}`,
      ).not.toBeNull();
      expect(
        analyzeTwofishRound(roundGroup(twofishDecryptSpec, `round.${r}`)),
        `dec round.${r}`,
      ).not.toBeNull();
    }
  });
});

describe("analyzeTwofishRound — null-sweep (never mis-fires on 2-way / AES / SHA)", () => {
  it("returns null for every group in the DES, Blowfish, AES-128 and SHA-256 specs", () => {
    const sha256Spec = buildSha256Spec();
    for (const spec of [desSpec, blowfishSpec, aes128Spec, sha256Spec]) {
      for (const group of allGroups(spec)) {
        expect(analyzeTwofishRound(group), `${spec.id}:${group.id}`).toBeNull();
      }
    }
  });
});

describe("findActiveTwofishRound — resolves a round from a frame", () => {
  const trace = runSpec(twofishSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex("00000000000000000000000000000000")),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex("00000000000000000000000000000000")],
    ]),
  });

  it("finds round.3 from a frame inside it", () => {
    const frame = trace.frames.find((f) => f.stepId.startsWith("round.3.g0.mds"));
    expect(frame).toBeDefined();
    if (!frame) return;
    const found = findActiveTwofishRound(frame, twofishSpec);
    expect(found).not.toBeNull();
    expect(found?.group.id).toBe("round.3");
  });

  it("rejects a non-round frame (input whitening)", () => {
    const frame = trace.frames.find((f) => f.stepId.startsWith("whiten-in.split"));
    expect(frame).toBeDefined();
    if (!frame) return;
    expect(findActiveTwofishRound(frame, twofishSpec)).toBeNull();
  });
});
