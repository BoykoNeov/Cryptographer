/**
 * ChaCha20 quarter-round RECOGNITION (`src/core/chacha-shape.ts`).
 *
 * The recognizer is what turns a flat run of 98 ARX leaves into eight readable
 * quarter-round cells, in both the graph view and the linear diagram. These
 * tests check the property that matters: that it derives the RFC's structure
 * from WIRING ALONE — no leaf ids, no spec tag, no direction-awareness — and
 * that it declines cleanly rather than half-matching when the wiring isn't
 * ChaCha's.
 *
 * The declining half is the load-bearing half. A recognizer that matched
 * loosely would lay a canonical cell over a round that isn't one, which is a
 * worse failure than no cell at all: the user would read RFC structure into
 * wiring that doesn't have it.
 */

import { chacha20DecryptSpec, chacha20EncryptSpec } from "@/ciphers/chacha20";
import { analyzeChaChaDoubleRound, findActiveChaChaQuarterRound } from "@/core/chacha-shape";
import { analyzeFeistelRound } from "@/core/feistel-shape";
import { analyzeTwofishRound } from "@/core/twofish-shape";
import type { CipherSpec, StepGroup, StepNode, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

/** Every group in a spec, depth-first — the double rounds live inside the iterate. */
const allGroups = (spec: CipherSpec): StepGroup[] => {
  const out: StepGroup[] = [];
  const walk = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "group") {
        out.push(n);
        walk(n.children);
      } else if (n.kind === "iterate") {
        walk(n.children);
      }
    }
  };
  walk(spec.steps);
  return out;
};

const doubleRounds = (spec: CipherSpec): StepGroup[] =>
  allGroups(spec).filter((g) => analyzeChaChaDoubleRound(g) !== null);

/** Deep-clone a group so a test can perturb its wiring without leaking. */
const cloneGroup = (group: StepGroup): StepGroup => JSON.parse(JSON.stringify(group)) as StepGroup;

describe("analyzeChaChaDoubleRound — deriving RFC 8439 §2.1 from wiring", () => {
  it("recognizes all ten double rounds of the shipped encrypt spec", () => {
    expect(doubleRounds(chacha20EncryptSpec)).toHaveLength(10);
  });

  it("recognizes the decrypt spec identically — the specs are structurally the same", () => {
    // ChaCha20 decryption is the same operation as encryption, so unlike
    // Twofish (whose two rotations swap) this recognizer needs no direction
    // branch at all. If a branch ever creeps in, these counts diverge.
    expect(doubleRounds(chacha20DecryptSpec)).toHaveLength(10);
  });

  it("finds eight quarter rounds per double round, each of twelve leaves", () => {
    for (const group of doubleRounds(chacha20EncryptSpec)) {
      const shape = analyzeChaChaDoubleRound(group);
      expect(shape).not.toBeNull();
      expect(shape?.quarterRounds).toHaveLength(8);
      for (const qr of shape?.quarterRounds ?? []) {
        expect(qr.memberIds).toHaveLength(12);
        expect(qr.ops).toHaveLength(12);
      }
    }
  });

  it("derives the RFC's operation sequence: +, ^, <<<16, +, ^, <<<12, +, ^, <<<8, +, ^, <<<7", () => {
    // This is the whole pedagogical payload — the rotation constants read as
    // RFC 8439 §2.1 writes them (16/12/8/7), which is the reason
    // `rotate-bits-left@1` exists at all rather than reusing the right-rotate
    // at its complement (16/20/24/25).
    const shape = analyzeChaChaDoubleRound(doubleRounds(chacha20EncryptSpec)[0] as StepGroup);
    const qr = shape?.quarterRounds[0];
    expect(qr?.ops.map((o) => o.kind)).toEqual([
      "add",
      "xor",
      "rotate",
      "add",
      "xor",
      "rotate",
      "add",
      "xor",
      "rotate",
      "add",
      "xor",
      "rotate",
    ]);
    expect(
      qr?.ops.map((o) => (o.kind === "rotate" ? o.bits : null)).filter((b) => b !== null),
    ).toEqual([16, 12, 8, 7]);
  });

  it("derives which rail each operation targets — a+=b, d^=a, d<<<, c+=d, b^=c, b<<<", () => {
    const shape = analyzeChaChaDoubleRound(doubleRounds(chacha20EncryptSpec)[0] as StepGroup);
    const qr = shape?.quarterRounds[0];
    expect(qr?.ops.map((o) => o.target)).toEqual([
      "a",
      "d",
      "d",
      "c",
      "b",
      "b",
      "a",
      "d",
      "d",
      "c",
      "b",
      "b",
    ]);
    // The source rails on the add/xor ops, in order: b, a, d, c, b, a, d, c.
    expect(
      qr?.ops.filter((o) => o.kind !== "rotate").map((o) => (o as { source: string }).source),
    ).toEqual(["b", "a", "d", "c", "b", "a", "d", "c"]);
  });

  it("names the leaf producing each rail's final value", () => {
    const shape = analyzeChaChaDoubleRound(doubleRounds(chacha20EncryptSpec)[0] as StepGroup);
    const qr = shape?.quarterRounds[0];
    // a and c end on their second add; b ends on <<<7; d ends on <<<8.
    expect(qr?.outputs.a).toBe(qr?.ops[6]?.nodeId);
    expect(qr?.outputs.d).toBe(qr?.ops[8]?.nodeId);
    expect(qr?.outputs.c).toBe(qr?.ops[9]?.nodeId);
    expect(qr?.outputs.b).toBe(qr?.ops[11]?.nodeId);
    expect(qr?.outputs.b).toBe(qr?.id); // the anchor IS the b output
  });

  it("the eight quarter rounds tile the group exactly — no leaf claimed twice, none left over", () => {
    // The partition property. 8 × 12 = 96 members, plus the split and the
    // concat, is the group's entire leaf population.
    for (const group of doubleRounds(chacha20EncryptSpec)) {
      const shape = analyzeChaChaDoubleRound(group);
      if (!shape) throw new Error("expected a shape");
      const claimed = shape.quarterRounds.flatMap((qr) => qr.memberIds);
      expect(new Set(claimed).size).toBe(96);
      const leafIds = group.children.filter((c) => c.kind === "step").map((c) => c.id);
      expect(new Set([...claimed, shape.splitId, shape.concatId])).toEqual(new Set(leafIds));
    }
  });

  it("the four column quarter rounds read the split; the four diagonal ones do not", () => {
    // RFC 8439 §2.3.1's structure, recovered from wiring: a column round mixes
    // the state's columns (so it reads the freshly-split words), then a diagonal
    // round mixes its outputs. This is what makes the two-tier graph layout an
    // honest depiction rather than an arbitrary arrangement.
    const shape = analyzeChaChaDoubleRound(doubleRounds(chacha20EncryptSpec)[0] as StepGroup);
    if (!shape) throw new Error("expected a shape");
    const readsSplit = shape.quarterRounds.map((qr) =>
      Object.values(qr.inputs).every((b) => b.node === shape.splitId),
    );
    expect(readsSplit).toEqual([true, true, true, true, false, false, false, false]);
  });
});

describe("analyzeChaChaDoubleRound — declining what is not a ChaCha round", () => {
  it("returns null for every other cipher's round groups", () => {
    // Cross-recognizer isolation, checked in both directions below.
    for (const group of allGroups(chacha20EncryptSpec)) {
      const isChaCha = analyzeChaChaDoubleRound(group) !== null;
      if (!isChaCha) continue;
      // A ChaCha double round must NOT also read as a Feistel or Twofish round.
      expect(analyzeFeistelRound(group)).toBeNull();
      expect(analyzeTwofishRound(group)).toBeNull();
    }
  });

  it("returns null when one operation is rewired — the partition gate fires", () => {
    // Perturbation, run rather than assumed. Redirect the second a-add's
    // operand to the split, which severs it from its quarter round: the walk
    // for that round now fails, so the whole double round declines.
    const group = cloneGroup(doubleRounds(chacha20EncryptSpec)[0] as StepGroup);
    expect(analyzeChaChaDoubleRound(group)).not.toBeNull(); // clone still matches
    const shape = analyzeChaChaDoubleRound(group);
    const victimId = shape?.quarterRounds[0]?.ops[6]?.nodeId;
    const victim = group.children.find((c) => c.id === victimId);
    if (!victim || victim.kind !== "step" || !victim.portInputs) {
      throw new Error("expected the second a-add to have port inputs");
    }
    (victim.portInputs as Record<string, { node: string; port: string }>).operand0 = {
      node: shape?.splitId as string,
      port: "output0",
    };
    expect(analyzeChaChaDoubleRound(group)).toBeNull();
  });

  it("returns null when a rotation constant is changed — 16/12/8/7 is structural", () => {
    // The rotation amounts are not decoration: the walk uses them to tell the
    // four lines apart. A round with the wrong constants is not the RFC's
    // quarter round and must not be drawn as one.
    const group = cloneGroup(doubleRounds(chacha20EncryptSpec)[0] as StepGroup);
    const shape = analyzeChaChaDoubleRound(group);
    const rot12Id = shape?.quarterRounds[0]?.ops[5]?.nodeId;
    const rot = group.children.find((c) => c.id === rot12Id);
    if (!rot || rot.kind !== "step") throw new Error("expected the <<<12 rotation");
    (rot.params as Record<string, unknown>).bits = 13;
    expect(analyzeChaChaDoubleRound(group)).toBeNull();
  });

  it("returns null when an extra leaf is spliced into the round — no orphans allowed", () => {
    // A leaf the eight walks don't claim means the cell would render with a
    // member floating outside every quarter round. Declining is the honest
    // response; the generic stack shows all 99 leaves truthfully.
    const group = cloneGroup(doubleRounds(chacha20EncryptSpec)[0] as StepGroup);
    const shape = analyzeChaChaDoubleRound(group);
    (group.children as StepNode[]).push({
      kind: "step",
      id: "interloper",
      type: "rotate-bits-left@1",
      params: { bits: 3, wordBits: 32 },
      portInputs: { input: { node: shape?.splitId as string, port: "output0" } },
    });
    expect(analyzeChaChaDoubleRound(group)).toBeNull();
  });
});

describe("findActiveChaChaQuarterRound", () => {
  const frameAt = (stepId: string, path: readonly string[]): TraceFrame =>
    ({ stepId, path }) as unknown as TraceFrame;

  it("resolves the quarter round owning the active leaf", () => {
    const group = doubleRounds(chacha20EncryptSpec)[0] as StepGroup;
    const shape = analyzeChaChaDoubleRound(group);
    if (!shape) throw new Error("expected a shape");
    const target = shape.quarterRounds[5] as { id: string; memberIds: readonly string[] };
    const found = findActiveChaChaQuarterRound(
      frameAt(target.memberIds[4] as string, ["chacha-blocks", group.id]),
      chacha20EncryptSpec,
    );
    expect(found?.quarterRound.id).toBe(target.id);
    expect(found?.quarterRoundIndex).toBe(5);
  });

  it("returns null on the split and the concat — they belong to no single quarter round", () => {
    const group = doubleRounds(chacha20EncryptSpec)[0] as StepGroup;
    const shape = analyzeChaChaDoubleRound(group);
    if (!shape) throw new Error("expected a shape");
    for (const id of [shape.splitId, shape.concatId]) {
      expect(
        findActiveChaChaQuarterRound(frameAt(id, ["chacha-blocks", group.id]), chacha20EncryptSpec),
      ).toBeNull();
    }
  });

  it("returns null for a frame outside any double round", () => {
    expect(
      findActiveChaChaQuarterRound(frameAt("chacha-xor", ["chacha-blocks"]), chacha20EncryptSpec),
    ).toBeNull();
  });
});
