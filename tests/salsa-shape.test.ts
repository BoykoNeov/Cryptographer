/**
 * Salsa20 quarter-round RECOGNITION (`src/core/salsa-shape.ts`).
 *
 * The recognizer is what turns a flat run of 98 ARX leaves into eight readable
 * quarter-round cells, in both the graph view and the linear diagram. These
 * tests check the property that matters: that it derives Bernstein's structure
 * from WIRING ALONE — no leaf ids, no spec tag, no direction-awareness — and
 * that it declines cleanly rather than half-matching when the wiring isn't
 * Salsa's.
 *
 * The declining half is the load-bearing half. A recognizer that matched
 * loosely would lay a canonical cell over a round that isn't one, which is a
 * worse failure than no cell at all: the user would read Salsa structure into
 * wiring that doesn't have it.
 *
 * **The cross-cipher isolation tests are this file's unique job.** ChaCha20 and
 * Salsa20 share the whole double-round envelope in `arx-round-shape.ts` —
 * same 16-way split, same eight anchors, same partition gate — and differ only
 * in the twelve-op walk. So "does ChaCha's analyzer stay away from Salsa's
 * rounds, and vice versa?" is a real question here in a way it was not for
 * Feistel vs Twofish, whose group shapes are not even superficially alike.
 */

import { chacha20EncryptSpec } from "@/ciphers/chacha20";
import { salsa20DecryptSpec, salsa20EncryptSpec } from "@/ciphers/salsa20";
import { analyzeChaChaDoubleRound } from "@/core/chacha-shape";
import { analyzeFeistelRound } from "@/core/feistel-shape";
import { analyzeSalsaDoubleRound, findActiveSalsaQuarterRound } from "@/core/salsa-shape";
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
  allGroups(spec).filter((g) => analyzeSalsaDoubleRound(g) !== null);

/** Deep-clone a group so a test can perturb its wiring without leaking. */
const cloneGroup = (group: StepGroup): StepGroup => JSON.parse(JSON.stringify(group)) as StepGroup;

const firstRound = (): StepGroup => doubleRounds(salsa20EncryptSpec)[0] as StepGroup;

describe("analyzeSalsaDoubleRound — deriving Bernstein's quarterround from wiring", () => {
  it("recognizes all ten double rounds of the shipped encrypt spec", () => {
    expect(doubleRounds(salsa20EncryptSpec)).toHaveLength(10);
  });

  it("recognizes the decrypt spec identically — the specs are structurally the same", () => {
    // Salsa20 decryption is the same operation as encryption, so like ChaCha
    // (and unlike Twofish, whose two rotations swap) this recognizer needs no
    // direction branch at all. If a branch ever creeps in, these counts diverge.
    expect(doubleRounds(salsa20DecryptSpec)).toHaveLength(10);
  });

  it("finds eight quarter rounds per double round, each of twelve leaves", () => {
    for (const group of doubleRounds(salsa20EncryptSpec)) {
      const shape = analyzeSalsaDoubleRound(group);
      expect(shape).not.toBeNull();
      expect(shape?.quarterRounds).toHaveLength(8);
      for (const qr of shape?.quarterRounds ?? []) {
        expect(qr.memberIds).toHaveLength(12);
        expect(qr.ops).toHaveLength(12);
      }
    }
  });

  it("derives the written sequence: add, rotate, xor — four times, with 7/9/13/18", () => {
    // The whole pedagogical payload, and the structural difference from
    // ChaCha in one assertion. ChaCha's twelve ops read add/xor/rotate ×4
    // (accumulate then rotate the accumulated rail); Salsa's read
    // add/rotate/xor ×4 — the sum is rotated BEFORE it ever touches the state.
    const shape = analyzeSalsaDoubleRound(firstRound());
    const qr = shape?.quarterRounds[0];
    expect(qr?.ops.map((o) => o.kind)).toEqual([
      "add",
      "rotate",
      "xor",
      "add",
      "rotate",
      "xor",
      "add",
      "rotate",
      "xor",
      "add",
      "rotate",
      "xor",
    ]);
    expect(
      qr?.ops.map((o) => (o.kind === "rotate" ? o.bits : null)).filter((b) => b !== null),
    ).toEqual([7, 9, 13, 18]);
  });

  it("derives each line's two sources and its target — z1=y1^((y0+y3)<<<7), and so on", () => {
    // Rails a/b/c/d are Bernstein's y0/y1/y2/y3. The four lines are
    //   z1 = y1 ^ ((y0 + y3) <<<  7)   sources a,d  target b
    //   z2 = y2 ^ ((z1 + y0) <<<  9)   sources b,a  target c
    //   z3 = y3 ^ ((z2 + z1) <<< 13)   sources c,b  target d
    //   z0 = y0 ^ ((z3 + z2) <<< 18)   sources d,c  target a
    const shape = analyzeSalsaDoubleRound(firstRound());
    const qr = shape?.quarterRounds[0];
    const adds = qr?.ops.filter((o) => o.kind === "add") ?? [];
    expect(adds.map((o) => (o.kind === "add" ? [o.srcA, o.srcB] : null))).toEqual([
      ["a", "d"],
      ["b", "a"],
      ["c", "b"],
      ["d", "c"],
    ]);
    const xors = qr?.ops.filter((o) => o.kind === "xor") ?? [];
    expect(xors.map((o) => (o.kind === "xor" ? o.target : null))).toEqual(["b", "c", "d", "a"]);
  });

  it("every rail's final value is its own line's XOR — each word written exactly once", () => {
    // Salsa's defining difference from ChaCha, stated as a structural fact.
    // ChaCha's rails end on four DIFFERENT kinds of op (two adds, a <<<8 and a
    // <<<7) because each rail is mutated repeatedly. Here every rail ends on an
    // XOR, and the anchor rotation is no rail's output at all — it lives on the
    // scratch rail, which is exactly what the diagram's fifth lane draws.
    const shape = analyzeSalsaDoubleRound(firstRound());
    const qr = shape?.quarterRounds[0];
    if (!qr) throw new Error("expected a quarter round");
    expect(qr.outputs.b).toBe(qr.ops[2]?.nodeId); // line 1's xor
    expect(qr.outputs.c).toBe(qr.ops[5]?.nodeId); // line 2's xor
    expect(qr.outputs.d).toBe(qr.ops[8]?.nodeId); // line 3's xor
    expect(qr.outputs.a).toBe(qr.ops[11]?.nodeId); // line 4's xor
    // The `<<< 18` anchor is the round's IDENTITY but nobody's output.
    expect(qr.id).toBe(qr.ops[10]?.nodeId);
    expect(Object.values(qr.outputs)).not.toContain(qr.id);
  });

  it("the eight quarter rounds tile the group exactly — no leaf claimed twice, none left over", () => {
    // The partition property. 8 × 12 = 96 members, plus the split and the
    // concat, is the group's entire leaf population. This is also what proves
    // the forward consumer scan really found `xor18`: miss it and each round
    // claims eleven leaves, leaving eight unclaimed and the gate refusing.
    for (const group of doubleRounds(salsa20EncryptSpec)) {
      const shape = analyzeSalsaDoubleRound(group);
      if (!shape) throw new Error("expected a shape");
      const claimed = shape.quarterRounds.flatMap((qr) => qr.memberIds);
      expect(new Set(claimed).size).toBe(96);
      const leafIds = group.children.filter((c) => c.kind === "step").map((c) => c.id);
      expect(new Set([...claimed, shape.splitId, shape.concatId])).toEqual(new Set(leafIds));
    }
  });

  it("the four column quarter rounds read the split; the four row ones do not", () => {
    // Bernstein's columnround-then-rowround structure, recovered from wiring.
    // This is what makes the two-tier graph layout an honest depiction rather
    // than an arbitrary arrangement.
    const shape = analyzeSalsaDoubleRound(firstRound());
    if (!shape) throw new Error("expected a shape");
    const readsSplit = shape.quarterRounds.map((qr) =>
      Object.values(qr.inputs).every((b) => b.node === shape.splitId),
    );
    expect(readsSplit).toEqual([true, true, true, true, false, false, false, false]);
  });
});

describe("analyzeSalsaDoubleRound — cross-cipher isolation", () => {
  // The ARX envelope is shared, so these two are the closest pair of shapes in
  // the app. Both directions are asserted because a walk that was merely
  // PERMISSIVE would pass one direction and fail the other.

  it("declines every ChaCha20 double round — the <<<18 anchor does not exist there", () => {
    for (const group of allGroups(chacha20EncryptSpec)) {
      expect(analyzeSalsaDoubleRound(group)).toBeNull();
    }
    // And ChaCha's own analyzer still recognizes them, so the spec above really
    // does contain double rounds and this isn't vacuously true.
    expect(allGroups(chacha20EncryptSpec).filter((g) => analyzeChaChaDoubleRound(g))).toHaveLength(
      10,
    );
  });

  it("ChaCha20's analyzer declines every Salsa20 double round", () => {
    for (const group of allGroups(salsa20EncryptSpec)) {
      expect(analyzeChaChaDoubleRound(group)).toBeNull();
    }
  });

  it("a Salsa double round is not also a Feistel or Twofish round", () => {
    for (const group of doubleRounds(salsa20EncryptSpec)) {
      expect(analyzeFeistelRound(group)).toBeNull();
      expect(analyzeTwofishRound(group)).toBeNull();
    }
  });
});

describe("analyzeSalsaDoubleRound — declining what is not a Salsa round", () => {
  it("returns null when one operation is rewired — the partition gate fires", () => {
    // Perturbation, run rather than assumed. Redirect line 3's add to the
    // split, which severs it from its quarter round: the walk for that round
    // now fails, so the whole double round declines.
    const group = cloneGroup(firstRound());
    expect(analyzeSalsaDoubleRound(group)).not.toBeNull(); // clone still matches
    const shape = analyzeSalsaDoubleRound(group);
    const victimId = shape?.quarterRounds[0]?.ops[6]?.nodeId;
    const victim = group.children.find((c) => c.id === victimId);
    if (!victim || victim.kind !== "step" || !victim.portInputs) {
      throw new Error("expected line 3's add to have port inputs");
    }
    (victim.portInputs as Record<string, { node: string; port: string }>).operand0 = {
      node: shape?.splitId as string,
      port: "output0",
    };
    expect(analyzeSalsaDoubleRound(group)).toBeNull();
  });

  it("returns null when a rotation constant is changed — 7/9/13/18 is structural", () => {
    // The rotation amounts are not decoration: the walk uses them to tell the
    // four lines apart. A round with the wrong constants is not Bernstein's
    // quarter round and must not be drawn as one.
    const group = cloneGroup(firstRound());
    const shape = analyzeSalsaDoubleRound(group);
    const rot9Id = shape?.quarterRounds[0]?.ops[4]?.nodeId;
    const rot = group.children.find((c) => c.id === rot9Id);
    if (!rot || rot.kind !== "step") throw new Error("expected the <<<9 rotation");
    (rot.params as Record<string, unknown>).bits = 11;
    expect(analyzeSalsaDoubleRound(group)).toBeNull();
  });

  it("returns null when the anchor's XOR is severed — the forward scan must find it", () => {
    // The one leaf reached FORWARD rather than backward, and therefore the one
    // the walk could most plausibly have been written without. Point line 4's
    // XOR at the split instead of at the `<<< 18`: every backward check still
    // passes, and only the consumer scan (plus the partition gate behind it)
    // catches it. Without this test a walk missing `xor18` entirely would still
    // pass every other assertion in this file except the tiling one.
    const group = cloneGroup(firstRound());
    const shape = analyzeSalsaDoubleRound(group);
    const xor18Id = shape?.quarterRounds[0]?.ops[11]?.nodeId;
    const xor = group.children.find((c) => c.id === xor18Id);
    if (!xor || xor.kind !== "step" || !xor.portInputs) {
      throw new Error("expected line 4's xor to have port inputs");
    }
    for (const [key, binding] of Object.entries(xor.portInputs)) {
      if (binding.node === shape?.quarterRounds[0]?.ops[10]?.nodeId) {
        (xor.portInputs as Record<string, { node: string; port: string }>)[key] = {
          node: shape?.splitId as string,
          port: "output0",
        };
      }
    }
    expect(analyzeSalsaDoubleRound(group)).toBeNull();
  });

  it("tolerates a swapped commutative operand pair — recognition is not positional", () => {
    // `add-mod-32@1` and `xor@1` are commutative, so swapping a pair changes
    // nothing about the cipher. The walk pins every unknown by an
    // already-identified LEAF rather than by operand index, which is what makes
    // this hold — and a user who swaps two operands in the editor must not lose
    // the canonical cell for a no-op edit.
    const group = cloneGroup(firstRound());
    const shape = analyzeSalsaDoubleRound(group);
    const addId = shape?.quarterRounds[0]?.ops[0]?.nodeId;
    const add = group.children.find((c) => c.id === addId);
    if (!add || add.kind !== "step" || !add.portInputs) {
      throw new Error("expected line 1's add to have port inputs");
    }
    const ins = add.portInputs as Record<string, { node: string; port: string }>;
    const [a, b] = [ins.operand0, ins.operand1];
    ins.operand0 = b as { node: string; port: string };
    ins.operand1 = a as { node: string; port: string };
    expect(analyzeSalsaDoubleRound(group)).not.toBeNull();
  });
});

describe("findActiveSalsaQuarterRound", () => {
  const round = (): StepGroup => firstRound();

  const frameFor = (leafId: string, path: readonly string[]): TraceFrame =>
    ({ stepId: leafId, path }) as unknown as TraceFrame;

  it("resolves the quarter round owning an active leaf", () => {
    const shape = analyzeSalsaDoubleRound(round());
    if (!shape) throw new Error("expected a shape");
    const qr = shape.quarterRounds[5];
    if (!qr) throw new Error("expected a sixth quarter round");
    const found = findActiveSalsaQuarterRound(
      frameFor(qr.ops[4]?.nodeId as string, [round().id]),
      salsa20EncryptSpec,
    );
    expect(found?.quarterRound.id).toBe(qr.id);
    expect(found?.quarterRoundIndex).toBe(5);
  });

  it("returns null for the split and the concat — they belong to no one quarter round", () => {
    const shape = analyzeSalsaDoubleRound(round());
    if (!shape) throw new Error("expected a shape");
    for (const id of [shape.splitId, shape.concatId]) {
      expect(
        findActiveSalsaQuarterRound(frameFor(id, [round().id]), salsa20EncryptSpec),
      ).toBeNull();
    }
  });
});
