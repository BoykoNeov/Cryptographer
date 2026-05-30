/**
 * Tests for the structural mutation helpers added in Slice 4 of the 2D
 * editor plan:
 *   • findStepAndParent — locate a node + its parent + its index
 *   • insertStepAfter / insertStepBefore — splice a new node in
 *   • removeStep — splice a node out
 *   • reorderStep — move within the same parent
 *
 * These are pure functions; node-env vitest is enough (no DOM).
 *
 * Coverage strategy: exercise each operation at three depths — top level,
 * inside a group, inside an iterate body — using the real shipped specs
 * (aes-128 and aes-128-ecb) so we also catch any accidental dependency on
 * a contrived test-only shape.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import {
  findStep,
  findStepAndParent,
  insertStepAfter,
  insertStepBefore,
  prependChildToContainer,
  removeStep,
  reorderStep,
} from "@/core/spec-mutations";
import type { StepLeaf, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";
import { buildSyntheticFeistelSpec } from "./fixtures/synthetic-feistel-rounds";

// B4 (universal-port Phase 4d): the port-native DES no longer uses
// `feistel-round`, but `findStepAndParent`'s track descent survives until
// Phase 5. The shared synthetic Feistel fixture (shaped like the old DES —
// a `rounds` group of feistel-rounds with 4-leaf R tracks) exercises it.
const synthFeistelSpec = buildSyntheticFeistelSpec();

/**
 * Tiny fixture leaf used as the "newly inserted" node. The structural
 * mutators don't care about contents — only `id`, `kind`, and tree
 * placement — so we never need a registered step type here.
 */
const fixtureLeaf = (id: string): StepLeaf => ({
  kind: "step",
  id,
  type: "test.fixture@1",
  params: {},
});

/** Count every node (leaf + group + iterate) anywhere in the tree. */
const countAllNodes = (nodes: readonly StepNode[]): number => {
  let n = 0;
  for (const node of nodes) {
    n++;
    if (node.kind === "step") continue;
    if (node.kind === "feistel-round") {
      for (const track of node.tracks) n += countAllNodes(track.children);
    } else {
      n += countAllNodes(node.children);
    }
  }
  return n;
};

describe("findStepAndParent", () => {
  it("locates a top-level leaf with parent=null", () => {
    // key-expansion is a top-level leaf in aes-128 (lives directly in
    // spec.steps, not inside a round group).
    const loc = findStepAndParent(aes128Spec, "key-expansion");
    expect(loc).not.toBeNull();
    expect(loc?.node.id).toBe("key-expansion");
    expect(loc?.parent).toBeNull();
    expect(loc?.indexInParent).toBe(0); // key-expansion is first
  });

  it("locates a leaf nested inside a round group with parent set", () => {
    // round.1.sub-bytes lives inside the round.1 group.
    const loc = findStepAndParent(aes128Spec, "round.1.sub-bytes");
    expect(loc).not.toBeNull();
    expect(loc?.node.id).toBe("round.1.sub-bytes");
    expect(loc?.parent?.id).toBe("round.1");
    expect(loc?.parent?.kind).toBe("group");
    // Within round.1 group, sub-bytes is the first step.
    expect(loc?.indexInParent).toBe(0);
  });

  it("locates a group itself (not just its leaves)", () => {
    // findStep returns null for groups; findStepAndParent must NOT.
    const loc = findStepAndParent(aes128Spec, "round.1");
    expect(loc).not.toBeNull();
    expect(loc?.node.kind).toBe("group");
    expect(loc?.parent).toBeNull(); // round.1 is top-level
  });

  it("locates a leaf inside an iterate body", () => {
    // aes-128-ecb's iterate id is "ecb-blocks"; its children are the
    // AES-128 round body (round.1, round.2, ...). Find a deeply nested
    // leaf inside the iterate to prove recursion descends into iterates.
    const loc = findStepAndParent(aes128EcbSpec, "round.1.sub-bytes");
    expect(loc).not.toBeNull();
    expect(loc?.parent?.id).toBe("round.1");
    expect(loc?.parent?.kind).toBe("group");
  });

  it("locates an iterate node itself", () => {
    const loc = findStepAndParent(aes128EcbSpec, "ecb-blocks");
    expect(loc).not.toBeNull();
    expect(loc?.node.kind).toBe("iterate");
    expect(loc?.parent).toBeNull();
  });

  it("returns null for a non-existent id", () => {
    expect(findStepAndParent(aes128Spec, "no-such-step")).toBeNull();
  });

  // ── Feistel-round track descent (Phase 6d-ii) ─────────────────────
  // The walker recurses into each `feistel-round`'s tracks. A leaf
  // inside a track gets a StepLocation whose `parent` is the round
  // itself + `trackIdx` naming the matched track.

  it("locates a leaf inside an R track of a DES Feistel round", () => {
    const loc = findStepAndParent(synthFeistelSpec, "round.1.expand-R");
    expect(loc).not.toBeNull();
    expect(loc?.node.id).toBe("round.1.expand-R");
    expect(loc?.parent?.kind).toBe("feistel-round");
    expect(loc?.parent?.id).toBe("round.1");
    expect(loc?.indexInParent).toBe(0); // first child of R track
    expect(loc?.trackIdx).toBe(1); // R is the second track on DES rounds
  });

  it("locates a leaf at a non-zero index inside an R track", () => {
    // round.1's R track: expand-R, xor-K, s-boxes, p-permute.
    const loc = findStepAndParent(synthFeistelSpec, "round.1.s-boxes");
    expect(loc).not.toBeNull();
    expect(loc?.parent?.kind).toBe("feistel-round");
    expect(loc?.indexInParent).toBe(2);
    expect(loc?.trackIdx).toBe(1);
  });

  it("locates the feistel-round group itself with its outer parent (rounds group)", () => {
    // round.1 lives inside the "rounds" StepGroup, not inside another
    // feistel-round. Parent should be the rounds group, NOT round.1
    // (the round isn't its own parent), and trackIdx should be omitted.
    const loc = findStepAndParent(synthFeistelSpec, "round.1");
    expect(loc).not.toBeNull();
    expect(loc?.node.kind).toBe("feistel-round");
    expect(loc?.parent?.kind).toBe("group");
    expect(loc?.parent?.id).toBe("rounds");
    expect(loc?.trackIdx).toBeUndefined();
  });

  it("returns null for the synthetic passthrough id (not a spec node)", () => {
    expect(findStepAndParent(synthFeistelSpec, "round.1:passthrough-0")).toBeNull();
  });

  it("returns null for the synthetic rejoin id (not a spec node)", () => {
    expect(findStepAndParent(synthFeistelSpec, "round.1:rejoin")).toBeNull();
  });
});

describe("insertStepAfter", () => {
  it("inserts at the top level", () => {
    const newStep = fixtureLeaf("after-key-expansion");
    const updated = insertStepAfter(aes128Spec, "key-expansion", newStep);

    // The new step lands at index 1 in the top-level array.
    const inserted = findStepAndParent(updated, "after-key-expansion");
    expect(inserted?.parent).toBeNull();
    expect(inserted?.indexInParent).toBe(1);
    // Original node count grows by exactly one.
    expect(countAllNodes(updated.steps)).toBe(countAllNodes(aes128Spec.steps) + 1);
  });

  it("inserts inside a round group, anchored to a child", () => {
    const newStep = fixtureLeaf("round.1.injected");
    const updated = insertStepAfter(aes128Spec, "round.1.sub-bytes", newStep);

    const inserted = findStepAndParent(updated, "round.1.injected");
    expect(inserted?.parent?.id).toBe("round.1");
    // round.1's children were [sub-bytes, shift-rows, mix-columns, add-round-key];
    // the new node goes after sub-bytes → index 1.
    expect(inserted?.indexInParent).toBe(1);
  });

  it("inserts inside an iterate body", () => {
    // The aes-128-ecb iterate body is the round structure of AES.
    // Insert after a deeply nested leaf (round.1.sub-bytes lives in
    // round.1, which lives inside the ecb-blocks iterate).
    const newStep = fixtureLeaf("round.1.injected-in-ecb");
    const updated = insertStepAfter(aes128EcbSpec, "round.1.sub-bytes", newStep);

    const inserted = findStepAndParent(updated, "round.1.injected-in-ecb");
    expect(inserted).not.toBeNull();
    // The chain up is: round.1 group → ecb-blocks iterate → top-level.
    expect(inserted?.parent?.id).toBe("round.1");
  });

  it("preserves reference equality on untouched top-level branches", () => {
    // Insert into round.5; round.1, round.2, … round.4 should keep their
    // original references because they live in the same top-level array
    // that DID change. Hmm — that's not quite right: when the top-level
    // array changes, the array reference changes but each *element* of
    // the new array should still point at the original group object for
    // untouched siblings.
    const newStep = fixtureLeaf("round.5.injected");
    const updated = insertStepAfter(aes128Spec, "round.5.sub-bytes", newStep);

    // The top-level array reference changes (round.5 was rebuilt) but
    // round.1's object reference doesn't.
    const originalRound1 = aes128Spec.steps.find((n) => n.id === "round.1");
    const updatedRound1 = updated.steps.find((n) => n.id === "round.1");
    expect(updatedRound1).toBe(originalRound1);
  });

  it("does not mutate the original spec", () => {
    const before = JSON.stringify(aes128Spec);
    insertStepAfter(aes128Spec, "round.1.sub-bytes", fixtureLeaf("ephemeral"));
    expect(JSON.stringify(aes128Spec)).toBe(before);
  });

  it("throws when the anchor step does not exist", () => {
    expect(() => insertStepAfter(aes128Spec, "no-such-id", fixtureLeaf("x"))).toThrow(
      /no step with id "no-such-id"/,
    );
  });
});

describe("insertStepBefore", () => {
  it("inserts at the top level", () => {
    const newStep = fixtureLeaf("before-key-expansion");
    const updated = insertStepBefore(aes128Spec, "key-expansion", newStep);

    const inserted = findStepAndParent(updated, "before-key-expansion");
    expect(inserted?.parent).toBeNull();
    expect(inserted?.indexInParent).toBe(0); // becomes the new first step
  });

  it("inserts before a child inside a group", () => {
    // round.1.shift-rows is the second child; insert before it → index 1.
    const newStep = fixtureLeaf("round.1.before-shift");
    const updated = insertStepBefore(aes128Spec, "round.1.shift-rows", newStep);

    const inserted = findStepAndParent(updated, "round.1.before-shift");
    expect(inserted?.parent?.id).toBe("round.1");
    expect(inserted?.indexInParent).toBe(1);
  });

  it("throws when the anchor step does not exist", () => {
    expect(() => insertStepBefore(aes128Spec, "no-such-id", fixtureLeaf("x"))).toThrow(
      /no step with id "no-such-id"/,
    );
  });
});

describe("prependChildToContainer", () => {
  it("inserts as the first child of a non-empty group", () => {
    // Byte-native round.1 has 4 children (AddRoundKey merged in F3):
    // [sub-bytes, shift-rows, mix-columns, add-round-key].
    const newStep = fixtureLeaf("prepended-into-round-1");
    const updated = prependChildToContainer(aes128Spec, "round.1", newStep);
    const round1 = findStepAndParent(updated, "round.1");
    expect(round1?.node.kind).toBe("group");
    if (round1?.node.kind === "group") {
      expect(round1.node.children.length).toBe(5);
      expect(round1.node.children[0]?.id).toBe("prepended-into-round-1");
      expect(round1.node.children[1]?.id).toBe("round.1.sub-bytes");
    }
  });

  it("inserts into an EMPTY group as the sole child", () => {
    // The headline regression: dropping a step on an empty round used to
    // fall through to root-append because `insertStepBefore(firstChild,...)`
    // had nothing to anchor on. Now the empty container actually receives
    // the new child.
    // Byte-native round.1 has 4 children (AddRoundKey merged to one leaf in F3).
    const withEmptyRound = removeStep(
      removeStep(
        removeStep(removeStep(aes128Spec, "round.1.sub-bytes"), "round.1.shift-rows"),
        "round.1.mix-columns",
      ),
      "round.1.add-round-key",
    );
    // Sanity: round.1 is now empty.
    const emptyR1 = findStepAndParent(withEmptyRound, "round.1");
    if (emptyR1?.node.kind === "group") {
      expect(emptyR1.node.children.length).toBe(0);
    }

    const newStep = fixtureLeaf("dropped-into-empty-round");
    const updated = prependChildToContainer(withEmptyRound, "round.1", newStep);

    const round1 = findStepAndParent(updated, "round.1");
    expect(round1?.node.kind).toBe("group");
    if (round1?.node.kind === "group") {
      expect(round1.node.children.length).toBe(1);
      expect(round1.node.children[0]?.id).toBe("dropped-into-empty-round");
    }
    // And critically: the step did NOT leak to the top level.
    const topLevelDropTarget = updated.steps.find((n) => n.id === "dropped-into-empty-round");
    expect(topLevelDropTarget).toBeUndefined();
  });

  it("inserts into an iterate body as the first child", () => {
    // aes-128-ecb's iterate id is "ecb-blocks"; its children begin with
    // the round structure (initial.add-round-key, round.1, …). Prepending
    // should slot in before initial.add-round-key.
    const newStep = fixtureLeaf("prepended-into-ecb-body");
    const updated = prependChildToContainer(aes128EcbSpec, "ecb-blocks", newStep);
    const iter = findStepAndParent(updated, "ecb-blocks");
    expect(iter?.node.kind).toBe("iterate");
    if (iter && iter.node.kind === "iterate") {
      expect(iter.node.children[0]?.id).toBe("prepended-into-ecb-body");
    }
  });

  it("throws when the id resolves to a leaf, not a container", () => {
    expect(() => prependChildToContainer(aes128Spec, "key-expansion", fixtureLeaf("x"))).toThrow(
      /resolves to a leaf, not a container/,
    );
  });

  it("throws when no node has that id", () => {
    expect(() => prependChildToContainer(aes128Spec, "no-such-id", fixtureLeaf("x"))).toThrow(
      /no node with id "no-such-id"/,
    );
  });

  it("preserves reference equality on untouched sibling branches", () => {
    // Prepending into round.5 should leave round.1's object reference unchanged.
    const updated = prependChildToContainer(aes128Spec, "round.5", fixtureLeaf("new-in-r5"));
    const originalRound1 = aes128Spec.steps.find((n) => n.id === "round.1");
    const updatedRound1 = updated.steps.find((n) => n.id === "round.1");
    expect(updatedRound1).toBe(originalRound1);
  });

  it("does not mutate the original spec", () => {
    const before = JSON.stringify(aes128Spec);
    prependChildToContainer(aes128Spec, "round.1", fixtureLeaf("ephemeral"));
    expect(JSON.stringify(aes128Spec)).toBe(before);
  });
});

describe("removeStep", () => {
  it("removes a leaf from a group; the group's child count shrinks by one", () => {
    // round.1 originally has 4 children: sub-bytes, shift-rows,
    // mix-columns, add-round-key. Remove sub-bytes → 3 remain.
    const originalRound1 = findStepAndParent(aes128Spec, "round.1");
    const originalChildCount =
      originalRound1?.node.kind === "group" ? originalRound1.node.children.length : -1;

    const updated = removeStep(aes128Spec, "round.1.sub-bytes");
    const newRound1 = findStepAndParent(updated, "round.1");
    expect(newRound1?.node.kind).toBe("group");
    if (newRound1?.node.kind === "group") {
      expect(newRound1.node.children.length).toBe(originalChildCount - 1);
      // The removed step is gone.
      expect(newRound1.node.children.some((c) => c.id === "round.1.sub-bytes")).toBe(false);
      // Other siblings survive in their original order.
      expect(newRound1.node.children[0]?.id).toBe("round.1.shift-rows");
    }
  });

  it("removing the only child leaves an empty group standing", () => {
    // Construct a spec with a single-child group, then remove that child.
    const onlyChild = fixtureLeaf("onlychild");
    const withSingleton = insertStepAfter(aes128Spec, "key-expansion", {
      kind: "group",
      id: "singleton-group",
      label: "Singleton",
      children: [onlyChild],
    });
    const afterRemove = removeStep(withSingleton, "onlychild");

    // The group itself remains, with an empty children array.
    const groupLoc = findStepAndParent(afterRemove, "singleton-group");
    expect(groupLoc?.node.kind).toBe("group");
    if (groupLoc?.node.kind === "group") {
      expect(groupLoc.node.children.length).toBe(0);
    }
  });

  it("does not mutate the original spec", () => {
    const before = JSON.stringify(aes128Spec);
    removeStep(aes128Spec, "round.1.sub-bytes");
    expect(JSON.stringify(aes128Spec)).toBe(before);
  });

  it("throws on a non-existent stepId", () => {
    expect(() => removeStep(aes128Spec, "no-such-id")).toThrow(/no step with id "no-such-id"/);
  });
});

describe("reorderStep", () => {
  it("moves a leaf within its parent group", () => {
    // Move round.1.add-round-key (originally at index 3) to index 0.
    const updated = reorderStep(aes128Spec, "round.1.add-round-key", 0);
    const round1 = findStepAndParent(updated, "round.1");
    expect(round1?.node.kind).toBe("group");
    if (round1?.node.kind === "group") {
      expect(round1.node.children[0]?.id).toBe("round.1.add-round-key");
      // The displaced steps shift right but keep their relative order.
      expect(round1.node.children[1]?.id).toBe("round.1.sub-bytes");
      expect(round1.node.children[2]?.id).toBe("round.1.shift-rows");
      expect(round1.node.children[3]?.id).toBe("round.1.mix-columns");
    }
  });

  it("moves a top-level node", () => {
    // round.2 (originally at index 2 in spec.steps) → index 0.
    const updated = reorderStep(aes128Spec, "round.2", 0);
    expect(updated.steps[0]?.id).toBe("round.2");
  });

  it("returns the original spec by reference when newIndex equals current index", () => {
    // round.1.sub-bytes is at index 0 within round.1; reorder to 0 = no-op.
    const result = reorderStep(aes128Spec, "round.1.sub-bytes", 0);
    expect(result).toBe(aes128Spec);
  });

  it("clamps newIndex when out of range (large value)", () => {
    // Asking for index 999 puts the node at the end of its parent.
    const updated = reorderStep(aes128Spec, "round.1.sub-bytes", 999);
    const round1 = findStepAndParent(updated, "round.1");
    if (round1?.node.kind === "group") {
      const last = round1.node.children[round1.node.children.length - 1];
      expect(last?.id).toBe("round.1.sub-bytes");
    }
  });

  it("clamps newIndex when out of range (negative value)", () => {
    const updated = reorderStep(aes128Spec, "round.1.shift-rows", -5);
    const round1 = findStepAndParent(updated, "round.1");
    if (round1?.node.kind === "group") {
      expect(round1.node.children[0]?.id).toBe("round.1.shift-rows");
    }
  });

  it("leaves untouched groups at reference equality", () => {
    // Reordering inside round.5 should not perturb round.1's object identity.
    const updated = reorderStep(aes128Spec, "round.5.sub-bytes", 2);
    const originalRound1 = aes128Spec.steps.find((n) => n.id === "round.1");
    const updatedRound1 = updated.steps.find((n) => n.id === "round.1");
    expect(updatedRound1).toBe(originalRound1);
  });

  it("does not mutate the original spec", () => {
    const before = JSON.stringify(aes128Spec);
    reorderStep(aes128Spec, "round.1.sub-bytes", 3);
    expect(JSON.stringify(aes128Spec)).toBe(before);
  });

  it("throws on a non-existent stepId", () => {
    expect(() => reorderStep(aes128Spec, "no-such-id", 0)).toThrow(/no step with id "no-such-id"/);
  });
});

describe("structural mutations preserve runtime correctness", () => {
  it("findStep still works after insertStepAfter (round-trip via the existing finder)", () => {
    const newStep = fixtureLeaf("post-keyexp");
    const updated = insertStepAfter(aes128Spec, "key-expansion", newStep);
    // findStep is leaf-only and should locate our new leaf.
    expect(findStep(updated, "post-keyexp")?.id).toBe("post-keyexp");
    // Pre-existing leaves are still findable.
    expect(findStep(updated, "round.1.sub-bytes")?.id).toBe("round.1.sub-bytes");
  });

  it("removing then re-inserting via insertStepBefore yields a structurally equivalent spec", () => {
    // round.1.shift-rows lives at index 1 inside round.1. Remove it,
    // then insert a copy back at the same anchor (before mix-columns,
    // which moved up to index 1 after removal). Final shape should be
    // identical to the input.
    const removed = removeStep(aes128Spec, "round.1.shift-rows");
    const reinserted = insertStepBefore(
      removed,
      "round.1.mix-columns",
      fixtureLeaf("round.1.shift-rows"),
    );
    const round1 = findStepAndParent(reinserted, "round.1");
    if (round1?.node.kind === "group") {
      expect(round1.node.children.map((c) => c.id)).toEqual([
        "round.1.sub-bytes",
        "round.1.shift-rows",
        "round.1.mix-columns",
        "round.1.add-round-key",
      ]);
    }
  });
});
