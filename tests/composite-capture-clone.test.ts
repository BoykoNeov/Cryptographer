/**
 * Compose-and-save (universal-port Phase 4f) — headless core.
 *
 * Pinned here (pure, registry-free):
 *   - `captureCompositeFromGroup` produces a context-free template (seedInput
 *     cleared, defaultCollapsed, label = name) and guards its inputs.
 *   - `cloneGroupWithFreshIds` regenerates every id collision-free and rebases
 *     INTERNAL port references (portInputs, the children's `port(groupId,"in")`
 *     seed refs, bodyOutput) while leaving EXTERNAL refs untouched.
 *   - `pickSeedBinding` chooses the "insert into the pipeline" seed for each
 *     anchor flavor.
 *
 * The end-to-end byte-parity gate vs a real round group lives in the Slice E
 * integration test; this file proves the mechanics in isolation.
 */

import {
  type CompositeInsertAnchor,
  captureCompositeFromGroup,
  cloneGroupWithFreshIds,
  collectSpecIds,
  pickSeedBinding,
} from "@/core/spec-mutations";
import type { CipherSpec, PortBinding, StepGroup, StepLeaf, StepNode } from "@/core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "@/core/types";
import { describe, expect, it } from "vitest";

const port = (node: string, portName: string): PortBinding => ({ node, port: portName });

/** A minimal AES-round-shaped group: seeded, two wired leaves, a published exit. */
const makeRoundGroup = (id: string): StepGroup => ({
  kind: "group",
  id,
  label: "Round 1",
  seedInput: port("prev", "out"), // external (a preceding sibling outside the group)
  bodyOutput: port(`${id}.mix`, "output"),
  children: [
    {
      kind: "step",
      id: `${id}.sub`,
      type: "byte-substitute@1",
      params: { sbox: [1, 2, 3] },
      portInputs: { input: port(id, "in") }, // reads the group seed
    },
    {
      kind: "step",
      id: `${id}.mix`,
      type: "gf-matrix-multiply@1",
      params: { matrix: [[1]] },
      portInputs: { input: port(`${id}.sub`, "output") }, // internal sibling ref
    },
  ],
});

/** Wrap nodes into a CipherSpec shell (fields beyond `steps` are unused here). */
const specOf = (...steps: StepNode[]): CipherSpec =>
  ({ id: "test", inputShape: "bytes", steps }) as unknown as CipherSpec;

const prevLeaf: StepLeaf = {
  kind: "step",
  id: "prev",
  type: "permute@1",
  params: {},
};

describe("captureCompositeFromGroup", () => {
  it("clears seedInput, sets defaultCollapsed, and renames the label", () => {
    const spec = specOf(prevLeaf, makeRoundGroup("round.1"));
    const template = captureCompositeFromGroup(spec, "round.1", "AES Round");

    expect(template.seedInput).toBeUndefined();
    expect(template.defaultCollapsed).toBe(true);
    expect(template.label).toBe("AES Round");
    // Boundary preserved: the published exit + children carry through.
    expect(template.bodyOutput).toEqual(port("round.1.mix", "output"));
    expect(template.children).toHaveLength(2);
  });

  it("throws on a non-group id, an empty group, and looping containers", () => {
    const spec = specOf(prevLeaf, makeRoundGroup("round.1"));
    expect(() => captureCompositeFromGroup(spec, "prev", "x")).toThrow(/must be a group/);
    expect(() => captureCompositeFromGroup(spec, "missing", "x")).toThrow(/no node with id/);

    const emptyGroup: StepGroup = { kind: "group", id: "g", label: "G", children: [] };
    expect(() => captureCompositeFromGroup(specOf(emptyGroup), "g", "x")).toThrow(/is empty/);

    const withIterate: StepGroup = {
      kind: "group",
      id: "g",
      label: "G",
      children: [{ kind: "iterate", id: "g.it", children: [] } as unknown as StepNode],
    };
    expect(() => captureCompositeFromGroup(specOf(withIterate), "g", "x")).toThrow(/unsupported/);
  });
});

describe("cloneGroupWithFreshIds", () => {
  it("regenerates ids collision-free and rebases internal references", () => {
    const source = makeRoundGroup("round.1");
    // Force a collision on the root so dedup kicks in: the live spec already
    // holds every id of the source (cloning next to the original).
    const existing = collectSpecIds(specOf(prevLeaf, source));
    const { group, renames } = cloneGroupWithFreshIds(source, "round.1", existing);

    // Root deduped, descendants derived from the deduped root.
    expect(group.id).toBe("round.1-2");
    expect(renames.get("round.1")).toBe("round.1-2");
    expect(renames.get("round.1.sub")).toBe("round.1-2.sub");
    expect(renames.get("round.1.mix")).toBe("round.1-2.mix");
    // No clone id collides with the live spec.
    for (const id of renames.values()) expect(existing.has(id)).toBe(false);

    const [sub, mix] = group.children as [StepLeaf, StepLeaf];
    expect(sub.id).toBe("round.1-2.sub");
    expect(mix.id).toBe("round.1-2.mix");
    // The seed ref (port(groupId,"in")) and the internal sibling ref rebase.
    expect(sub.portInputs?.input).toEqual(port("round.1-2", "in"));
    expect(mix.portInputs?.input).toEqual(port("round.1-2.sub", "output"));
    // bodyOutput (internal) rebases; seedInput (external "prev") is untouched.
    expect(group.bodyOutput).toEqual(port("round.1-2.mix", "output"));
    expect(group.seedInput).toEqual(port("prev", "out"));
  });

  it("preserves params + narration and shares no node identity with the source", () => {
    const source = makeRoundGroup("round.1");
    const { group } = cloneGroupWithFreshIds(source, "fresh", new Set());
    expect(group.id).toBe("fresh");
    const [sub] = group.children as [StepLeaf];
    expect(sub.params).toEqual({ sbox: [1, 2, 3] });
    // Fresh node objects (id changed) — the readonly tree is rebuilt, not aliased.
    expect(group.children[0]).not.toBe(source.children[0]);
  });
});

describe("pickSeedBinding", () => {
  // A stub resolver: containers publish "out", leaves publish "output".
  const primaryOut = (n: StepNode): string => (n.kind === "step" ? "output" : "out");
  const spec = specOf(prevLeaf, makeRoundGroup("round.1"));

  it("after X → X's primary output", () => {
    const a: CompositeInsertAnchor = { kind: "after", stepId: "prev" };
    expect(pickSeedBinding(spec, a, primaryOut)).toEqual(port("prev", "output"));
  });

  it("before X → X's preceding sibling, or $input when X is first at top", () => {
    expect(pickSeedBinding(spec, { kind: "before", stepId: "round.1" }, primaryOut)).toEqual(
      port("prev", "output"),
    );
    expect(pickSeedBinding(spec, { kind: "before", stepId: "prev" }, primaryOut)).toEqual(
      port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    );
  });

  it("root-append → last top-level node, or $input on an empty spec", () => {
    expect(pickSeedBinding(spec, { kind: "root-append" }, primaryOut)).toEqual(
      port("round.1", "out"),
    );
    expect(pickSeedBinding(specOf(), { kind: "root-append" }, primaryOut)).toEqual(
      port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    );
  });

  it("into-start C → port(C,'in') when C seeds its body, else undefined", () => {
    // makeRoundGroup carries a seedInput, so it seeds its body.
    expect(
      pickSeedBinding(spec, { kind: "into-start", containerId: "round.1" }, primaryOut),
    ).toEqual(port("round.1", "in"));
    const unseeded: StepGroup = { kind: "group", id: "plain", label: "P", children: [] };
    expect(
      pickSeedBinding(specOf(unseeded), { kind: "into-start", containerId: "plain" }, primaryOut),
    ).toBeUndefined();
  });
});
