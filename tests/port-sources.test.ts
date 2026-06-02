/**
 * Tests for the port-wiring editor's legal-source enumeration + shape-compat
 * classification (universal-port plan Phase 4d-bis, `src/core/port-sources.ts`).
 *
 * Three groups:
 *   1. `classifyBinding` — the byteLength-coerce verdict.
 *   2. `legalSourcesForInput` scope rules — synthetic specs pin INCLUSION
 *      (preceding sibling, container seed, top-scope `$input`) and EXCLUSION
 *      (self, following siblings, cross-scope, nested `$input`).
 *   3. Anti-drift superset — every binding every SHIPPED spec already declares
 *      must appear in the enumerator's output, proving it agrees with the
 *      runtime / `spec-shapes.ts` validator on all real data.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { classifyBinding, legalSourcesForInput } from "@/core/port-sources";
import type { CipherSpec, StepNode } from "@/core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "@/core/types";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

/** Minimal CipherSpec wrapper around a list of steps for the synthetic cases. */
const makeSpec = (steps: readonly StepNode[]): CipherSpec => ({
  id: "src-test@1",
  name: "src-test",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps,
});

/** Does the enumerated source set contain this (node, port) pair? */
const has = (
  sources: ReturnType<typeof legalSourcesForInput>,
  node: string,
  port: string,
): boolean => sources.some((s) => s.node === node && s.port === port);

describe("classifyBinding", () => {
  it("is 'ok' when both ports declare the same byteLength", () => {
    expect(classifyBinding({ byteLength: 16 }, { byteLength: 16 })).toBe("ok");
  });

  it("is 'coerce' when both declare a byteLength and they differ", () => {
    expect(classifyBinding({ byteLength: 16 }, { byteLength: 8 })).toBe("coerce");
  });

  it("is 'ok' when the target is polymorphic (no byteLength)", () => {
    expect(classifyBinding({ layout: "raw" }, { byteLength: 8 })).toBe("ok");
    expect(classifyBinding(undefined, { byteLength: 8 })).toBe("ok");
  });

  it("is 'ok' when the source is polymorphic (no byteLength)", () => {
    expect(classifyBinding({ byteLength: 16 }, { layout: "raw" })).toBe("ok");
    expect(classifyBinding({ byteLength: 16 }, undefined)).toBe("ok");
  });

  it("ignores layout-only differences (advisory, not a coerce)", () => {
    expect(
      classifyBinding({ byteLength: 4, layout: "be-word" }, { byteLength: 4, layout: "le-word" }),
    ).toBe("ok");
  });
});

describe("legalSourcesForInput — top scope", () => {
  // a → b at the top scope. b reads a.output.
  const spec = makeSpec([
    { kind: "step", id: "a", type: "not@1", params: {} },
    {
      kind: "step",
      id: "b",
      type: "not@1",
      params: {},
      portInputs: { input: { node: "a", port: "output" } },
    },
  ]);

  it("offers the preceding sibling's output AND the top-scope $input", () => {
    const sources = legalSourcesForInput(spec, registry, "b", "input");
    expect(has(sources, "a", "output")).toBe(true);
    expect(has(sources, INPUT_SOURCE_ID, INPUT_SOURCE_PORT)).toBe(true);
    expect(sources).toHaveLength(2);
  });

  it("never offers the leaf itself or a following sibling", () => {
    const sources = legalSourcesForInput(spec, registry, "b", "input");
    expect(has(sources, "b", "output")).toBe(false);
  });

  it("offers only $input for the first node (no preceding siblings)", () => {
    const sources = legalSourcesForInput(spec, registry, "a", "input");
    expect(sources).toHaveLength(1);
    expect(has(sources, INPUT_SOURCE_ID, INPUT_SOURCE_PORT)).toBe(true);
  });

  it("returns [] for a non-existent / non-leaf id", () => {
    expect(legalSourcesForInput(spec, registry, "nope", "input")).toEqual([]);
  });
});

describe("legalSourcesForInput — nested (seeded group) body", () => {
  // Top: p, then group g (seeded from p). Body: g.x reads the seed, g.y reads g.x.
  const spec = makeSpec([
    { kind: "step", id: "p", type: "not@1", params: {} },
    {
      kind: "group",
      id: "g",
      label: "G",
      seedInput: { node: "p", port: "output" },
      bodyOutput: { node: "g.y", port: "output" },
      children: [
        {
          kind: "step",
          id: "g.x",
          type: "not@1",
          params: {},
          portInputs: { input: { node: "g", port: "in" } },
        },
        {
          kind: "step",
          id: "g.y",
          type: "not@1",
          params: {},
          portInputs: { input: { node: "g.x", port: "output" } },
        },
      ],
    },
  ]);

  it("offers the container seed port(g,'in') plus the preceding body sibling", () => {
    const sources = legalSourcesForInput(spec, registry, "g.y", "input");
    expect(has(sources, "g", "in")).toBe(true);
    expect(has(sources, "g.x", "output")).toBe(true);
    expect(sources).toHaveLength(2);
  });

  it("does NOT offer $input from a nested scope (would throw at runtime)", () => {
    const sources = legalSourcesForInput(spec, registry, "g.y", "input");
    expect(has(sources, INPUT_SOURCE_ID, INPUT_SOURCE_PORT)).toBe(false);
  });

  it("does NOT offer a cross-scope top-level sibling", () => {
    const sources = legalSourcesForInput(spec, registry, "g.y", "input");
    expect(has(sources, "p", "output")).toBe(false);
  });

  it("offers only the seed for the body's head leaf", () => {
    const sources = legalSourcesForInput(spec, registry, "g.x", "input");
    expect(sources).toHaveLength(1);
    expect(has(sources, "g", "in")).toBe(true);
  });
});

describe("legalSourcesForInput — anti-drift superset over shipped specs", () => {
  // Collect every (leafId, portName, binding) across a spec tree.
  const collectBindings = (
    spec: CipherSpec,
  ): { leafId: string; portName: string; node: string; port: string }[] => {
    const out: { leafId: string; portName: string; node: string; port: string }[] = [];
    const visit = (nodes: readonly StepNode[]): void => {
      for (const node of nodes) {
        if (node.kind === "step") {
          for (const [portName, binding] of Object.entries(node.portInputs ?? {})) {
            out.push({ leafId: node.id, portName, node: binding.node, port: binding.port });
          }
        } else {
          visit(node.children);
        }
      }
    };
    visit(spec.steps);
    return out;
  };

  const specs: Array<[string, CipherSpec]> = [
    ["aes-128", aes128Spec],
    ["aes-128-ecb", aes128EcbSpec],
    ["aes-128-cbc", aes128CbcSpec],
    ["serpent-128", serpent128Spec],
    ["des", desSpec],
    ["sha-256", buildSha256Spec()],
    ["speck-32-64-be", speck32_64BeSpec],
  ];

  for (const [name, spec] of specs) {
    it(`every declared binding in ${name} is a member of the enumerated legal set`, () => {
      const bindings = collectBindings(spec);
      // Guard against a spec that wires nothing (would make this vacuous).
      expect(bindings.length).toBeGreaterThan(0);
      for (const b of bindings) {
        const sources = legalSourcesForInput(spec, registry, b.leafId, b.portName);
        expect(
          has(sources, b.node, b.port),
          `${name}: leaf ${b.leafId} port ${b.portName} → ${b.node}.${b.port} not enumerated`,
        ).toBe(true);
      }
    });
  }
});
