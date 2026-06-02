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
import { COERCE_STEP_TYPE } from "@/core/port-projection";
import { classifyBinding, legalSourcesForInput } from "@/core/port-sources";
import { runSpec } from "@/core/runtime";
import { setPortBinding } from "@/core/spec-mutations";
import { bytesFromHex } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
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

describe("legalSourcesForInput — preceding container's published output", () => {
  // A top-scope leaf AFTER a group may read that group's published `out`,
  // but NOT a leaf buried inside the group's body (different scope).
  const spec = makeSpec([
    {
      kind: "group",
      id: "g",
      label: "G",
      children: [{ kind: "step", id: "g.x", type: "not@1", params: {} }],
    },
    {
      kind: "step",
      id: "after",
      type: "not@1",
      params: {},
      portInputs: { input: { node: "g", port: "out" } },
    },
  ]);

  it("offers the finished container's out port", () => {
    const sources = legalSourcesForInput(spec, registry, "after", "input");
    expect(has(sources, "g", "out")).toBe(true);
  });

  it("does NOT offer a leaf inside that container (cross-scope)", () => {
    const sources = legalSourcesForInput(spec, registry, "after", "input");
    expect(has(sources, "g.x", "output")).toBe(false);
  });
});

describe("coerce wiring — reachable in a shipped spec + coerces-and-runs", () => {
  // The DES key schedule's rotate step wants a 7-byte half; load-key publishes
  // 8 bytes. Wiring rotate's input straight to load-key is a genuine concrete
  // mismatch (8 → 7) — the canary that the coerce affordance isn't dead UI.
  const SINK = "key-schedule.g0.rotate";
  const SOURCE = { node: "key-schedule.load-key", port: "output" } as const;

  it("legalSourcesForInput tags the mismatched source 'coerce'", () => {
    const sources = legalSourcesForInput(desSpec, registry, SINK, "input");
    const match = sources.find((s) => s.node === SOURCE.node && s.port === SOURCE.port);
    expect(match, "the load-key source must be a legal target for rotate").toBeDefined();
    expect(match?.compat).toBe("coerce");
  });

  it("a coerce wire coerces-and-runs (no throw) and emits a __coerce__ frame", () => {
    const rewired = setPortBinding(desSpec, SINK, "input", {
      node: SOURCE.node,
      port: SOURCE.port,
    });
    const trace = runSpec(rewired, registry, {
      initialState: { shape: "bytes", bytes: bytesFromHex("0123456789abcdef") },
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
    });
    // The run completed (a coerce is warn-and-run, never a throw)…
    expect(trace.frames.length).toBeGreaterThan(0);
    // …and the length mismatch surfaced as a visible synthetic coercion frame.
    expect(trace.frames.some((f) => f.stepType === COERCE_STEP_TYPE)).toBe(true);
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
