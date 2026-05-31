/**
 * A4 — Anti-creep contract test (scaffolding-suppression plan, Phase A).
 *
 * The plan's load-bearing goal is **bytes-only leaf executors**. The
 * lifted-legacy matrix/word steps — registered `kind: "ported"` but still
 * carrying a `legacy` fallback executor + projection `meta` — are the
 * scaffolding being phased out. Each Phase-B cipher rebuild (B1 AES, B2
 * Speck, B3 Serpent, B4 DES) replaces its lifts with port-native byte
 * primitives that declare only raw layouts. This test makes the property
 * LOAD: a registered ported leaf may NOT declare a non-bytes port shape
 * unless it is on the explicit, SHRINKING allowlist below.
 *
 * Empirically (the seed for ALLOWLIST was dumped from a throwaway probe
 * against `buildDefaultRegistry()`, NOT from file greps — the grep missed
 * two string-branch layouts), every offender today is a `[legacy meta]`
 * lift. Every port-native step (`xor@1`, `rotate-bits-right@1`,
 * `byte-slice@1`, …) is already raw-only, so the allowlist == the set of
 * not-yet-rebuilt lifts and it drains to empty as Phase B ships.
 *
 * ── Terminology bridge ("bytes" vs "raw") ──────────────────────────────
 * The plan's A4 prose says "any PortContract input/output that isn't
 * `bytes`". But `PortLayout` (core/types.ts) has NO `"bytes"` member — its
 * byte-native layout is `"raw"`, and an ABSENT layout defaults to raw. The
 * `"bytes"` token the plan borrows belongs to the *other* contract system
 * (`StateShape`, exercised by tests/state-shape-contracts.test.ts). So the
 * mapping this test enforces is:
 *     bytes-native  ==  layout absent  OR  layout === "raw"
 *     non-bytes     ==  any other layout — today: "matrix-cm-4x4",
 *                       "matrix-cm-4x4-array", "preserve-input-variant"
 *                       (and the declared-but-unused "be-word"/"le-word").
 *
 * ── Why exact-equality (deliberately stronger than the plan's gate) ─────
 * The plan's literal gate (slice A4) only asks: green with the allowlist,
 * a deliberately-broken fixture goes red — a SUBSET check. But the plan's
 * PROSE requires "a Phase B cipher's rebuild PR must remove its allowlist
 * entry", which a subset check can't enforce (a stale entry for an
 * already-rebuilt step would sit forever). So we assert EXACT set-equality
 * between offenders and the allowlist, split into two directional checks
 * for diagnostic failure messages:
 *     (1) offenders ∖ allowlist empty → "a new non-bytes port crept in"
 *     (2) allowlist ∖ offenders empty → "rebuilt byte-native; drop the entry"
 * This escalates to compiler-enforced at Phase C1 (when the State variants
 * are deleted and a non-bytes leaf port no longer type-checks); until then
 * this runtime test is the guard.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { resolvePortMap } from "@/core/port-projection";
import { StepRegistry } from "@/core/registry";
import type {
  Json,
  PortContract,
  PortShape,
  PortShapeMap,
  PortedExecutor,
  StepDocumentation,
} from "@/core/types";
import { describe, expect, it } from "vitest";

/**
 * The not-yet-rebuilt lifted-legacy steps that still declare a non-bytes
 * (interpreted-shape) port layout. Grouped by the Phase-B slice that will
 * delete the lift and thereby remove the entry. KEEP THIS SORTED-AT-COMPARE
 * (we sort a copy below); the grouping is for the human reader.
 *
 * A rebuild PR that makes a step byte-native MUST delete its line here, or
 * assertion (2) fails.
 */
const NON_BYTES_ALLOWLIST: readonly string[] = [
  // EMPTY since Slice 5.2 (2026-05-31). The matrix `matrix-cm-4x4` transforms
  // + ECB/CBC boundary steps retired in Slice 5.1 (2026-05-30) with the
  // MatrixState shape. The last entry — `generic.aux-copy@1`'s
  // `out:result = "preserve-input-variant"` sentinel — dropped to `"raw"` when
  // the aux primitives went port-native in Slice 5.2 (its only purpose was
  // round-tripping a MatrixState through aux-copy, and that variant is gone).
  // No shipped ported leaf declares a non-bytes port any more.
];

// (The `LEGACY_CONTRACT_ALLOWLIST` + its runtime "legacy-contract tripwire"
//  describe were retired in Phase C / universal-port Phase 5. `StepRegistration`
//  is now a single `kind: "ported"` shape, so a legacy registration is
//  unrepresentable in the type system — a strictly stronger guarantee than the
//  allowlist-plus-tripwire it replaced.)

/**
 * Kitchen-sink params sufficient to resolve EVERY function-form
 * `PortShapeMap` in the registry without throwing. Layouts inside the
 * contracts are static literals independent of param VALUES — so one valid
 * resolution per step suffices; we never need to explore param space. The
 * fields cover: `inputCount` (xor/and/add-mod-32/concat), `rounds` (every
 * key schedule), `widths` (split-bytes), `byteLength`+`auxName`
 * (aux-load-bytes), `sourceByteLength`/`length`/`offset` (byte-slice),
 * `bytes` (constant-load). A future function-form step that needs a field
 * absent here will THROW → assertion (3) fails loudly, prompting the
 * author to extend this object.
 */
const KITCHEN_SINK: Json = {
  inputCount: 2,
  rounds: 1,
  widths: [4],
  byteLength: 4,
  auxName: "probe",
  sourceByteLength: 16,
  length: 4,
  offset: 0,
  bytes: [0, 0, 0, 0],
} as unknown as Json;

type Scan = {
  /** stepType → list of "side:port=layout" descriptors for offending ports. */
  readonly offenders: ReadonlyMap<string, readonly string[]>;
  /** stepTypes whose function-form contract threw under KITCHEN_SINK. */
  readonly unresolvable: readonly string[];
};

/**
 * Walk every `kind: "ported"` registration and collect ports whose layout
 * is non-bytes (present and not "raw"). Factored out so the negative-gate
 * test can run it against a hand-built fixture registry.
 */
const findNonBytesLeafPorts = (registry: StepRegistry): Scan => {
  const offenders = new Map<string, string[]>();
  const unresolvable: string[] = [];

  const scanSide = (side: "in" | "out", map: PortShapeMap, hits: string[]): void => {
    let resolved: ReadonlyMap<string, PortShape>;
    try {
      resolved = resolvePortMap(map, KITCHEN_SINK);
    } catch {
      throw new Error("UNRESOLVABLE"); // bubbled up and recorded per-step below
    }
    for (const [portName, shape] of resolved) {
      if (shape.layout !== undefined && shape.layout !== "raw") {
        hits.push(`${side}:${portName}=${shape.layout}`);
      }
    }
  };

  for (const stepType of registry.types()) {
    const reg = registry.getRegistration(stepType);
    if (reg?.kind !== "ported") continue;
    const hits: string[] = [];
    try {
      scanSide("in", reg.shape.inputs, hits);
      scanSide("out", reg.shape.outputs, hits);
    } catch {
      unresolvable.push(stepType);
      continue;
    }
    if (hits.length > 0) offenders.set(stepType, hits);
  }

  return { offenders, unresolvable };
};

const sorted = (xs: Iterable<string>): string[] => [...xs].sort();
const setDiff = (a: Iterable<string>, b: ReadonlySet<string>): string[] =>
  [...a].filter((x) => !b.has(x)).sort();

describe("byte-native ports — anti-creep contract (A4)", () => {
  const registry = buildDefaultRegistry();
  const { offenders, unresolvable } = findNonBytesLeafPorts(registry);
  const allowSet = new Set(NON_BYTES_ALLOWLIST);

  it("(3) every function-form port contract resolves under the kitchen-sink params", () => {
    expect(
      unresolvable,
      `ported steps whose contract threw — extend KITCHEN_SINK with the missing param(s): ${unresolvable.join(", ")}`,
    ).toEqual([]);
  });

  it("(1) no non-bytes port has crept in outside the allowlist", () => {
    const crept = setDiff(offenders.keys(), allowSet);
    const detail = crept.map((s) => `${s} {${(offenders.get(s) ?? []).join(", ")}}`).join("; ");
    expect(
      crept,
      `new non-bytes leaf port(s) — rebuild byte-native or (if truly a not-yet-migrated lift) add to NON_BYTES_ALLOWLIST: ${detail}`,
    ).toEqual([]);
  });

  it("(2) every allowlist entry is still a non-bytes lift (shrinks as Phase B ships)", () => {
    const stale = setDiff(NON_BYTES_ALLOWLIST, new Set(offenders.keys()));
    expect(
      stale,
      `allowlisted step(s) no longer declare a non-bytes port (rebuilt byte-native?) — delete the line(s) from NON_BYTES_ALLOWLIST: ${stale.join(", ")}`,
    ).toEqual([]);
  });

  it("the allowlist has no duplicate entries", () => {
    expect(sorted(NON_BYTES_ALLOWLIST)).toEqual(sorted(new Set(NON_BYTES_ALLOWLIST)));
  });

  // (The "legacy-contract tripwire" describe was retired in Phase C —
  // `StepRegistration` is now a single `kind: "ported"` shape, so a legacy
  // registration is unrepresentable; the type system enforces what the
  // runtime filter used to.)

  // ── Gate: a deliberately-broken fixture leaf makes the checker red ──
  it("gate: a non-bytes port on a fresh fixture registry is detected", () => {
    const fixture = new StepRegistry();
    const noop: PortedExecutor = () => new Map();
    const matrixShape: PortContract = {
      inputs: new Map([["state", { byteLength: 16, layout: "matrix-cm-4x4" }]]),
      outputs: new Map([["state", { byteLength: 16, layout: "matrix-cm-4x4" }]]),
    };
    const doc: StepDocumentation = {
      name: "Fake Creep Step",
      summary: "fixture leaf that interprets its port bytes as a 4×4 matrix",
      detail: "Only exists to prove the anti-creep checker flags a non-raw layout.",
    };
    fixture.register("fixture.creep-matrix@1", {
      kind: "ported",
      executor: noop,
      shape: matrixShape,
      doc,
    });

    const scan = findNonBytesLeafPorts(fixture);
    expect([...scan.offenders.keys()]).toContain("fixture.creep-matrix@1");
    expect(scan.offenders.get("fixture.creep-matrix@1")).toEqual([
      "in:state=matrix-cm-4x4",
      "out:state=matrix-cm-4x4",
    ]);
  });

  // A raw-only fixture leaf must NOT be flagged (guards against the checker
  // over-reporting and turning every port-native step into a false offender).
  it("gate: a raw-only fixture leaf is NOT flagged", () => {
    const fixture = new StepRegistry();
    const noop: PortedExecutor = () => new Map();
    const rawShape: PortContract = {
      inputs: new Map([["input", { layout: "raw" }]]),
      outputs: new Map([["output", {}]]), // absent layout → bytes-native
    };
    const doc: StepDocumentation = {
      name: "Fake Raw Step",
      summary: "fixture leaf with only raw / absent layouts",
      detail: "Must not be reported as a non-bytes offender.",
    };
    fixture.register("fixture.raw-ok@1", {
      kind: "ported",
      executor: noop,
      shape: rawShape,
      doc,
    });

    const scan = findNonBytesLeafPorts(fixture);
    expect(scan.offenders.has("fixture.raw-ok@1")).toBe(false);
    expect(scan.unresolvable).toEqual([]);
  });
});
