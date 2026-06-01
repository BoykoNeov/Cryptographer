/**
 * `core/spec-defaults.ts` unit tests — universal-port plan Slice 2.6d
 * follow-up (2026-05-25). Covers the spec walker that derives default-
 * collapsed container ids from a `CipherSpec`, plus the effective-set
 * algebra that combines defaults with the layout store's two override
 * sets.
 *
 * Why these properties matter:
 *
 *  - `getDefaultCollapsedContainers(spec)` MUST return exactly the
 *    container ids whose spec node carries `defaultCollapsed: true`,
 *    regardless of nesting depth or container kind. A regression here
 *    would either drop SHA-256's 64 round groups from the defaults set
 *    (chip wall on first render) or pull in unintended container ids
 *    (over-collapse hides correct steps).
 *
 *  - `getEffectiveCollapsedSet(spec, layout)` MUST honor the set
 *    algebra: `(defaults ∪ collapsedGroups) − expandedGroups`. Tests
 *    pin each operand independently so a bug in any single layer
 *    surfaces as a specific failure rather than a generic "wrong set."
 *
 *  - SHA-256's specific shape — 64 `round.0..round.63` group ids, no
 *    other defaults — is the load-bearing case driving this slice.
 *    Pinned both to lock the cipher's contract and to catch a future
 *    SHA-256 refactor that loses the `defaultCollapsed: true` markers.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildSha256Spec } from "@/ciphers/sha-256";
import type { LayoutSpec } from "@/core/document";
import {
  getDefaultCollapsedContainers,
  getEffectiveCollapsedSet,
  isDefaultCollapsed,
} from "@/core/spec-defaults";
import type { CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Empty-layout sentinel used when a test only cares about spec defaults. */
const EMPTY_LAYOUT: LayoutSpec = {
  positions: {},
  collapsedGroups: [],
  flowDirection: "ltr",
};

/** Wrap a step tree in a minimal-but-valid CipherSpec shell. */
const wrapSpec = (steps: readonly StepNode[]): CipherSpec => ({
  id: "test-spec@1",
  name: "Test",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 0 },
  },
  steps,
});

// ─── getDefaultCollapsedContainers ────────────────────────────────────────

describe("getDefaultCollapsedContainers", () => {
  it("returns an empty set for a spec with no defaultCollapsed markers", () => {
    // A synthetic spec whose containers carry NO `defaultCollapsed` marker —
    // the negative-case anchor. (We no longer use a shipped AES spec here:
    // since the key-schedule decomposition (K1c) every AES spec carries the
    // default-collapsed `key-schedule` group, so AES-128 ECB now has exactly
    // ONE marker — see the dedicated assertion below.)
    const spec = wrapSpec([
      {
        kind: "group",
        id: "plain-outer",
        label: "Plain outer",
        children: [{ kind: "group", id: "plain-inner", label: "Plain inner", children: [] }],
      },
    ]);
    const ids = getDefaultCollapsedContainers(spec);
    expect(ids.size).toBe(0);
  });

  it("includes the decomposed AES key-schedule group (default-collapsed since K1c)", () => {
    // The key-schedule-decomposition (K1c) wraps the schedule in a
    // `key-schedule` group marked `defaultCollapsed: true` so its ~140
    // sub-step chips don't wall the canvas on first render. It is the ONLY
    // default-collapsed surface in AES-128 ECB (the ECB iterate renders
    // compactly at the spine level and is not marked).
    const ids = getDefaultCollapsedContainers(aes128EcbSpec);
    expect(ids.has("key-schedule")).toBe(true);
    expect(ids.size).toBe(1);
  });

  it("returns the SHA-256 default-collapsed surfaces (64 round groups + msg-schedule)", () => {
    const spec = buildSha256Spec();
    const ids = getDefaultCollapsedContainers(spec);
    // Exact set: 64 round containers (`round.N` for N in [0, 64)) plus
    // the `msg-schedule` for-each-subgraph-with-history container. Slice
    // 2.10c (2026-05-25) added `defaultCollapsed: true` to msg-schedule
    // pre-emptively before exposing SHA-256 in the cipher selector — its
    // 48 iterations × 14 leaves = 672 chips would have produced a wall
    // on first render otherwise.
    expect(ids.size).toBe(65);
    for (let t = 0; t < 64; t += 1) {
      expect(ids.has(`round.${t}`)).toBe(true);
    }
    expect(ids.has("msg-schedule")).toBe(true);
    // Sanity: the top-level `compression` for-each-subgraph is NOT in
    // the set. It renders fine uncollapsed because its body is the 64
    // round groups which ARE collapsed.
    expect(ids.has("compression")).toBe(false);
  });

  it("walks into group children (nested default-collapsed surfaces)", () => {
    // Outer container has no default; inner container does.
    const spec = wrapSpec([
      {
        kind: "group",
        id: "outer",
        label: "Outer",
        children: [
          {
            kind: "group",
            id: "inner",
            label: "Inner",
            defaultCollapsed: true,
            children: [],
          },
        ],
      },
    ]);
    const ids = getDefaultCollapsedContainers(spec);
    expect(ids.has("inner")).toBe(true);
    expect(ids.has("outer")).toBe(false);
  });

  it("respects defaultCollapsed: false (does NOT include the id)", () => {
    // Explicit false === absent — only `true` adds to the set.
    const spec = wrapSpec([
      {
        kind: "group",
        id: "explicit-false",
        label: "Explicit false",
        defaultCollapsed: false,
        children: [],
      },
    ]);
    const ids = getDefaultCollapsedContainers(spec);
    expect(ids.has("explicit-false")).toBe(false);
  });
});

// ─── isDefaultCollapsed ───────────────────────────────────────────────────

describe("isDefaultCollapsed", () => {
  it("agrees with getDefaultCollapsedContainers (membership semantics)", () => {
    const spec = buildSha256Spec();
    expect(isDefaultCollapsed(spec, "round.0")).toBe(true);
    expect(isDefaultCollapsed(spec, "round.63")).toBe(true);
    expect(isDefaultCollapsed(spec, "compression")).toBe(false);
    expect(isDefaultCollapsed(spec, "does-not-exist")).toBe(false);
  });
});

// ─── getEffectiveCollapsedSet ─────────────────────────────────────────────

describe("getEffectiveCollapsedSet", () => {
  it("returns spec defaults alone when layout is null", () => {
    const spec = buildSha256Spec();
    const effective = getEffectiveCollapsedSet(spec, null);
    // 64 round groups + msg-schedule (Slice 2.10c) = 65 defaults.
    expect(effective.size).toBe(65);
    expect(effective.has("round.0")).toBe(true);
    expect(effective.has("msg-schedule")).toBe(true);
  });

  it("returns spec defaults alone for an empty layout", () => {
    const spec = buildSha256Spec();
    const effective = getEffectiveCollapsedSet(spec, EMPTY_LAYOUT);
    expect(effective.size).toBe(65);
  });

  it("unions layout.collapsedGroups with spec defaults", () => {
    const spec = buildSha256Spec();
    // User explicitly collapses `compression` (which has no default).
    // Effective set is defaults ∪ {compression}. `msg-schedule` is already
    // in the defaults (Slice 2.10c), so using IT as the layout-collapse
    // target would not exercise the union semantic.
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: ["compression"],
      flowDirection: "ltr",
    };
    const effective = getEffectiveCollapsedSet(spec, layout);
    expect(effective.size).toBe(66);
    expect(effective.has("compression")).toBe(true);
    expect(effective.has("msg-schedule")).toBe(true);
    expect(effective.has("round.0")).toBe(true);
  });

  it("subtracts layout.expandedGroups from the union", () => {
    const spec = buildSha256Spec();
    // User explicitly EXPANDS round.5 (which is in the spec defaults).
    // Effective set is defaults − {round.5}.
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      expandedGroups: ["round.5"],
    };
    const effective = getEffectiveCollapsedSet(spec, layout);
    // 65 defaults − 1 expanded = 64.
    expect(effective.size).toBe(64);
    expect(effective.has("round.5")).toBe(false);
    // The other 63 default-collapsed rounds + msg-schedule remain collapsed.
    expect(effective.has("round.0")).toBe(true);
    expect(effective.has("round.63")).toBe(true);
    expect(effective.has("msg-schedule")).toBe(true);
  });

  it("combines union + subtraction in one pass (defaults + collapse + expand)", () => {
    const spec = buildSha256Spec();
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: ["compression"],
      flowDirection: "ltr",
      expandedGroups: ["round.5"],
    };
    const effective = getEffectiveCollapsedSet(spec, layout);
    // 65 defaults − 1 expanded + 1 explicit collapse = 65.
    expect(effective.size).toBe(65);
    expect(effective.has("compression")).toBe(true);
    expect(effective.has("msg-schedule")).toBe(true);
    expect(effective.has("round.5")).toBe(false);
    expect(effective.has("round.4")).toBe(true);
    expect(effective.has("round.6")).toBe(true);
  });

  it("returns a fresh Set each call (callers may mutate without aliasing)", () => {
    const spec = buildSha256Spec();
    const a = getEffectiveCollapsedSet(spec, null);
    const b = getEffectiveCollapsedSet(spec, null);
    expect(a).not.toBe(b);
  });
});
