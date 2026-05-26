// @vitest-environment jsdom

/**
 * GraphView — SHA-256 preamble lift (port-native pure sources).
 *
 * Slice S2(d) of `docs/plans/sha-256-density-polish.md`. Before this
 * fix, the `auxOnlyRootIds` heuristic only lifted root leaves whose
 * `shapeContract.input === "any"`. Port-native primitives
 * (`constant-load@1`, `aux-load-bytes@1`) omit `shapeContract` entirely
 * — their surface is described by `PortContract` — so the heuristic
 * skipped them and they stayed pinned to the spine row alongside the
 * actual state writers/consumers. On SHA-256's preamble row this meant
 * `H-constant` (a pure 32-byte constant emitter) rendered next to
 * `init-working-vars` (a real state writer), and the lifted siblings
 * `K-to-aux` / `H-to-aux` / `W-publish` floated above with a visual
 * gap below them.
 *
 * Post-fix: any root step whose registration is `kind: "ported"` with
 * neither `meta.stateInputPort` nor `meta.stateOutputPort` also lifts.
 * That captures `constant-load@1` (no meta at all) and `aux-load-bytes@1`
 * (meta declares `auxReadPorts` only) while still excluding the genuine
 * state bridges — `bytes-to-state@1` has `meta.stateOutputPort` so
 * `init-working-vars` correctly stays on the spine.
 *
 * Coverage: this test pins the geometric assertion that after the fix
 * the SHA-256 preamble row collapses up cleanly — every lifted root
 * shares one y, and the spine row contains only steps that actually
 * read or write state.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests, setHash } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const seedSha256Trace = (): void => {
  // FIPS 180-4 §A.1 "abc" vector. Trace is the same shape the live
  // session would produce — `portedDispatchEnabled: true` because the
  // SHA-256 spec is fully port-native at root.
  const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    portedDispatchEnabled: true,
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetReplicationForTests();
  __resetLayoutsForTests();
};

/**
 * Read the SVG `y` attribute off a leaf's rendered `<rect>`. The leaf
 * `<g>` carries `data-testid="graph-leaf-${stepId}"` and its child
 * `<rect class="graph-leaf-rect">` carries the position attributes set
 * from the layout box.
 */
const leafY = (container: HTMLElement, stepId: string): number => {
  const g = container.querySelector(`[data-testid="graph-leaf-${stepId}"]`);
  if (!g) throw new Error(`no leaf rendered for stepId="${stepId}"`);
  const rect = g.querySelector("rect.graph-leaf-rect");
  if (!rect) throw new Error(`no .graph-leaf-rect inside leaf "${stepId}"`);
  const y = rect.getAttribute("y");
  if (y === null) throw new Error(`leaf "${stepId}" rect has no y attribute`);
  return Number(y);
};

describe("GraphView — SHA-256 preamble lifts port-native pure sources", () => {
  beforeEach(() => {
    resetAll();
    setHash("sha-256");
    seedSha256Trace();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("H-constant (constant-load@1) lifts to the same y as H-to-aux (existing legacy lift)", () => {
    const { container } = render(() => <GraphView />);
    // `H-to-aux` uses `generic.aux-load@1` (legacy, shapeContract.input
    // === "any") — was already lifted pre-fix and survives replication
    // because it has exactly one consumer (`final.fetch-H`), below the
    // default fanout threshold. It's the reference y for the lifted row.
    //
    // Note: `K-to-aux` and `W-publish` are not present as standalone
    // leaves in the rendered graph — both fan out to all 64 compression
    // rounds (fanout = 64), well past the default replication threshold
    // (6), so `replicateHighFanoutSources` removes the originals and
    // emits per-consumer chips (`K-to-aux@->round.0`, etc.) instead.
    // Their lift behavior is implied by the same code path.
    const hToAuxY = leafY(container, "H-to-aux");
    const hConstantY = leafY(container, "H-constant");
    // Both sit on the lifted row (CANVAS_MARGIN). The legacy lift
    // establishes the row; the new port-native lift must join it.
    expect(hConstantY).toBe(hToAuxY);
  });

  it("init-working-vars (bytes-to-state@1) STAYS on the spine row — it writes state", () => {
    const { container } = render(() => <GraphView />);
    // `bytes-to-state@1` declares `meta.stateOutputPort = "output"`, so
    // the widened heuristic must NOT lift it. A wrong lift here would
    // visually orphan the only step that turns H bytes into the
    // initial working variables — the spine would skip from
    // msg-schedule straight to round.0 with no visible transition.
    const initWorkingVarsY = leafY(container, "init-working-vars");
    const hToAuxY = leafY(container, "H-to-aux");
    // Spine row is strictly below the lifted row.
    expect(initWorkingVarsY).toBeGreaterThan(hToAuxY);
  });

  it("seed-schedule (bytes-to-state@1) STAYS on the spine row — pre-schedule state writer", () => {
    const { container } = render(() => <GraphView />);
    // Same `bytes-to-state@1` class as `init-working-vars`. Pins that
    // the widened heuristic doesn't accidentally lift either of the
    // two state-bridge leaves on the SHA-256 preamble row.
    const seedY = leafY(container, "seed-schedule");
    const hToAuxY = leafY(container, "H-to-aux");
    expect(seedY).toBeGreaterThan(hToAuxY);
  });
});
