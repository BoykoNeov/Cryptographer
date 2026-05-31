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
 * actual state writers/consumers.
 *
 * Post-fix: any root step whose registration is `kind: "ported"` with
 * neither `meta.stateInputPort` nor `meta.stateOutputPort` also lifts.
 * That captures `aux-load-bytes@1` (meta declares `auxReadPorts` only)
 * while still excluding the genuine state bridges and port-chain
 * consumers — `pad-with-byte@1` / `append-be64-length@1` declare
 * `portInputs`, so they stay on the spine row.
 *
 * Updated post scaffolding-suppression A1 (2026-05-28): the old lifted
 * preamble row had three standalone constant sources — `H-constant`
 * (constant-load@1), `K-to-aux` + `H-to-aux` (generic.aux-load@1). A1
 * retired all three (K/H now live on `spec.cipherConstants`, materialized
 * into aux by the runtime). The surviving standalone lifted source is
 * `init.fetch-H` (`aux-load-bytes@1`, reading the materialized aux["H"]
 * to seed the working variables). It's the lifted-row anchor here.
 *
 * Updated post scaffolding-suppression A3b (2026-05-28): A3b retired the
 * `init-working-vars` (`bytes-to-state@1`) state-seed bridge — round 0's
 * `seedInput` now reads `init.fetch-H` directly. SHA-256 no longer has any
 * `bytes-to-state@1` leaf, so the spine-row reference here is `pad`
 * (a port-chain consumer that stays on the spine).
 *
 * Coverage: this test pins the geometric assertion that the SHA-256
 * preamble lifts pure aux sources above the spine, and the spine row
 * contains only steps that actually read or write state.
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

  it("init.fetch-H (aux-load-bytes@1) lifts ABOVE the spine row — pure aux source", () => {
    const { container } = render(() => <GraphView />);
    // `init.fetch-H` uses `aux-load-bytes@1` (ported, meta declares
    // `auxReadPorts` only — no `stateInputPort`/`stateOutputPort`) and
    // has no `portInputs` (it reads the materialized aux["H"]). So the
    // widened S2(d) heuristic must lift it to the preamble row, strictly
    // above the spine. `pad` is a known spine leaf (a port-chain consumer)
    // used as the spine-row reference. (Was `init-working-vars` before
    // scaffolding-suppression A3b retired that bytes-to-state bridge.)
    const initFetchHY = leafY(container, "init.fetch-H");
    const spineY = leafY(container, "pad");
    expect(initFetchHY).toBeLessThan(spineY);
  });

  // (The pre-A3b `init-working-vars (bytes-to-state@1) STAYS on the spine
  // row` case was removed when A3b retired that bridge — SHA-256 no longer
  // has any bytes-to-state@1 leaf. The `pad` / `length-append` cases below
  // pin the port-chain-consumer-stays-on-spine property instead.)

  it("pad (pad-with-byte@1) STAYS on the spine row — port-chain consumer, not pure source", () => {
    const { container } = render(() => <GraphView />);
    // `pad-with-byte@1` is port-native with NO state-port meta —
    // candidate (a + b) of the port-native pure-source predicate
    // match. But the spec wires `portInputs: { input: port("$input",
    // "out") }` (scaffolding-suppression A3a — was `plaintext-source`),
    // so it's a port-chain consumer downstream of the `$input` source.
    // The non-empty-portInputs condition keeps it on the spine. Without
    // it the S2(d) original ship would have lifted `pad` alongside the
    // actual constant emitters, which is a layout regression.
    const padY = leafY(container, "pad");
    const initFetchHY = leafY(container, "init.fetch-H");
    expect(padY).toBeGreaterThan(initFetchHY);
  });

  it("length-append (append-be64-length@1) STAYS on the spine row — port-chain consumer", () => {
    const { container } = render(() => <GraphView />);
    // Same shape as `pad` — port-native, no state-port meta, but
    // declares `portInputs.data` + `portInputs.length-source`.
    const lengthAppendY = leafY(container, "length-append");
    const initFetchHY = leafY(container, "init.fetch-H");
    expect(lengthAppendY).toBeGreaterThan(initFetchHY);
  });
});
