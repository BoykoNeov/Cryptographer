// @vitest-environment jsdom

/**
 * GraphView — replication overrides panel: port-flow source eligibility.
 *
 * Slice S2(l) follow-up, 2026-05-26.
 *
 * Pins the fix for: SHA-256's port-native sources (e.g. `fetch-p2` with
 * 3 outgoing port-flow state edges to `sigma1-r17/r19/s10`) MUST appear
 * in the replication-overrides panel so the user can manually flip them
 * to `"always"` and decongest the canvas.
 *
 * The bug: pre-fix, the panel's `replicationSources` memo at
 * `GraphView.tsx:2993` filtered `e.kind !== "aux"` — never updated when
 * Slice S2(i) widened `replicateHighFanoutSources`'s eligibility to also
 * count `kind: "state"` edges with `auxKey === PORT_FLOW_AUX_KEY`. As a
 * result, every SHA-256 port-native source (which only emits port-flow
 * state edges, not aux edges) showed panel-fanout 0 and was hidden from
 * the panel — even though those same edges WERE eligible for the actual
 * replication transform.
 *
 * The fix: widen the panel's filter to match the replication predicate
 * exactly. Both now count `aux` OR (`state` + `auxKey: "port-flow"`).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests, toggleCollapse } from "@/ui/stores/layout";
import { __resetSpecForTests, setHash } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import {
  __resetReplicationForTests,
  setReplicationEnabled,
  setReplicationPanelOpen,
} from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SHA256_SPEC_ID = "sha-256@1";

const seedSha256Trace = (): void => {
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

describe("GraphView — replication panel port-flow source eligibility", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("SHA-256 with expanded msg-schedule: `fetch-p2` (3 port-flow edges) appears in the replication-overrides panel", () => {
    setHash("sha-256");
    seedSha256Trace();
    // msg-schedule is defaultCollapsed:true — force expand so fetch-p2
    // and its 3 outgoing port-flow edges are part of the collapsedGraph
    // the panel reads from.
    // 3rd arg `inDefaults: true` because msg-schedule has `defaultCollapsed: true`
    // — the call adds it to `expandedGroups` (explicit user override).
    toggleCollapse(SHA256_SPEC_ID, "msg-schedule", true);
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    setReplicationPanelOpen(true);
    // fetch-p2 wires three downstream consumers (sigma1-r17/r19/s10) via
    // portInputs; those become `kind: "state", auxKey: "port-flow"`
    // edges in the graph. After the fix, fetch-p2 has effective fanout
    // = 3 in the panel's eligibility predicate and surfaces as a row.
    const row = container.querySelector('[data-testid="replication-row-fetch-p2"]');
    expect(row).not.toBeNull();
    // The row's fanout label should read "3 edges".
    expect(row?.textContent ?? "").toContain("3");
  });

  it("SHA-256 with expanded msg-schedule: `length-append` (4 history-seed aux edges) appears in the panel with fanout 4", () => {
    setHash("sha-256");
    seedSha256Trace();
    // 3rd arg `inDefaults: true` because msg-schedule has `defaultCollapsed: true`
    // — the call adds it to `expandedGroups` (explicit user override).
    toggleCollapse(SHA256_SPEC_ID, "msg-schedule", true);
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    setReplicationPanelOpen(true);
    // Sanity: the Slice S2(l) path (aux edges) still works under the
    // widened predicate — the widening is additive, not replacement.
    // Post scaffolding-suppression A3a the history-seed source is
    // `length-append` (the FES `seedInput.node`), not the retired
    // `seed-schedule` bridge.
    const row = container.querySelector('[data-testid="replication-row-length-append"]');
    expect(row).not.toBeNull();
    expect(row?.textContent ?? "").toContain("4");
  });
});
