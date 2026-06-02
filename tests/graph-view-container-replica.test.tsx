// @vitest-environment jsdom

/**
 * GraphView — collapsed-GROUP container replication (2026-06-02).
 *
 * Regression guard for the LAYOUT / RENDER path of container-sourced
 * replicas — NOT just the graph-data transform (`tests/replicate-fanout.ts`
 * already pins that a collapsed group produces replica NODES). A collapsed
 * `group` source flows through `buildReplicaPlacement`, a positioning path
 * originally written for LEAF sources: a container replica can be created
 * perfectly in data yet land unplaced / overlapping in layout with every
 * data test still green (the `feedback_visual_smoke_vs_property_tests`
 * trap). So we render the real scenario and assert the chips actually paint.
 *
 * LeafRect renders only inside `<Show when={box()}>`, so a PRESENT replica
 * testid proves the layout pass assigned it a box — i.e. it's placed, not
 * dropped. We also assert the orphaned original container box is gone and
 * that no round-key fan-out line still emits from the bare container id.
 *
 * Scenario: single-block AES-128 — 11 DISTINCT AddRoundKey consumers, so the
 * distinct-consumer AUTO path fires (no override needed) — with the
 * default-collapsed `key-schedule` group. With replication ON, the collapsed
 * group replicates one "Key Expansion" chip next to each AddRoundKey.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests, setCipher } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetSpecForTests, setCipherMode } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { __resetValueInspectorForTests } from "@/ui/stores/view-value-inspector";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const KEY = "000102030405060708090a0b0c0d0e0f";
const PT = "00112233445566778899aabbccddeeff";

const seed = (): void => {
  setCipher("aes-128");
  setCipherMode("single-block");
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]),
  });
  setTrace(trace);
  // `key-schedule` is default-collapsed, so it is already a single chip-like
  // container source of all 11 roundKey aux edges. Just turn the master
  // replication switch ON (jsdom defaults it OFF — see
  // `feedback_jsdom_replication_off_default`).
  setReplicationEnabled(true);
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetReplicationForTests();
  __resetLayoutsForTests();
  __resetValueInspectorForTests();
};

describe("GraphView — collapsed-group container replication", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("places a replica chip per AddRoundKey consumer and drops the orphan container box", () => {
    seed();
    const { container } = render(() => <GraphView />);

    // Replica leaf testids: `graph-leaf-${source}@->${consumer}`. Present ==
    // placed (LeafRect is gated on a resolved layout box). 11 AddRoundKey
    // consumers: initial.add-round-key + round.1..10.add-round-key.
    const replicaLeaves = Array.from(
      container.querySelectorAll<SVGGElement>('[data-testid^="graph-leaf-key-schedule@->"]'),
    );
    expect(replicaLeaves.length).toBe(11);

    // The orphaned original `key-schedule` CONTAINER box must be gone: the
    // removal filter drops it from `graph.containers`, so no header renders.
    const orphanHeader = container.querySelector(
      '[data-testid="graph-container-header-key-schedule"]',
    );
    expect(orphanHeader).toBeNull();
  });

  it("removes the long round-key fan-out lines from the bare container source", () => {
    seed();
    const { container } = render(() => <GraphView />);

    // Decongestion is the whole point: after replication NO edge (singleton
    // `${from}|${to}|${auxKey}|${kind}` or `bundle:${from}|...`) may still
    // emit from the bare `key-schedule` id — they all reroute through the
    // `key-schedule@->...` replicas (which start with `@`, not `|`, so the
    // prefix check below excludes them).
    const bareSourceEdges = Array.from(
      container.querySelectorAll<SVGPathElement>("path[data-edge-key]"),
    ).filter((p) => {
      const key = p.getAttribute("data-edge-key") ?? "";
      return key.startsWith("key-schedule|") || key.startsWith("bundle:key-schedule|");
    });
    expect(bareSourceEdges.length).toBe(0);
  });
});
