// @vitest-environment jsdom

/**
 * Diagnostic-only measurement of altitude-staggering's actual visual
 * delta on SHA-256 `final.assemble` 8-fan-IN. Prints the 8 c1x values
 * and adjacent gaps so we can judge whether the spread is visually
 * meaningful or buried in fp noise.
 *
 * NOT a regression pin — the distinctness/monotonicity properties are
 * already pinned by `graph-view-altitude-staggering.test.tsx`. This
 * test exists solely to surface the numeric reality for triage on the
 * 2026-05-27 "is altitude staggering visible at all?" investigation.
 *
 * Delete after triage if it gets noisy.
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

describe("[diagnostic] altitude staggering — measure SHA-256 fan-IN spread", () => {
  beforeEach(() => {
    resetAll();
    setHash("sha-256");
    seedSha256Trace();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("prints c1x + sx + tx for the 8 final.assemble edges", () => {
    const { container } = render(() => <GraphView />);
    const rows: Array<{
      sIdx: number;
      sx: number;
      sy: number;
      c1x: number;
      c1y: number;
      tx: number;
      ty: number;
      pull: number;
      basePull: number;
      multiplier: number;
    }> = [];
    const allEdges = container.querySelectorAll<SVGPathElement>("path.graph-edge-hit");
    for (const edge of Array.from(allEdges)) {
      const key = edge.getAttribute("data-edge-key");
      if (key === null) continue;
      if (!key.includes("|final.assemble|")) continue;
      const fromPart = key.startsWith("bundle:")
        ? key.substring("bundle:".length).split("|")[0]
        : key.split("|")[0];
      if (fromPart === undefined) continue;
      const match = fromPart.match(/^final\.s(\d+)$/);
      if (match === null) continue;
      const idx = match[1];
      if (idx === undefined) continue;
      const sIdx = Number(idx);
      const d = edge.getAttribute("d");
      if (d === null) continue;
      const t = d.trim().split(/[\s,]+/);
      const sx = Number(t[1]);
      const sy = Number(t[2]);
      const c1x = Number(t[4]);
      const c1y = Number(t[5]);
      const tx = Number(t[8]);
      const ty = Number(t[9]);
      const pull = Math.abs(c1x - sx);
      const basePull = Math.max(20, Math.abs(tx - sx) / 2);
      const multiplier = pull / basePull;
      rows.push({ sIdx, sx, sy, c1x, c1y, tx, ty, pull, basePull, multiplier });
    }
    rows.sort((a, b) => a.sIdx - b.sIdx);
    // eslint-disable-next-line no-console
    console.log("\n=== SHA-256 final.assemble 8-fan-IN edge geometry ===");
    for (const r of rows) {
      // eslint-disable-next-line no-console
      console.log(
        `s_${r.sIdx}: sx=${r.sx.toFixed(1)} sy=${r.sy.toFixed(1)} | tx=${r.tx.toFixed(1)} ty=${r.ty.toFixed(1)} | basePull=${r.basePull.toFixed(1)} pull=${r.pull.toFixed(1)} mult=${r.multiplier.toFixed(3)}`,
      );
    }
    if (rows.length >= 2) {
      // eslint-disable-next-line no-console
      console.log("\n=== adjacent c1x deltas ===");
      for (let i = 0; i < rows.length - 1; i += 1) {
        const a = rows[i];
        const b = rows[i + 1];
        if (a !== undefined && b !== undefined) {
          // eslint-disable-next-line no-console
          console.log(`s_${a.sIdx} → s_${b.sIdx}: Δc1x = ${(b.c1x - a.c1x).toFixed(2)} px`);
        }
      }
      const minC1x = Math.min(...rows.map((r) => r.c1x));
      const maxC1x = Math.max(...rows.map((r) => r.c1x));
      // eslint-disable-next-line no-console
      console.log(`\ntotal c1x spread (slot 0 → slot 7): ${(maxC1x - minC1x).toFixed(2)} px`);
    }
    expect(rows.length).toBeGreaterThan(0);
  });
});
