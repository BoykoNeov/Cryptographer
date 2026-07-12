// @vitest-environment jsdom

/**
 * Cases C + D of the "arrival dots on every arrow" work (2026-07-12): an arrow
 * whose target ISN'T a plain editable leaf still gets a colored terminus dot.
 *
 * - **Case C — replica chips.** A fanout-replicated node that has its OWN inputs
 *   (RSA `phi`, fed by `p-1`/`q-1`) receives arrows on the ONE replica that
 *   inherits its incoming edges. Replicas carry no interactive wiring handles, so
 *   they render a plain, non-interactive `.graph-arrival-dot` where each arrow
 *   lands. The pure-OUTPUT replicas (the other `phi@->eea-N`) receive nothing and
 *   stay dotless. This includes AUX-FED loaders (`load-n`/`load-exp`, fed by the
 *   Key-Generation aux publish): their single incoming aux edge redirects to the
 *   spine-entry replica, which must resolve its `input` port via the replica's
 *   `replicaOf` params (the 2026-07-12 fix — a replica id isn't in the spec, so
 *   the old `findStep(spec, id)` reverse-map lookup returned null and no dot drew).
 *
 * - **Case D — collapsed containers.** A folded group / iterate receives arrows
 *   (SHA-256's per-round `W` aux, the `blocks → round.0` seed) on its box; each
 *   gets a non-interactive `.graph-arrival-dot` where the arrow lands. Scoped to
 *   COLLAPSED containers so an expanded wrapper isn't peppered with edge dots.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { buildRsaSpec } from "@/ciphers/rsa";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { bigIntToBytes } from "@/core/big-int-codec";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests, toggleCollapse } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setAsymmetric, setCipher, setHash } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const RSA_SPEC = buildRsaSpec("encrypt", 2);

const seedRsaReplicated = (): void => {
  setAsymmetric("rsa");
  const trace = runSpec(RSA_SPEC, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: bigIntToBytes(65n, 2) },
  });
  setTrace(trace);
  // Replicas only exist with replication ON, and jsdom defaults it OFF
  // (`feedback_jsdom_replication_off_default`).
  setReplicationEnabled(true);
};

const seedSha256 = (): void => {
  setHash("sha-256"); // rounds render DEFAULT-COLLAPSED
  const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex("616263")), // "abc"
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetReplicationForTests();
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
  __resetLayoutsForTests();
};

describe("GraphView — arrival dots on replicas (case C)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("draws arrival dots on the phi replica that inherits phi's inputs, and none on the pure-output replicas", () => {
    seedRsaReplicated();
    const { container } = render(() => <GraphView />);
    // Key Generation is default-collapsed; expand it so the `phi` replicas render
    // (inDefaults=true → the expand override for a default-collapsed group).
    toggleCollapse(RSA_SPEC.id, "key-generation", true);

    // `phi@->eea-0` is the replica that inherited phi's incoming p-1 / q-1 edges
    // (a + b) → two arrival dots.
    const primary = container.querySelector('[data-testid="graph-leaf-phi@->eea-0"]');
    expect(primary).not.toBeNull();
    expect(primary?.querySelectorAll(".graph-arrival-dot").length).toBe(2);

    // A pure-output phi replica (feeds an eea rung's modulus, no incoming edge of
    // its own) shows no arrival dot.
    const pureOutput = container.querySelector('[data-testid="graph-leaf-phi@->eea-5"]');
    expect(pureOutput).not.toBeNull();
    expect(pureOutput?.querySelectorAll(".graph-arrival-dot").length).toBe(0);
  });

  it("draws an arrival dot on the aux-fed loader replica that inherits the Key-Generation aux edge", () => {
    // The 2026-07-12 replica-param fix. `load-n` is a top-level `aux-load-bytes`
    // (reads aux[rsa.n] onto its `input` port) that fans out to every ladder rung,
    // so it FULLY replicates. Its single incoming aux edge (from the collapsed
    // Key-Generation group's publish) redirects to the spine-entry replica
    // `load-n@->square-0`, which must resolve `rsa.n → input` via the replica's
    // source params and land a dot. The loaders sit at TOP LEVEL, so no expand.
    seedRsaReplicated();
    const { container } = render(() => <GraphView />);

    const spineEntry = container.querySelector('[data-testid="graph-leaf-load-n@->square-0"]');
    expect(spineEntry).not.toBeNull();
    expect(spineEntry?.querySelectorAll(".graph-arrival-dot").length).toBe(1);

    // A pure-output loader replica (spawned copy, no incoming aux edge of its own)
    // stays dotless — the arrow lands once, on the spine-entry replica only.
    const pureCopy = container.querySelector('[data-testid="graph-leaf-load-n@->mult-0"]');
    expect(pureCopy).not.toBeNull();
    expect(pureCopy?.querySelectorAll(".graph-arrival-dot").length).toBe(0);
  });
});

describe("GraphView — arrival dots on collapsed containers (case D)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("draws a terminus dot per incoming arrow on each folded SHA-256 round", () => {
    seedSha256();
    const { container } = render(() => <GraphView />);
    // SHA-256's 64 rounds render collapsed by default; each folds an incoming `W`
    // aux + the running-hash spine carry, so ~2 dots per round. Assert a
    // substantial population rather than an exact count (block-count / padding
    // tweaks shift the total) — the point is "folded rounds get their dots".
    const dots = container.querySelectorAll(".graph-arrival-dot");
    expect(dots.length).toBeGreaterThan(60);
  });

  it("adds NO `.graph-arrival-dot` when nothing is collapsed and there are no replicas (DES)", () => {
    // Cross-check the dots are SPECIFIC to the collapsed-container (D) + replica
    // (C) cases, not sprayed on every arrow: DES renders its rounds EXPANDED by
    // default, and with replication OFF there are no replica chips either — so
    // `.graph-arrival-dot` is empty. (DES's Feistel swap uses the separate
    // `.graph-feistel-swap-dot` class, so it doesn't count here.)
    setCipher("des");
    const trace = runSpec(desSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("0123456789abcdef")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
    });
    setTrace(trace);
    setReplicationEnabled(false);
    const { container } = render(() => <GraphView />);
    expect(container.querySelectorAll(".graph-arrival-dot").length).toBe(0);
  });
});
