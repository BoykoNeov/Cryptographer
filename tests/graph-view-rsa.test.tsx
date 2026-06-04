// @vitest-environment jsdom

/**
 * Graph-view render check for RSA (Phase 3 of
 * `docs/plans/shimmying-booping-moth.md`).
 *
 * The graph tab is one click away from the linear view, and RSA's topology is
 * novel for the graph machinery: no `round.N` groups at all, `$input` fans out
 * to every ladder rung's `factor` port, the computed modulus `n` fans out to
 * ~32 `modulus` ports (above the replication threshold), and `cond-mod-mul@1`
 * is a 4-input leaf. None of that is fundamentally new (SHA-256 has high aux
 * fanout; multi-input leaves exist), but "probably renders" on a visible tab
 * with no test is exactly the gap this closes: render the RSA trace through
 * `GraphView` and assert it produces the ladder without throwing.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildRsaSpec } from "@/ciphers/rsa";
import { bigIntToBytes } from "@/core/big-int-codec";
import { runSpec } from "@/core/runtime";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, setAsymmetric } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetCipherForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
  __resetReplicationForTests();
};

/** Point the spec store at RSA (encrypt) and seed a matching trace. */
const seedRsa = (): void => {
  setAsymmetric("rsa"); // store → kind:"asymmetric", encrypt slot = rsaEncryptSpec
  const trace = runSpec(buildRsaSpec("encrypt", 2), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: bigIntToBytes(65n, 2) },
  });
  setTrace(trace);
  // Deterministic leaf count: no fan-out replica chips.
  setReplicationEnabled(false);
};

describe("GraphView — RSA render", () => {
  beforeEach(() => resetAll());
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders the RSA spec without throwing and draws the key-gen + ladder leaves", () => {
    seedRsa();
    const { container } = render(() => <GraphView />);
    // Flat spec: 3 aux-load (p/q/e) + 2 constant-load (one/result-seed)
    // + 4 key-gen (n, p-1, q-1, phi) + mod-inverse (d) + 16 rungs × 2
    // (square + conditional multiply) = 42 leaves. Assert the exact count
    // (catches a silent topology regression) — replication is off above.
    const leafRects = container.querySelectorAll(".graph-leaf-rect");
    expect(leafRects.length).toBe(42);
  });

  it("renders no container rects (RSA is flat — no round groups)", () => {
    seedRsa();
    const { container } = render(() => <GraphView />);
    expect(container.querySelectorAll(".graph-container-rect").length).toBe(0);
  });

  it("labels the endpoint pills message → ciphertext for RSA encrypt", () => {
    seedRsa();
    const { container } = render(() => <GraphView />);
    const text = container.textContent ?? "";
    expect(text).toContain("message");
    expect(text).toContain("ciphertext");
  });
});
