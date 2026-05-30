// @vitest-environment jsdom

/**
 * GraphView replication force-on for port-native specs.
 *
 * SHA-256 (the first ported cipher; shipped via Slice 2.10c) decomposes
 * into 1829 leaves with multiple high-fanout sources (`K-to-aux` →
 * 64 round consumers, `W-publish` → 64 round consumers, `H-to-aux` →
 * final-add consumers). With replication OFF the canvas reads as a
 * dense thicket of crossing long arrows. With replication ON each
 * source splits into per-consumer chips that read as a sequence.
 *
 * The fix: force replication ON when `requiresPortedDispatch(spec)`
 * returns true AND the user hasn't manually toggled the checkbox in
 * this session. Once the user toggles, their explicit choice wins
 * across every spec until the next page reload.
 *
 * Smoke surfaced 2026-05-26; see [[project_universal_port_dataflow_proposal]].
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
// `setHash` exists in BOTH stores/cipher and stores/spec — the cipher
// one only flips the signal, the spec one rebuilds the canonical spec
// via `buildCanonicalHash` and flips category. We need the spec-store
// boundary so `useSpec()` returns the SHA-256 spec post-call.
// (Same gotcha as [[feedback_setcipher_test_import]] for `setCipher`.)
import { __resetSpecForTests, setCipher, setHash } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests, setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// Non-ported control carrier. AES single-block (B1.1–B1.3), Speck rounds (B2),
// and the Serpent round body (B3) are all byte-native now (ported → auto-on),
// so the "non-ported, default-off" assertions retarget to DES — still lifted
// (Feistel + legacy contract) until its universal-port Phase 4d rebuild.
// 8-byte key + 8-byte block (FIPS 46-3 Appendix B.1 worked example). DES's
// byte-native rebuild will re-break these two tests — retarget the control to
// whatever lifted cipher survives then (grep `desSpec` / `setCipher("des")`).
const DES_KEY = "133457799bbcdff1";
const DES_PT = "0123456789abcdef";

const seedDesTrace = (): void => {
  // `effectiveReplicate` reads the STORE spec (`useSpec()`), not the trace, so
  // the store spec must be the non-ported control too. The post-reset default
  // is byte-native AES-128 (ported → auto-on); flip the store to DES via the
  // spec-store boundary (rebuilds the canonical spec — [[feedback_setcipher_test_import]]).
  setCipher("des");
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(DES_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(DES_KEY)]]),
  });
  setTrace(trace);
};

const seedSha256Trace = (): void => {
  const spec = buildSha256Spec();
  const trace = runSpec(spec, buildDefaultRegistry(), {
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

const isReplicationCheckboxChecked = (container: HTMLElement): boolean => {
  // The replication checkbox is the only one labelled "replicate high-fanout sources".
  const labels = Array.from(container.querySelectorAll("label"));
  const replicationLabel = labels.find((l) =>
    (l.textContent ?? "").toLowerCase().includes("replicate"),
  );
  expect(replicationLabel, "replication toggle label").not.toBeUndefined();
  const checkbox = replicationLabel?.querySelector('input[type="checkbox"]') as HTMLInputElement;
  expect(checkbox, "replication toggle checkbox").not.toBeNull();
  return checkbox.checked;
};

describe("GraphView replication — force-on for port-native specs", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("non-ported spec (DES) keeps the default-off raw signal", () => {
    seedDesTrace();
    const { container } = render(() => <GraphView />);
    // Raw default false + no user toggle + DES is NOT ported →
    // effective replication stays off.
    expect(isReplicationCheckboxChecked(container)).toBe(false);
  });

  it("ported spec (SHA-256) auto-enables replication on first visit", () => {
    // Flip to the SHA-256 hash spec via the store boundary (mirrors
    // the production cipher-selector flow).
    setHash("sha-256");
    seedSha256Trace();
    const { container } = render(() => <GraphView />);
    // Raw signal is still false (untouched), but the spec is ported AND
    // the user hasn't toggled the checkbox → effective on.
    expect(isReplicationCheckboxChecked(container)).toBe(true);
  });

  it("explicit user toggle wins over the auto-on for ported specs", () => {
    setHash("sha-256");
    seedSha256Trace();
    // Simulate the user clicking the checkbox OFF before rendering.
    // `setReplicationEnabled(false)` marks `userToggledThisSession=true`,
    // so the auto-on no longer applies even on a ported spec.
    setReplicationEnabled(false);
    const { container } = render(() => <GraphView />);
    expect(isReplicationCheckboxChecked(container)).toBe(false);
  });

  it("user toggle on DES also wins when they later switch to SHA-256", () => {
    // User toggles ON while looking at DES (raw → true, userToggled → true).
    // DES (non-ported) makes the toggle genuinely the user's choice, not the
    // ported auto-on — preserving the test's discriminating power.
    seedDesTrace();
    setReplicationEnabled(true);
    // ... then switches to SHA-256. Effective should be raw = true (matches
    // their explicit choice, NOT forced-on by the ported branch — userToggled
    // short-circuits that branch).
    setHash("sha-256");
    seedSha256Trace();
    const { container } = render(() => <GraphView />);
    expect(isReplicationCheckboxChecked(container)).toBe(true);
  });
});
