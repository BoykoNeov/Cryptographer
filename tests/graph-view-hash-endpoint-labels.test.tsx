// @vitest-environment jsdom

/**
 * GraphView endpoint pills — hash branch.
 *
 * The `endpointLabels` memo at `GraphView.tsx` historically hardcoded
 * "plaintext" / "ciphertext" (with the decrypt label swap on top).
 * When SHA-256 shipped via Slice 2.10c the linear-mode `inputLabel()` /
 * `outputLabel()` in `App.tsx` learned a hash branch — but the graph
 * pills did NOT, so a SHA-256 run rendered as "plaintext → ciphertext"
 * which is a category lie. Smoke surfaced 2026-05-26.
 *
 * This pins the post-fix labels for both the encrypt-cipher branch
 * (AES-128 → "plaintext" / "ciphertext") and the hash branch (SHA-256
 * → "message" / "digest"). The decrypt swap is already covered by the
 * existing `tests/graph-view.test.tsx`.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
// `setHash` from stores/spec rebuilds the canonical spec; the cipher
// one only flips the signal (see [[feedback_setcipher_test_import]]).
import { __resetSpecForTests, setHash } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

const seedSha256Trace = (): void => {
  // `setHash("sha-256")` rebuilds the spec store with the canonical
  // SHA-256 spec; we build a fresh copy here for the trace so both
  // sides use byte-equivalent shapes. Trace plaintext is the
  // FIPS 180-4 §A.1 "abc" vector.
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

const endpointLabelTexts = (container: HTMLElement): string[] => {
  // `EndpointPill` renders an SVG `<text class="graph-endpoint-label">`.
  return Array.from(container.querySelectorAll(".graph-endpoint-label")).map(
    (el) => el.textContent ?? "",
  );
};

describe("GraphView endpoint pills — hash vs cipher labels", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("AES-128 encrypt renders 'plaintext' / 'ciphertext' on the endpoint pills", () => {
    seedAes128Trace();
    const { container } = render(() => <GraphView />);
    const labels = endpointLabelTexts(container);
    expect(labels).toContain("plaintext");
    expect(labels).toContain("ciphertext");
    expect(labels).not.toContain("message");
    expect(labels).not.toContain("digest");
  });

  it("SHA-256 renders 'message' / 'digest' on the endpoint pills (NOT plaintext/ciphertext)", () => {
    setHash("sha-256");
    seedSha256Trace();
    const { container } = render(() => <GraphView />);
    const labels = endpointLabelTexts(container);
    expect(labels).toContain("message");
    expect(labels).toContain("digest");
    // Category lie regression-pin: a hash spec must NEVER surface
    // cipher nomenclature on its endpoint pills.
    expect(labels).not.toContain("plaintext");
    expect(labels).not.toContain("ciphertext");
  });
});
