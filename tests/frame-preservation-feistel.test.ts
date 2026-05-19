/**
 * Phase 2 of the DES + branching primitive plan (`docs/plans/des-feistel.md`).
 *
 * Pins the frame-preservation contract for Feistel-emitted frame stepIds:
 * `setTrace` resolves the scrubber by CANONICAL stepId (the spec leaf id),
 * stripping `:b{i}` / `:t{name}` / `:rejoin` / `:swap` suffixes. The
 * `:t{name}` suffix introduced in Phase 2 must thread through the trace
 * store the same way the existing `:b{i}` does — otherwise a user
 * scrubbed to "round.1.add-k" on the R track would land elsewhere after
 * a re-run.
 *
 * Per `[[feedback-frame-preservation]]` (memory): the scrubber's anchor
 * is the canonical stepId, NOT the raw frame stepId. The test exercises
 * that round-trip for Feistel-emitted suffixes.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { FEISTEL_TOY_KAT, FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { runSpec } from "@/core/runtime";
import { canonicalStepId } from "@/core/step-id";
import { describe, expect, it } from "vitest";

describe("step-id canonicalization (Feistel suffixes)", () => {
  it("strips :t{name} suffix", () => {
    expect(canonicalStepId("round.1.add-k:tR")).toBe("round.1.add-k");
    expect(canonicalStepId("foo:tL")).toBe("foo");
  });

  it("strips :rejoin suffix", () => {
    expect(canonicalStepId("round.1:rejoin")).toBe("round.1");
    expect(canonicalStepId("round.2:rejoin")).toBe("round.2");
  });

  it("strips combined :tX:bN suffixes (Feistel inside iterate)", () => {
    // A leaf inside a Feistel track inside an iterate emits both suffixes,
    // innermost-first: `{stepId}:t{name}:b{i}`. canonicalStepId must
    // recover the spec leaf id from either.
    expect(canonicalStepId("round.1.add-k:tR:b3")).toBe("round.1.add-k");
    expect(canonicalStepId("round.1:rejoin:b7")).toBe("round.1");
  });

  it("leaves a bare spec id alone", () => {
    expect(canonicalStepId("key-expansion")).toBe("key-expansion");
    expect(canonicalStepId("round.1.add-k")).toBe("round.1.add-k");
  });

  it("Feistel toy frames' canonical stepIds resolve to existing spec leaves", () => {
    // Every emitted frame should canonicalize to either a leaf id in the
    // spec OR a feistel-round container id (for rejoin frames). This is
    // the property setTrace's findIndex relies on.
    const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(FEISTEL_TOY_KAT.plaintext) },
    });
    const validIds = new Set(["round.1", "round.1.add-k", "round.2", "round.2.add-k"]);
    for (const f of trace.frames) {
      const canonical = canonicalStepId(f.stepId);
      expect(validIds.has(canonical)).toBe(true);
    }
  });
});
