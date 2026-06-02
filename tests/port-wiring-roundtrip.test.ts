/**
 * Document round-trip for port rewires (universal-port Phase 4d-bis, Slice G).
 *
 * The wiring editor mutates `StepLeaf.portInputs`, which is already part of the
 * `CipherDocument` schema — so no schema bump, but the round-trip needs a pin:
 * a rewire must survive Save → Load byte-identically, and CLEARING a port must
 * not leave a `portInputs: {}` husk that would break the "spec-only saves are
 * byte-stable" property the URL-share hash depends on (`setPortBinding`
 * normalizes an emptied map back to absent — this is its serialization-level
 * proof). The App's `applyDocument` installs exactly the spec `parseDocument`
 * returns, so the core round-trip below is the load-bearing assertion; the
 * App-level Save/reset/Load mechanism is already pinned by
 * `built-from-palette-roundtrip.test.tsx`.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import {
  CURRENT_SCHEMA_VERSION,
  type CipherDocument,
  parseDocument,
  serializeDocument,
} from "@/core/document";
import { findStep, setPortBinding } from "@/core/spec-mutations";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const docFor = (spec: CipherSpec): CipherDocument => ({
  schemaVersion: CURRENT_SCHEMA_VERSION,
  spec,
});

/** Serialize → parse → unwrap the spec, asserting the parse succeeded. */
const roundTrip = (spec: CipherSpec): CipherSpec => {
  const result = parseDocument(serializeDocument(docFor(spec)));
  if (!result.ok) throw new Error(`parse failed: ${result.error}`);
  return result.doc.spec;
};

describe("port rewire — document round-trip", () => {
  it("preserves a rewired input binding across Save → Load", () => {
    const rewired = setPortBinding(aes128Spec, "round.1.mix-columns", "input", {
      node: "round.1.sub-bytes",
      port: "output",
    });
    const loaded = roundTrip(rewired);
    expect(findStep(loaded, "round.1.mix-columns")?.portInputs?.input).toEqual({
      node: "round.1.sub-bytes",
      port: "output",
    });
  });

  it("clears a port to ABSENT (no `portInputs: {}` husk in the serialized form)", () => {
    // mix-columns only has the `input` port — clearing it empties the map.
    const cleared = setPortBinding(aes128Spec, "round.1.mix-columns", "input", null);
    const serialized = serializeDocument(docFor(cleared));

    // The cleared leaf round-trips with portInputs absent, not `{}`.
    const loaded = roundTrip(cleared);
    expect(findStep(loaded, "round.1.mix-columns")?.portInputs).toBeUndefined();
    // And the serialized text carries no empty-object husk.
    expect(serialized).not.toContain('"portInputs":{}');
  });

  it("serialization is a fixed point through parse (byte-stable saves)", () => {
    // Bind then clear returns mix-columns to no-portInputs; the resulting
    // spec must serialize identically before and after a parse round-trip.
    const bound = setPortBinding(aes128Spec, "round.1.mix-columns", "input", {
      node: "round.1.sub-bytes",
      port: "output",
    });
    const cleared = setPortBinding(bound, "round.1.mix-columns", "input", null);

    const once = serializeDocument(docFor(cleared));
    const twice = serializeDocument(docFor(roundTrip(cleared)));
    expect(twice).toBe(once);
  });
});
