/**
 * Document round-trip for a DROPPED composite (universal-port Phase 4f, Slice E
 * follow-up). The analogue of `port-wiring-roundtrip.test.ts` for compose-and-
 * save.
 *
 * The plan + CHANGELOG claim a dropped composite is **self-contained** (the
 * saved/shared `.cipher.json` carries the inlined nodes, never a reference to
 * the composites library) and needs **no `schemaVersion` bump**. The Playwright
 * smoke pins the *library*'s localStorage persistence across reload — a
 * different round-trip from "a spec CONTAINING a dropped composite survives
 * serialize→parse." This file backs that named claim directly: a dropped
 * composite is an ordinary `group` + `portInputs`/`seedInput`/`bodyOutput`/
 * `defaultCollapsed`, all already in the document schema, so it must round-trip
 * byte-identically with the version unchanged.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import {
  CURRENT_SCHEMA_VERSION,
  type CipherDocument,
  parseDocument,
  serializeDocument,
} from "@/core/document";
import {
  captureCompositeFromGroup,
  cloneGroupWithFreshIds,
  collectSpecIds,
  findStepAndParent,
  insertStepAfter,
} from "@/core/spec-mutations";
import type { CipherSpec, StepGroup } from "@/core/types";
import { describe, expect, it } from "vitest";

const docFor = (spec: CipherSpec): CipherDocument => ({
  schemaVersion: CURRENT_SCHEMA_VERSION,
  spec,
});

const roundTrip = (spec: CipherSpec): CipherSpec => {
  const result = parseDocument(serializeDocument(docFor(spec)));
  if (!result.ok) throw new Error(`parse failed: ${result.error}`);
  return result.doc.spec;
};

/** A spec with a captured+cloned round.1 inlined after initial.add-round-key,
 *  seeded like a real drop would (auto-bound to the predecessor). */
const specWithDroppedComposite = (): CipherSpec => {
  const template = captureCompositeFromGroup(aes128Spec, "round.1", "AES Round");
  const { group } = cloneGroupWithFreshIds(template, "aes-round", collectSpecIds(aes128Spec));
  const seeded: StepGroup = {
    ...group,
    seedInput: { node: "initial.add-round-key", port: "output" },
  };
  return insertStepAfter(aes128Spec, "initial.add-round-key", seeded);
};

describe("dropped composite — document round-trip", () => {
  it("survives Save → Load byte-identically (self-contained, no library reference)", () => {
    const withComposite = specWithDroppedComposite();
    const loaded = roundTrip(withComposite);

    const before = findStepAndParent(withComposite, "aes-round")?.node;
    const after = findStepAndParent(loaded, "aes-round")?.node;
    expect(before, "the dropped composite group should exist pre-save").toBeDefined();
    // Deep-equal: fresh id, defaultCollapsed, seedInput, bodyOutput, and every
    // child's rebased portInputs all come back unchanged.
    expect(after).toEqual(before);
  });

  it("does not bump the schema version", () => {
    const serialized = serializeDocument(docFor(specWithDroppedComposite()));
    expect(JSON.parse(serialized).schemaVersion).toBe(CURRENT_SCHEMA_VERSION);
  });

  it("serialization is a fixed point through parse (byte-stable saves)", () => {
    const withComposite = specWithDroppedComposite();
    const once = serializeDocument(docFor(withComposite));
    const twice = serializeDocument(docFor(roundTrip(withComposite)));
    expect(twice).toBe(once);
  });
});
