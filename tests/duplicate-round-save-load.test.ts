/**
 * Phase 6 of docs/plans/duplicate-round.md — end-to-end save/load
 * round-trip for a spec that's been mutated by the duplicate-round
 * feature.
 *
 * The properties under test:
 *
 *   1. **Schema acceptance.** A duplicated spec containing
 *      `aes.key-expansion@2` (the morphed type) and an extra round group
 *      validates cleanly against `CipherDocumentSchema`. The step-type
 *      string is `z.string()` in the schema, so this is a structural
 *      check rather than an enum check — but pinning it here catches a
 *      future tighten-up that would silently break duplicate-round.
 *
 *   2. **Run-correctness survives load.** Serialize a duplicated
 *      encrypt spec, parse it back, run the parsed spec on FIPS-197
 *      §A.1's (plaintext, key). Then load the matching duplicated
 *      decrypt spec, run it on the encrypt's ciphertext. The recovered
 *      plaintext equals the original. This is the strongest
 *      correctness signal — confirms the serialized form carries
 *      enough fidelity to reproduce the cipher pair exactly.
 *
 *   3. **Byte-stability.** `serializeDocument` produces byte-identical
 *      output for two `deep-equal` documents. Confirms the
 *      `sortKeysDeep` discipline applies to duplicate-mutated specs
 *      too (no key ordering quirk introduced by the mutator).
 *
 *   4. **Layout-pin migration survives the round-trip.** A pin set
 *      AFTER a duplicate (so the pin points at a renumbered id like
 *      `round.6`) lands at the same id in a re-serialized document
 *      and decodes back cleanly.
 *
 * The end-to-end UI flow (clicking [save], picking a file, clicking
 * [load]) is covered in `tests/file-save-load.test.tsx`. This file
 * exercises the document-layer property directly so a future failure
 * narrows to "parse/serialize broke" rather than "UI plumbing broke."
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { requiresPortedDispatch } from "@/core/dispatch";
import {
  CURRENT_SCHEMA_VERSION,
  type CipherDocument,
  parseDocument,
  serializeDocument,
} from "@/core/document";
import { runSpec } from "@/core/runtime";
import { duplicateRoundGroup, findStep } from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

const PLAINTEXT_HEX = "00112233445566778899aabbccddeeff";
const KEY_HEX = "000102030405060708090a0b0c0d0e0f";

const docFromSpec = (spec: CipherSpec): CipherDocument => ({
  schemaVersion: CURRENT_SCHEMA_VERSION,
  spec,
});

const countRoundGroups = (spec: CipherSpec, prefix: "round" | "inv-round"): number => {
  let count = 0;
  const visit = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "group" && n.id.startsWith(`${prefix}.`)) count++;
      if (n.kind === "step" || n.kind === "feistel-round") continue;
      visit(n.children);
    }
  };
  visit(spec.steps);
  return count;
};

// ─── 1. Schema acceptance ────────────────────────────────────────────────

describe("duplicate-round save/load — schema acceptance", () => {
  it("a duplicated AES-128 encrypt spec passes CipherDocumentSchema validation", () => {
    const { spec: duplicated } = duplicateRoundGroup(aes128Spec, "round.2", "forward");
    const doc = docFromSpec(duplicated);
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error);
    // Sanity: key-expansion morphed to @2 and the round count grew.
    const keyExp = findStep(result.doc.spec, "key-expansion");
    expect(keyExp?.type).toBe("aes.key-expansion@2");
    expect(countRoundGroups(result.doc.spec, "round")).toBe(11);
  });

  it("a duplicated AES-128 decrypt spec passes validation too", () => {
    const { spec: duplicated } = duplicateRoundGroup(aes128DecryptSpec, "inv-round.2", "reverse");
    const doc = docFromSpec(duplicated);
    const result = parseDocument(serializeDocument(doc));
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error);
    expect(countRoundGroups(result.doc.spec, "inv-round")).toBe(11);
  });
});

// ─── 2. Run-correctness survives load ────────────────────────────────────

describe("duplicate-round save/load — run-correctness survives round-trip", () => {
  it("encrypt (loaded) + decrypt (loaded) recover the original plaintext", () => {
    const { spec: encryptDup } = duplicateRoundGroup(aes128Spec, "round.2", "forward");
    const { spec: decryptDup } = duplicateRoundGroup(aes128DecryptSpec, "inv-round.2", "reverse");

    // Serialize then parse — the strongest "did anything subtly break"
    // signal because both the schema AND the runtime have to accept the
    // serialized form.
    const encryptParse = parseDocument(serializeDocument(docFromSpec(encryptDup)));
    const decryptParse = parseDocument(serializeDocument(docFromSpec(decryptDup)));
    expect(encryptParse.ok).toBe(true);
    expect(decryptParse.ok).toBe(true);
    if (!encryptParse.ok || !decryptParse.ok) throw new Error("schema failed");

    const registry = buildDefaultRegistry();

    // Byte-native encrypt (Slice B1): flat BytesState + ported dispatch.
    // Confirms serialize/parse preserved portInputs/seedInput/outputFrom
    // faithfully — a dropped binding would surface as a runtime throw here.
    const encryptTrace = runSpec(encryptParse.doc.spec, registry, {
      initialState: makeBytesState(bytesFromHex(PLAINTEXT_HEX)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_HEX)]]),
      portedDispatchEnabled: requiresPortedDispatch(encryptParse.doc.spec, registry),
    });
    if (encryptTrace.finalState.shape !== "bytes") throw new Error("bytes expected");
    const ciphertext = encryptTrace.finalState.bytes;

    const decryptTrace = runSpec(decryptParse.doc.spec, registry, {
      initialState: matrixFromBytes(ciphertext),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY_HEX)]]),
    });
    if (decryptTrace.finalState.shape !== "matrix4x4-bytes") throw new Error("matrix expected");
    expect(hexFromBytes(decryptTrace.finalState.bytes)).toBe(PLAINTEXT_HEX);
  });
});

// ─── 3. Byte-stability ───────────────────────────────────────────────────

describe("duplicate-round save/load — byte-stable serialization", () => {
  it("serializing the same duplicated spec twice produces byte-identical output", () => {
    const { spec: duplicated } = duplicateRoundGroup(aes128Spec, "round.2", "forward");
    const doc = docFromSpec(duplicated);
    const first = serializeDocument(doc);
    const second = serializeDocument(doc);
    expect(first).toBe(second);
  });

  it("a round-trip through parse + serialize is byte-stable", () => {
    // serialize → parse → serialize should be a fixed point.
    const { spec: duplicated } = duplicateRoundGroup(aes128Spec, "round.2", "forward");
    const original = serializeDocument(docFromSpec(duplicated));
    const result = parseDocument(original);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error);
    const reSerialized = serializeDocument(result.doc);
    expect(reSerialized).toBe(original);
  });
});

// ─── 4. Layout-pin migration through round-trip ──────────────────────────

describe("duplicate-round save/load — layout pins survive serialization", () => {
  it("a pin on round.6 (a renumbered round) serializes + parses back at the same id", () => {
    const { spec: duplicated } = duplicateRoundGroup(aes128Spec, "round.2", "forward");
    // Simulate the user pinning round.6 AFTER the duplicate.
    const doc: CipherDocument = {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      spec: duplicated,
      layout: {
        positions: { "round.6": { x: 200, y: 100 } },
        collapsedGroups: ["round.7"],
        flowDirection: "ltr",
      },
    };
    const result = parseDocument(serializeDocument(doc));
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(result.error);
    expect(result.doc.layout?.positions["round.6"]).toEqual({ x: 200, y: 100 });
    expect(result.doc.layout?.collapsedGroups).toEqual(["round.7"]);
  });
});
