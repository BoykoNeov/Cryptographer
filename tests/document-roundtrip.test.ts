/**
 * Tests for `src/core/document.ts` — the CipherDocument file format
 * (Slice 3 of the 2D editor plan).
 *
 * Coverage targets:
 *   - Round-trip every shipped cipher spec (14 total: AES-128/192/256
 *     × {encrypt, decrypt} = 6, AES-128-ECB × {encrypt, decrypt} = 2,
 *     Speck-32-64 × {BE, LE} × {encrypt, decrypt} = 4, Serpent-128/192/256
 *     × {encrypt, decrypt} = 6 — totals 18, but minimal docs are still
 *     ≤ 14 unique specs since Serpent is 3 sizes).
 *   - Reject schemaVersion 0 and ≥4 with the friendly pre-check error
 *     (not the raw Zod literal mismatch). Accept schemaVersion 1 + 2
 *     (via the v1 → v2 migration from Phase 4 of `docs/plans/des-feistel.md`
 *     chained with the v2 → v3 migration from Slice 2.10b of the
 *     universal-port plan) and schemaVersion 3 (the current literal).
 *   - Reject malformed JSON syntax.
 *   - Reject malformed structure (missing required fields, bad
 *     discriminator, unknown wrapper-layer key).
 *   - Optional fields really are optional: a minimal `{ schemaVersion: 3,
 *     spec }` round-trips.
 *   - Stable key order: serialize twice → byte-for-byte identical.
 *   - Enum coverage: every Cipher / CipherMode / PaddingScheme /
 *     ByteFormat literal can appear in a SessionSnapshot (the
 *     compile-time `Exclude` check pins the LOCAL `CIPHER_IDS` list, but
 *     this guards against the runtime Zod enum drifting from the TS
 *     value the schema accepts).
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128CbcDecryptSpec } from "@/ciphers/aes-128-cbc-decrypt";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes128EcbDecryptSpec } from "@/ciphers/aes-128-ecb-decrypt";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes192DecryptSpec } from "@/ciphers/aes-192-decrypt";
import { aes256Spec } from "@/ciphers/aes-256";
import { aes256DecryptSpec } from "@/ciphers/aes-256-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
import {
  CURRENT_SCHEMA_VERSION,
  type CipherDocument,
  parseDocument,
  serializeDocument,
} from "@/core/document";
import {
  BYTE_FORMATS,
  CIPHER_IDS,
  CIPHER_MODES,
  HASH_IDS,
  PADDING_SCHEMES,
} from "@/core/document-schema";
import { runSpec } from "@/core/runtime";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Shipped specs table ──────────────────────────────────────────────────

const SHIPPED_SPECS: ReadonlyArray<{ readonly name: string; readonly spec: CipherSpec }> = [
  { name: "aes-128 encrypt", spec: aes128Spec },
  { name: "aes-128 decrypt", spec: aes128DecryptSpec },
  { name: "aes-128 ECB encrypt", spec: aes128EcbSpec },
  { name: "aes-128 ECB decrypt", spec: aes128EcbDecryptSpec },
  // CBC (Slice B1.4b): byte-native port-mode iterate carrying the chain on
  // `chainInput`/`chainFeedback` PortBindings. The `toEqual` deep-equality
  // below is the loud regression gate for those fields — if a future change
  // drops them from `IterateGroupSchema`, Zod strips them on parse and the
  // round-trip mismatches. (ECB above covers seedInput/blockByteLength/
  // bodyOutput; only CBC sets the chain fields.)
  { name: "aes-128 CBC encrypt", spec: aes128CbcSpec },
  { name: "aes-128 CBC decrypt", spec: aes128CbcDecryptSpec },
  { name: "aes-192 encrypt", spec: aes192Spec },
  { name: "aes-192 decrypt", spec: aes192DecryptSpec },
  { name: "aes-256 encrypt", spec: aes256Spec },
  { name: "aes-256 decrypt", spec: aes256DecryptSpec },
  { name: "speck-32-64-BE encrypt", spec: speck32_64BeSpec },
  { name: "speck-32-64-BE decrypt", spec: speck32_64BeDecryptSpec },
  { name: "speck-32-64-LE encrypt", spec: speck32_64LeSpec },
  { name: "speck-32-64-LE decrypt", spec: speck32_64LeDecryptSpec },
  { name: "serpent-128 encrypt", spec: serpent128Spec },
  { name: "serpent-128 decrypt", spec: serpent128DecryptSpec },
  { name: "serpent-192 encrypt", spec: serpent192Spec },
  { name: "serpent-192 decrypt", spec: serpent192DecryptSpec },
  { name: "serpent-256 encrypt", spec: serpent256Spec },
  { name: "serpent-256 decrypt", spec: serpent256DecryptSpec },
  // (The feistel-toy round-trip fixture was retired in Phase 5 Slice 5.3e
  // with the `feistel-round` node kind. DES below exercises the
  // discriminated-union round-trip with port-native group nodes instead.)
  // Phase 3 of the DES + branching primitive plan — DES encrypt + decrypt
  // specs are registered in `defaults` but not yet in the cipher selector
  // (Phase 4). Adding them to the round-trip table pins schema-v1
  // compatibility for feistel-round-bearing documents BEFORE the user can
  // reach a Save through the UI. Schema bump to v2 lands in Phase 4 with
  // the selector wiring.
  { name: "des encrypt", spec: desSpec },
  { name: "des decrypt", spec: desDecryptSpec },
];

// ─── Round-trip every shipped spec ────────────────────────────────────────

describe("serializeDocument + parseDocument: minimal documents", () => {
  for (const { name, spec } of SHIPPED_SPECS) {
    it(`round-trips ${name} (schemaVersion + spec only)`, () => {
      const doc: CipherDocument = { schemaVersion: 3, spec };
      const text = serializeDocument(doc);
      const result = parseDocument(text);
      expect(result.ok).toBe(true);
      if (result.ok) {
        // Deep structural equality — the parsed document re-creates the
        // same shape we serialized. The spec is recursively compared.
        expect(result.doc).toEqual(doc);
      }
    });
  }
});

// ─── Documents with sidecars ──────────────────────────────────────────────

describe("serializeDocument + parseDocument: documents with sidecars", () => {
  it("round-trips a document with a LayoutSpec", () => {
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: aes128Spec,
      layout: {
        positions: {
          "key-expansion": { x: 0, y: 0 },
          "round.1.sub-bytes": { x: 100, y: 50 },
        },
        collapsedGroups: ["round.2", "round.3"],
        flowDirection: "ltr",
      },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });

  it("round-trips a document with replicationModes (commit 5)", () => {
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: aes128Spec,
      layout: {
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        replicationModes: {
          "key-expansion": "always",
          "split-blocks": "never",
        },
      },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });

  it("rejects an invalid replicationModes value", () => {
    // "auto" is the IMPLICIT default — absence of an entry is auto, so the
    // schema's closed enum doesn't include "auto" as a serialized value.
    // A doc that tries to persist "auto" explicitly is malformed.
    const malformed = JSON.stringify({
      schemaVersion: 3,
      spec: aes128Spec,
      layout: {
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        replicationModes: { "key-expansion": "auto" },
      },
    });
    const result = parseDocument(malformed);
    expect(result.ok).toBe(false);
  });

  it("round-trips a document with relativePositions (draggable replicas)", () => {
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: aes128Spec,
      layout: {
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        relativePositions: {
          "key-expansion@->round.1.add-round-key": { dx: 24, dy: -8 },
          "ecb-blocks@block3": { dx: 0, dy: 40 },
        },
      },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });

  it("round-trips a document with expandedGroups (default-collapse override)", () => {
    // Slice 2.6d follow-up (2026-05-25). `expandedGroups` records
    // explicit user-expansions of containers the spec marks
    // `defaultCollapsed: true`. Must round-trip losslessly so a Save +
    // Share preserves the user's "I expanded round.5 to look at it"
    // choice.
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: aes128Spec,
      layout: {
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        expandedGroups: ["round.5", "round.10"],
      },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });

  it("round-trips a spec whose container declares defaultCollapsed: true", () => {
    // Slice 2.6d follow-up (2026-05-25). SHA-256's 64 round groups
    // carry `defaultCollapsed: true`; the field must survive the
    // schema round-trip so a Save/Share of SHA-256 keeps the
    // affordance on the recipient's side. Authoring a minimal spec
    // here (rather than importing SHA-256) keeps the test independent
    // of any future SHA-256 spec churn.
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: {
        id: "test-default-collapsed@1",
        name: "Test default collapsed",
        stateShape: "bytes",
        inputs: {
          plaintext: { shape: "bytes" },
          key: { byteLength: 0 },
        },
        steps: [
          {
            kind: "group",
            id: "collapsed-by-default",
            label: "Collapsed by default",
            defaultCollapsed: true,
            children: [],
          },
        ],
      },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.doc).toEqual(doc);
      // Explicit assertion: the field survives, not just the wrapping
      // structure.
      const node = result.doc.spec.steps[0];
      if (node !== undefined && node.kind === "group") {
        expect(node.defaultCollapsed).toBe(true);
      }
    }
  });

  it("rejects a malformed relativePositions entry", () => {
    // Wrong shape — RelativePosition is `{ dx, dy }`, not `{ x, y }`.
    const malformed = JSON.stringify({
      schemaVersion: 3,
      spec: aes128Spec,
      layout: {
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        relativePositions: { "key-expansion@->round.1.add-round-key": { x: 24, y: -8 } },
      },
    });
    const result = parseDocument(malformed);
    expect(result.ok).toBe(false);
  });

  it("round-trips a document with a SessionSnapshot (no bytes)", () => {
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: aes128Spec,
      session: {
        mode: "encrypt",
        cipher: "aes-128",
        cipherMode: "single-block",
        padding: "none",
        byteFormat: "hex",
      },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });

  it("round-trips a document with a SessionSnapshot including bytes", () => {
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: aes128Spec,
      session: {
        mode: "decrypt",
        cipher: "aes-128",
        cipherMode: "ecb",
        padding: "pkcs7",
        byteFormat: "ascii",
        inputBytes: [0xff, 0x00, 0x42, 0x7f],
        keyBytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });

  it("round-trips a document with DocumentMetadata", () => {
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: aes128Spec,
      metadata: {
        name: "My custom AES-128",
        createdAt: 1715500000000,
        appVersion: "0.1.0",
      },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });

  it("round-trips a document with all sidecars present", () => {
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: aes128EcbSpec,
      layout: {
        positions: { "key-expansion": { x: 10, y: 20 } },
        collapsedGroups: [],
        flowDirection: "ltr",
      },
      session: {
        mode: "encrypt",
        cipher: "aes-128",
        cipherMode: "ecb",
        padding: "pkcs7",
        byteFormat: "hex",
      },
      metadata: { name: "full doc" },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });

  it("treats DocumentMetadata fields as optional", () => {
    // All three metadata fields are optional. An empty metadata object
    // must round-trip cleanly — it's the shape a minimal save dialog
    // produces when the user doesn't fill in name.
    const doc: CipherDocument = { schemaVersion: 3, spec: aes128Spec, metadata: {} };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });
});

// ─── schemaVersion handling ───────────────────────────────────────────────

describe("parseDocument: schemaVersion handling", () => {
  it("accepts the current schemaVersion (3 after Slice 2.10b of universal-port-dataflow.md)", () => {
    expect(CURRENT_SCHEMA_VERSION).toBe(3);
    const result = parseDocument(JSON.stringify({ schemaVersion: 3, spec: aes128Spec }));
    expect(result.ok).toBe(true);
  });

  it("accepts legacy schemaVersion 1 via the v1 → v2 → v3 migration chain", () => {
    // Backwards-compat for documents saved before Phase 4 of
    // `docs/plans/des-feistel.md` bumped the schema. v1 documents
    // cannot contain `feistel-round` nodes (DES wasn't selectable)
    // and predate the cipher-hint field, so the chained migration
    // is a pure version-field bump (v1 → v2) followed by a no-op
    // (no `cipher` field to rename in v2 → v3).
    const result = parseDocument(JSON.stringify({ schemaVersion: 1, spec: aes128Spec }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      // Post-migration, the loaded document carries the current
      // version literal — the rest of the app reasons in current-
      // version terms regardless of file origin.
      expect(result.doc.schemaVersion).toBe(3);
    }
  });

  it("accepts legacy schemaVersion 2 via the v2 → v3 migration (cipher → algorithm rename)", () => {
    // Slice 2.10b of `docs/plans/universal-port-dataflow.md` renamed
    // the cipher-hint field at the document root. v2 documents carry
    // `cipher: <Cipher>`; the migration renames it to
    // `algorithm: <Cipher>` (the value passes through unchanged since
    // every v2 cipher value is also a valid Algorithm).
    const result = parseDocument(
      JSON.stringify({ schemaVersion: 2, spec: aes128Spec, cipher: "des" }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.doc.schemaVersion).toBe(3);
      // The legacy field is gone; the value is now at `algorithm`.
      expect(result.doc.algorithm).toBe("des");
      // Sanity: the strict-validating schema rejected anything in the
      // `cipher` field post-migration, so it's removed from the parsed
      // shape. (TS-level: `cipher` isn't on the v3 CipherDocument type.)
      expect((result.doc as { cipher?: unknown }).cipher).toBeUndefined();
    }
  });

  it("v2 document without a cipher field migrates to v3 cleanly (no algorithm field)", () => {
    // Pre-Phase-6e v2 docs (no cipher field at all) walk the migration
    // path and emerge as v3 with no algorithm field. The optional field
    // staying absent is the correct behavior — there's no value to fabricate.
    const result = parseDocument(JSON.stringify({ schemaVersion: 2, spec: aes128Spec }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.doc.schemaVersion).toBe(3);
      expect(result.doc.algorithm).toBeUndefined();
    }
  });

  it("rejects schemaVersion === 0 with a friendly forward/back-compat error", () => {
    const result = parseDocument(JSON.stringify({ schemaVersion: 0, spec: aes128Spec }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("schemaVersion 0 is not supported");
    }
  });

  it("rejects schemaVersion === 4 (forward-compat: future versions error friendly)", () => {
    const result = parseDocument(JSON.stringify({ schemaVersion: 4, spec: aes128Spec }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("schemaVersion 4 is not supported");
    }
  });
});

// ─── Error cases ──────────────────────────────────────────────────────────

describe("parseDocument: error cases", () => {
  it("rejects malformed JSON with an `invalid JSON` prefix", () => {
    const result = parseDocument("{not json}");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toMatch(/^invalid JSON:/);
    }
  });

  it("rejects a document missing the `spec` field", () => {
    const result = parseDocument(JSON.stringify({ schemaVersion: 3 }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Path naming uses `spec` (Zod issue path joined by `.`).
      expect(result.error).toContain("spec");
    }
  });

  it("rejects a document with an unknown wrapper-layer key", () => {
    // Wrapper is `.strict()` — unknown keys mean a forgotten
    // schemaVersion bump.
    const result = parseDocument(
      JSON.stringify({ schemaVersion: 3, spec: aes128Spec, fancyNewField: true }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a spec step with an unknown `kind` discriminator", () => {
    const result = parseDocument(
      JSON.stringify({
        schemaVersion: 3,
        spec: {
          id: "fake@1",
          name: "Fake",
          stateShape: "bytes",
          inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
          steps: [{ kind: "mystery", id: "x", type: "y", params: {} }],
        },
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("steps");
    }
  });

  it("rejects a SessionSnapshot.cipher value not in CIPHER_IDS", () => {
    const result = parseDocument(
      JSON.stringify({
        schemaVersion: 3,
        spec: aes128Spec,
        session: {
          mode: "encrypt",
          cipher: "not-a-real-cipher",
          cipherMode: "single-block",
          padding: "none",
          byteFormat: "hex",
        },
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("session.cipher");
    }
  });

  it("rejects a SessionSnapshot byte outside [0, 255]", () => {
    const result = parseDocument(
      JSON.stringify({
        schemaVersion: 3,
        spec: aes128Spec,
        session: {
          mode: "encrypt",
          cipher: "aes-128",
          cipherMode: "single-block",
          padding: "none",
          byteFormat: "hex",
          inputBytes: [256], // out of range
        },
      }),
    );
    expect(result.ok).toBe(false);
  });
});

// ─── Algorithm selector hint (Phase 6e, widened in Slice 2.10b) ──────────

describe("CipherDocument.algorithm hint field", () => {
  // Phase 6e of `docs/plans/des-feistel.md` introduced an optional
  // selector-hint field at the document root (originally `cipher: Cipher`).
  // Slice 2.10b of `docs/plans/universal-port-dataflow.md` renamed it to
  // `algorithm: Algorithm` and widened the enum to include Hash variants
  // (today: sha-256). The hint lets a recipient's selector flip to match
  // the loaded spec; without it, loading a DES doc into an AES-128-default
  // recipient left the selector mismatched and the input fields the wrong
  // byte length. Tests below pin the round-trip of the field through
  // serialize/parse — the selector-flip behavior on `setSpecFromDocument`
  // is covered by `built-from-palette-roundtrip.test.tsx` and the e2e
  // self-smoke.

  it("round-trips a spec-only document with an algorithm hint", () => {
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: desSpec,
      algorithm: "des",
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });

  it("round-trips a document with algorithm hint + layout + session (full fan-out)", () => {
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: desSpec,
      algorithm: "des",
      layout: {
        positions: { "des.initial-permutation": { x: 0, y: 0 } },
        collapsedGroups: ["rounds"],
        flowDirection: "ltr",
      },
      session: {
        mode: "encrypt",
        cipher: "des",
        cipherMode: "single-block",
        padding: "none",
        byteFormat: "hex",
      },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });

  it("a document without the algorithm hint still parses (back-compat)", () => {
    // Pre-Phase-6e documents (every shipped .cipher.json before this field
    // landed) must continue to load cleanly. The absent field is the legacy
    // fallback path: `setSpecFromDocument` doesn't flip the selector,
    // matching pre-fix behavior.
    const doc: CipherDocument = { schemaVersion: 3, spec: aes128Spec };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.doc).toEqual(doc);
      expect(result.doc.algorithm).toBeUndefined();
    }
  });

  it("rejects a malformed algorithm hint", () => {
    // Anything outside the closed `ALGORITHM_IDS` enum is malformed.
    const malformed = JSON.stringify({
      schemaVersion: 3,
      spec: aes128Spec,
      algorithm: "not-an-algorithm",
    });
    const result = parseDocument(malformed);
    expect(result.ok).toBe(false);
  });

  for (const cipher of CIPHER_IDS) {
    it(`accepts top-level algorithm hint = ${cipher}`, () => {
      const doc: CipherDocument = {
        schemaVersion: 3,
        spec: aes128Spec,
        algorithm: cipher,
      };
      const result = parseDocument(serializeDocument(doc));
      expect(result.ok).toBe(true);
    });
  }

  // Hash variants — Slice 2.10b widened the algorithm enum to include
  // Hash members. The spec field carries a cipher spec here (aes128Spec)
  // because the schema's algorithm field is structurally independent of
  // the spec's shape; cross-field consistency (hash hint paired with hash
  // spec) is the document author's responsibility, not the schema's.
  for (const hash of HASH_IDS) {
    it(`accepts top-level algorithm hint = ${hash} (hash variant)`, () => {
      const doc: CipherDocument = {
        schemaVersion: 3,
        spec: aes128Spec,
        algorithm: hash,
      };
      const result = parseDocument(serializeDocument(doc));
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.doc.algorithm).toBe(hash);
    });
  }
});

// ─── Stable serialization ─────────────────────────────────────────────────

describe("serializeDocument: stable key order", () => {
  it("produces byte-for-byte identical output on two equal-shaped inputs with different key insertion order", () => {
    // Build the same document twice but insert wrapper-level keys in
    // different orders. The serializer should sort keys alphabetically
    // so both calls produce identical output — this is the property
    // URL-share hashing (Slice 7) depends on.
    const docA: CipherDocument = {
      schemaVersion: 3,
      spec: aes128Spec,
      metadata: { name: "x", createdAt: 1 },
    };
    // Re-create by assembling fields in reverse order. JS object literals
    // preserve insertion order so the unsorted JSON.stringify would emit
    // different output.
    const docB: CipherDocument = {
      metadata: { createdAt: 1, name: "x" },
      spec: aes128Spec,
      schemaVersion: 3,
    } as CipherDocument;
    expect(serializeDocument(docA)).toBe(serializeDocument(docB));
  });

  it("preserves array order (arrays carry positional semantics)", () => {
    // sortKeysDeep MUST NOT sort arrays — params like `[1, 2, 3]` carry
    // positional meaning (S-box entries, rcon table, MixColumns matrix).
    const doc: CipherDocument = {
      schemaVersion: 3,
      spec: {
        id: "test@1",
        name: "Test",
        stateShape: "bytes",
        inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "leaf",
            type: "noop@1",
            params: { table: [3, 1, 2] },
          },
        ],
      },
    };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok && result.doc.spec.steps[0]?.kind === "step") {
      const params = result.doc.spec.steps[0].params as { table: number[] };
      expect(params.table).toEqual([3, 1, 2]); // NOT [1, 2, 3]
    }
  });
});

// ─── Enum coverage ─────────────────────────────────────────────────────────

describe("schema enum coverage", () => {
  // The compile-time `Exclude<>` check (`document-schema.ts`) pins
  // CIPHER_IDS against the Cipher type. This test pins the runtime Zod
  // enum: a SessionSnapshot with each shipped cipher must round-trip.

  for (const cipher of CIPHER_IDS) {
    it(`accepts SessionSnapshot.cipher = ${cipher}`, () => {
      const doc: CipherDocument = {
        schemaVersion: 3,
        spec: aes128Spec,
        session: {
          mode: "encrypt",
          cipher,
          cipherMode: "single-block",
          padding: "none",
          byteFormat: "hex",
        },
      };
      const result = parseDocument(serializeDocument(doc));
      expect(result.ok).toBe(true);
    });
  }

  for (const cipherMode of CIPHER_MODES) {
    it(`accepts SessionSnapshot.cipherMode = ${cipherMode}`, () => {
      const doc: CipherDocument = {
        schemaVersion: 3,
        spec: aes128Spec,
        session: {
          mode: "encrypt",
          cipher: "aes-128",
          cipherMode,
          padding: "none",
          byteFormat: "hex",
        },
      };
      const result = parseDocument(serializeDocument(doc));
      expect(result.ok).toBe(true);
    });
  }

  for (const padding of PADDING_SCHEMES) {
    it(`accepts SessionSnapshot.padding = ${padding}`, () => {
      const doc: CipherDocument = {
        schemaVersion: 3,
        spec: aes128Spec,
        session: {
          mode: "encrypt",
          cipher: "aes-128",
          cipherMode: "single-block",
          padding,
          byteFormat: "hex",
        },
      };
      const result = parseDocument(serializeDocument(doc));
      expect(result.ok).toBe(true);
    });
  }

  for (const byteFormat of BYTE_FORMATS) {
    it(`accepts SessionSnapshot.byteFormat = ${byteFormat}`, () => {
      const doc: CipherDocument = {
        schemaVersion: 3,
        spec: aes128Spec,
        session: {
          mode: "encrypt",
          cipher: "aes-128",
          cipherMode: "single-block",
          padding: "none",
          byteFormat,
        },
      };
      const result = parseDocument(serializeDocument(doc));
      expect(result.ok).toBe(true);
    });
  }
});

// ─── cipherConstants persistence (scaffolding-suppression A1) ──────────────
// SHA-256 is the first spec carrying `spec.cipherConstants` (K + H). The
// constants are Uint8Array at runtime but JSON has no byte type, so
// document.ts hex-encodes on serialize and decodes on parse. Pin that the
// round-trip preserves them byte-equal AND as Uint8Array (not the
// `{"0":..}` object JSON.stringify would emit for a raw typed array).

describe("cipherConstants persistence (A1)", () => {
  const sha256Doc = (): CipherDocument => ({
    schemaVersion: CURRENT_SCHEMA_VERSION,
    spec: buildSha256Spec(),
  });

  it("round-trips SHA-256 K + H as byte-equal Uint8Array", () => {
    const doc = sha256Doc();
    const result = parseDocument(serializeDocument(doc));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const constants = result.doc.spec.cipherConstants;
    expect(constants).toBeDefined();
    if (!constants) return;
    const k = constants.K;
    const h = constants.H;
    expect(k).toBeInstanceOf(Uint8Array);
    expect(h).toBeInstanceOf(Uint8Array);
    expect(k?.length).toBe(256);
    expect(h?.length).toBe(32);
    // Byte-equal to the source spec's constants.
    const src = doc.spec.cipherConstants;
    if (!src) throw new Error("source spec has no cipherConstants");
    expect(Array.from(k as Uint8Array)).toEqual(Array.from(src.K as Uint8Array));
    expect(Array.from(h as Uint8Array)).toEqual(Array.from(src.H as Uint8Array));
  });

  it("serializes constants as hex strings, not numeric-keyed objects", () => {
    const json = serializeDocument(sha256Doc());
    // H_0 = 0x6a09e667 — the hex form must appear; the typed-array object
    // form (`"cipherConstants":{"H":{"0":106,...}}`) must NOT.
    expect(json).toContain("6a09e667");
    expect(json).not.toContain('"0":106');
  });

  it("is byte-stable: serializing twice yields identical output", () => {
    const a = serializeDocument(sha256Doc());
    const b = serializeDocument(sha256Doc());
    expect(a).toBe(b);
  });

  it("round-trips an EDITED constant (user changes a byte in the panel)", () => {
    const base = buildSha256Spec();
    if (!base.cipherConstants) throw new Error("expected cipherConstants on SHA-256");
    const editedH = Uint8Array.from(base.cipherConstants.H as Uint8Array);
    editedH[0] = (editedH[0] ?? 0) ^ 0xff; // flip the first byte
    const doc: CipherDocument = {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      spec: { ...base, cipherConstants: { ...base.cipherConstants, H: editedH } },
    };
    const result = parseDocument(serializeDocument(doc));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const h = result.doc.spec.cipherConstants?.H;
    expect(h).toBeInstanceOf(Uint8Array);
    expect(Array.from(h as Uint8Array)).toEqual(Array.from(editedH));
  });

  // Slice 2.11b: the multi-block fold added structure that Zod could strip on
  // Save/Load — the `blocks` iterate's `chainInput`/`chainFeedback`/`chainOutput`
  // and `spec.outputFrom = port("blocks","digest")`. The constants tests above
  // don't catch a stripped field (they only inspect cipherConstants). This RUNS
  // the round-tripped spec and checks the digest survives — the load-bearing
  // persistence gate for the multi-block restructure. Both a single-block (§A.1)
  // and a multi-block (§A.2, 2 blocks) message, so a dropped chain field would
  // surface as a wrong multi-block digest even if single-block coincidentally held.
  it("round-tripped SHA-256 spec still hashes correctly (multi-block fold wiring survives)", () => {
    const hexDigest = (spec: CipherSpec, msg: Uint8Array): string => {
      const trace = runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: msg },
      });
      if (trace.finalState.shape !== "bytes") throw new Error("expected bytes finalState");
      return Array.from(trace.finalState.bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    };
    const result = parseDocument(serializeDocument(sha256Doc()));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const reloaded = result.doc.spec;
    // §A.1 "abc" (1 block).
    expect(hexDigest(reloaded, new TextEncoder().encode("abc"))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    // §A.2 56-byte message (2 blocks) — exercises chainFeedback across the
    // block boundary, which a stripped chain field would break.
    expect(
      hexDigest(
        reloaded,
        new TextEncoder().encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
      ),
    ).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  });
});
