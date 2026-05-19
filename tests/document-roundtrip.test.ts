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
 *   - Reject schemaVersion 0 and schemaVersion 2 with the friendly
 *     pre-check error message (not the raw Zod literal mismatch).
 *   - Reject malformed JSON syntax.
 *   - Reject malformed structure (missing required fields, bad
 *     discriminator, unknown wrapper-layer key).
 *   - Optional fields really are optional: a minimal `{ schemaVersion: 1,
 *     spec }` round-trips.
 *   - Stable key order: serialize twice → byte-for-byte identical.
 *   - Enum coverage: every Cipher / CipherMode / PaddingScheme /
 *     ByteFormat literal can appear in a SessionSnapshot (the
 *     compile-time `Exclude` check pins the LOCAL `CIPHER_IDS` list, but
 *     this guards against the runtime Zod enum drifting from the TS
 *     value the schema accepts).
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes128EcbDecryptSpec } from "@/ciphers/aes-128-ecb-decrypt";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes192DecryptSpec } from "@/ciphers/aes-192-decrypt";
import { aes256Spec } from "@/ciphers/aes-256";
import { aes256DecryptSpec } from "@/ciphers/aes-256-decrypt";
import { desSpec } from "@/ciphers/des";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
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
import { BYTE_FORMATS, CIPHER_IDS, CIPHER_MODES, PADDING_SCHEMES } from "@/core/document-schema";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Shipped specs table ──────────────────────────────────────────────────

const SHIPPED_SPECS: ReadonlyArray<{ readonly name: string; readonly spec: CipherSpec }> = [
  { name: "aes-128 encrypt", spec: aes128Spec },
  { name: "aes-128 decrypt", spec: aes128DecryptSpec },
  { name: "aes-128 ECB encrypt", spec: aes128EcbSpec },
  { name: "aes-128 ECB decrypt", spec: aes128EcbDecryptSpec },
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
  // Phase 2 of the DES + branching primitive plan — toy spec used to
  // exercise the new feistel-round node kind through the document
  // schema's discriminated union. Not a shipped user-facing cipher.
  { name: "feistel-toy (Phase 2 test fixture)", spec: FEISTEL_TOY_SPEC },
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
      const doc: CipherDocument = { schemaVersion: 1, spec };
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
      schemaVersion: 1,
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
      schemaVersion: 1,
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
      schemaVersion: 1,
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
      schemaVersion: 1,
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

  it("rejects a malformed relativePositions entry", () => {
    // Wrong shape — RelativePosition is `{ dx, dy }`, not `{ x, y }`.
    const malformed = JSON.stringify({
      schemaVersion: 1,
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
      schemaVersion: 1,
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
      schemaVersion: 1,
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
      schemaVersion: 1,
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
      schemaVersion: 1,
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
    const doc: CipherDocument = { schemaVersion: 1, spec: aes128Spec, metadata: {} };
    const text = serializeDocument(doc);
    const result = parseDocument(text);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.doc).toEqual(doc);
  });
});

// ─── schemaVersion handling ───────────────────────────────────────────────

describe("parseDocument: schemaVersion handling", () => {
  it("accepts schemaVersion === 1", () => {
    expect(CURRENT_SCHEMA_VERSION).toBe(1);
    const result = parseDocument(JSON.stringify({ schemaVersion: 1, spec: aes128Spec }));
    expect(result.ok).toBe(true);
  });

  it("rejects schemaVersion === 0 with a friendly forward/back-compat error", () => {
    const result = parseDocument(JSON.stringify({ schemaVersion: 0, spec: aes128Spec }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("schemaVersion 0 is not supported");
      expect(result.error).toContain("version 1");
    }
  });

  it("rejects schemaVersion === 2 with a friendly forward/back-compat error", () => {
    const result = parseDocument(JSON.stringify({ schemaVersion: 2, spec: aes128Spec }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("schemaVersion 2 is not supported");
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
    const result = parseDocument(JSON.stringify({ schemaVersion: 1 }));
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
      JSON.stringify({ schemaVersion: 1, spec: aes128Spec, fancyNewField: true }),
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a spec step with an unknown `kind` discriminator", () => {
    const result = parseDocument(
      JSON.stringify({
        schemaVersion: 1,
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
        schemaVersion: 1,
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
        schemaVersion: 1,
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

// ─── Stable serialization ─────────────────────────────────────────────────

describe("serializeDocument: stable key order", () => {
  it("produces byte-for-byte identical output on two equal-shaped inputs with different key insertion order", () => {
    // Build the same document twice but insert wrapper-level keys in
    // different orders. The serializer should sort keys alphabetically
    // so both calls produce identical output — this is the property
    // URL-share hashing (Slice 7) depends on.
    const docA: CipherDocument = {
      schemaVersion: 1,
      spec: aes128Spec,
      metadata: { name: "x", createdAt: 1 },
    };
    // Re-create by assembling fields in reverse order. JS object literals
    // preserve insertion order so the unsorted JSON.stringify would emit
    // different output.
    const docB: CipherDocument = {
      metadata: { createdAt: 1, name: "x" },
      spec: aes128Spec,
      schemaVersion: 1,
    } as CipherDocument;
    expect(serializeDocument(docA)).toBe(serializeDocument(docB));
  });

  it("preserves array order (arrays carry positional semantics)", () => {
    // sortKeysDeep MUST NOT sort arrays — params like `[1, 2, 3]` carry
    // positional meaning (S-box entries, rcon table, MixColumns matrix).
    const doc: CipherDocument = {
      schemaVersion: 1,
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
        schemaVersion: 1,
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
        schemaVersion: 1,
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
        schemaVersion: 1,
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
        schemaVersion: 1,
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
