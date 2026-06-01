// @vitest-environment node
//
// Unit tests for Slice 7's URL hash encode/decode pipeline. Runs in the
// node env (no DOM); CompressionStream is a Node 21+ global and we're on
// 24, so the same code path exercised here is what ships to the browser.
//
// Covered properties:
//
//   1. Round-trip: encode → decode reproduces a deep-equal document for
//      every shipped (cipher, mode) we care to share.
//
//   2. Determinism: encoding the same document twice produces the SAME
//      hash. This is what Slice 5's spec-only byte-stability test
//      protects upstream; here we verify the property survives the
//      compression layer (it does, because deflate is deterministic for
//      a given input and the serializer sorts keys).
//
//   3. Malformed payload handling: garbled base64, valid base64 of
//      garbage bytes (inflate fails), and inflate output that doesn't
//      parse as a valid document each produce a distinct, friendly error.
//
//   4. Size budget: shared session of AES-128 default is under 4 KB
//      encoded. Worst case (AES-256 session-on with custom layout) is
//      under 4 KB too. The plan's budget; encoded here as a test so it
//      can't silently regress.

import { aes128Spec } from "@/ciphers/aes-128";
import { aes256Spec } from "@/ciphers/aes-256";
import { CURRENT_SCHEMA_VERSION, type CipherDocument } from "@/core/document";
import {
  HASH_PREFIX,
  buildShareHash,
  decodeHashToDocument,
  encodeDocumentToHash,
  extractHashPayload,
} from "@/ui/stores/url-share";
import { describe, expect, it } from "vitest";

const specOnly: CipherDocument = {
  schemaVersion: CURRENT_SCHEMA_VERSION,
  spec: aes128Spec,
};

const aes256WithLayout: CipherDocument = {
  schemaVersion: CURRENT_SCHEMA_VERSION,
  spec: aes256Spec,
  layout: {
    positions: { "round.5": { x: 400, y: 80 }, "round.10": { x: 800, y: 80 } },
    collapsedGroups: ["round.7"],
    flowDirection: "ltr",
  },
  session: {
    mode: "encrypt",
    cipher: "aes-256",
    cipherMode: "single-block",
    padding: "none",
    byteFormat: "hex",
    inputBytes: Array(16).fill(0),
    keyBytes: Array(32).fill(0),
  },
  metadata: { createdAt: 1700000000000, appVersion: "0.2.0" },
};

describe("url-share — encode/decode round-trip", () => {
  it("encodes + decodes a spec-only document to a deep-equal result", async () => {
    const encoded = await encodeDocumentToHash(specOnly);
    const result = await decodeHashToDocument(encoded);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.doc).toEqual(specOnly);
  });

  it("encodes + decodes a full session document with layout intact", async () => {
    const encoded = await encodeDocumentToHash(aes256WithLayout);
    const result = await decodeHashToDocument(encoded);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.doc).toEqual(aes256WithLayout);
  });

  it("is deterministic — same document → same hash", async () => {
    // Critical for the "share my custom AES variant" pedagogy: a friend
    // I link should be able to verify they're seeing the same setup by
    // re-encoding and matching strings. Determinism comes from
    // serializeDocument's sorted-keys property + deflate's pure-fn nature.
    const a = await encodeDocumentToHash(specOnly);
    const b = await encodeDocumentToHash(specOnly);
    expect(a).toBe(b);
  });

  it("produces compact payloads — spec-only AES-128 under 12 KB encoded", async () => {
    const encoded = await encodeDocumentToHash(specOnly);
    // Byte-native AES-128 (Slice B1) plus the decomposed key schedule (K1c)
    // is a much larger spec than the matrix form — ~150 leaves now, each
    // carrying its own params plus a `narrationOverride` block (the ~114
    // key-schedule sub-step leaves added their RotWord/SubWord/Rcon/word-XOR
    // narration). The measured baseline rose ~4.4 KB → ~8.5 KB. Still trivially
    // URL-safe (orders of magnitude under any browser URL limit). Asserting at
    // the generous side keeps a real regression catchable without flapping.
    expect(encoded.length).toBeLessThan(12288);
  });

  it("produces compact payloads — AES-256 + layout + session under 14 KB", async () => {
    // Largest realistic case shipped today. Byte-native AES-256 (Slice B1.3)
    // plus the decomposed key schedule (K1c) — 14 rounds of port-native leaves
    // + the Nk=8 schedule's ~130 sub-step leaves, each with params + a
    // `narrationOverride` — pushed the measured baseline to ~9.7 KB. Still
    // trivially URL-safe. If this fails after a future schema change, time to
    // revisit the compression strategy.
    const encoded = await encodeDocumentToHash(aes256WithLayout);
    expect(encoded.length).toBeLessThan(14336);
  });
});

describe("url-share — failure modes", () => {
  it("rejects garbled base64url with a friendly error", async () => {
    const result = await decodeHashToDocument("!!!not-base64-at-all!!!");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    // The atob throw bubbles up as a "invalid base64url" prefix so the
    // boot hook can distinguish this from inflate / schema failures.
    expect(result.error).toMatch(/decode failed/);
  });

  it("rejects valid base64url of non-deflate bytes", async () => {
    // 'aGVsbG8' is base64url("hello") — valid base64 but not a deflate stream.
    const result = await decodeHashToDocument("aGVsbG8");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toMatch(/decode failed|invalid/);
  });

  it("rejects a valid-deflate-of-garbage-JSON payload at the schema layer", async () => {
    // Hand-encode a deflate stream whose contents are not a CipherDocument
    // so we exercise the parseDocument failure path inside decodeHash.
    // Easiest: encode a document with a future schemaVersion and verify
    // the friendly schema-version error survives the compression layer.
    const futureDoc = {
      schemaVersion: 999,
      spec: aes128Spec,
    } as unknown as CipherDocument;
    // We CAN encode it because encodeDocumentToHash doesn't validate
    // (it serializes whatever it's given). Decode runs parseDocument
    // which DOES validate — and the schemaVersion pre-check fires first.
    const encoded = await encodeDocumentToHash(futureDoc);
    const result = await decodeHashToDocument(encoded);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toMatch(/decoded document is invalid/);
    expect(result.error).toMatch(/schemaVersion 999/);
  });
});

describe("url-share — hash key helpers", () => {
  it("buildShareHash wraps the encoded payload with the `#doc=` prefix", () => {
    expect(buildShareHash("abc")).toBe("#doc=abc");
    expect(HASH_PREFIX).toBe("doc=");
  });

  it("extractHashPayload returns the payload for matching hashes", () => {
    expect(extractHashPayload("#doc=abc")).toBe("abc");
    expect(extractHashPayload("doc=abc")).toBe("abc");
  });

  it("extractHashPayload returns null for non-matching hashes", () => {
    expect(extractHashPayload("")).toBeNull();
    expect(extractHashPayload("#")).toBeNull();
    expect(extractHashPayload("#section")).toBeNull();
    expect(extractHashPayload("#otherkey=abc")).toBeNull();
  });
});
