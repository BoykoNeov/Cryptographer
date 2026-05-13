/**
 * URL hash sharing — Slice 7 of the 2D editor plan.
 *
 * Lets a user copy a self-contained URL that, when opened in a fresh tab,
 * loads the exact CipherDocument they had on screen. The whole document
 * (spec + optional layout + optional session) rides in the URL fragment
 * (`#doc=…`) so the server never sees it — keeps custom S-boxes and
 * plaintext bytes out of HTTP logs.
 *
 * ## Pipeline
 *
 *   serializeDocument → UTF-8 bytes → deflate-raw → base64url
 *
 * Why **deflate-raw + base64url** and not `pako` or plain base64-of-JSON:
 *
 *   - **Measured**: an `aes-128` spec-only document is 15.5 KB raw JSON,
 *     20.7 KB after plain base64url (paste-unfriendly), but only 1.2 KB
 *     after deflate and 1.6 KB after deflate+base64url. The AES-256
 *     session-on worst case is 1.9 KB encoded. Two orders of magnitude
 *     under any browser's URL cap (~32-200 KB depending on browser; the
 *     practical paste-into-Slack ceiling is much lower).
 *   - **Zero bundle cost**: `CompressionStream("deflate-raw")` is built
 *     into modern browsers (Chrome 80+, Firefox 113+, Safari 16.4+) and is
 *     a Node global since v21. Pako's ~12 KB gzipped would be a noticeable
 *     hit on a 72 KB bundle for the same compression ratio.
 *   - **`deflate-raw` over `gzip`**: gzip wraps deflate with a header +
 *     CRC32 footer (~18 bytes of overhead). For this size class, that
 *     overhead matters; deflate-raw is the smallest standard option.
 *
 * ## Async, by force
 *
 * `CompressionStream` is stream-based, so `encodeDocumentToHash` returns
 * a `Promise<string>` and `decodeHashToDocument` returns a `Promise<…>`.
 * Callers must await. The click handler in `App.tsx` is naturally async
 * (it also writes to the clipboard, which is async); the boot decode
 * runs once on mount and the brief sub-frame between mount and apply is
 * acceptable — `setSpecFromDocument` already overrides whatever the
 * localStorage-driven stores hydrated with at module import time.
 *
 * ## Failure handling
 *
 * `decodeHashToDocument` returns a discriminated `{ ok }` result so the
 * boot hook can surface friendly inline errors instead of throwing into
 * the void. Three failure modes get distinct messages: invalid base64,
 * inflate failure (corrupt/truncated bytes), and a successfully decoded
 * but schema-invalid document (a future-version share, or hand-edited).
 */

import { type CipherDocument, parseDocument, serializeDocument } from "@/core/document";

// ─── Hash key prefix ──────────────────────────────────────────────────────
// Documented as a constant so `App.tsx`'s boot hook and tests share the
// exact same key — avoids the "I'll just type '#doc=' here too" copy-paste
// drift that bites later.
export const HASH_PREFIX = "doc=";

// ─── Public API ────────────────────────────────────────────────────────────

export type DecodeResult =
  | { readonly ok: true; readonly doc: CipherDocument }
  | { readonly ok: false; readonly error: string };

/**
 * Encode a document into the value that follows `#doc=` in the share URL.
 *
 * Determinism: `serializeDocument` already sorts keys alphabetically, so
 * the same document deep-equal'd to itself always produces the same hash —
 * the property pinned by `tests/file-save-load.test.tsx`'s "byte-stable"
 * case. Don't add any timestamping at this layer; the spec-only path's
 * shareable URL must be the same across browser sessions.
 */
export const encodeDocumentToHash = async (doc: CipherDocument): Promise<string> => {
  const text = serializeDocument(doc);
  const utf8 = new TextEncoder().encode(text);
  const compressed = await deflateRaw(utf8);
  return toBase64Url(compressed);
};

/**
 * Decode a hash value (the part after `#doc=`) back into a document.
 * Boot hook in `App.tsx` calls this; failure cases keep the hash in the
 * URL so a user can show it to a maintainer when reporting a bad link.
 *
 * Each failure mode produces a distinct prefix so the UI's error banner
 * tells the user something actionable: "decode failed: …" → the URL is
 * garbled in transit; "decoded document is invalid: …" → the URL is well-
 * formed but the schema rejected it (typically a forward-version share).
 */
export const decodeHashToDocument = async (hash: string): Promise<DecodeResult> => {
  let compressed: Uint8Array;
  try {
    compressed = fromBase64Url(hash);
  } catch (e) {
    return { ok: false, error: `decode failed (invalid base64url): ${errMessage(e)}` };
  }

  let utf8: Uint8Array;
  try {
    utf8 = await inflateRaw(compressed);
  } catch (e) {
    return { ok: false, error: `decode failed (could not inflate): ${errMessage(e)}` };
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(utf8);
  } catch (e) {
    return { ok: false, error: `decode failed (invalid UTF-8): ${errMessage(e)}` };
  }

  const parsed = parseDocument(text);
  if (!parsed.ok) {
    return { ok: false, error: `decoded document is invalid: ${parsed.error}` };
  }
  return { ok: true, doc: parsed.doc };
};

/**
 * Build the full shareable URL string for the current window. Factored so
 * the App click handler is a one-liner and tests can assert the format
 * without window mocking. The host portion is left to the caller (just
 * `window.location.origin + window.location.pathname`); we own the hash
 * portion + prefix.
 */
export const buildShareHash = (encoded: string): string => `#${HASH_PREFIX}${encoded}`;

/**
 * Read a shareable doc value out of a raw `window.location.hash` string.
 * Returns `null` if the hash doesn't carry our prefix — boot hook treats
 * that as "nothing to do" (NOT an error; most page loads have no hash at
 * all, or have an unrelated `#section-anchor`).
 */
export const extractHashPayload = (hash: string): string | null => {
  // location.hash includes the leading "#" when present; strip it.
  const trimmed = hash.startsWith("#") ? hash.slice(1) : hash;
  if (!trimmed.startsWith(HASH_PREFIX)) return null;
  return trimmed.slice(HASH_PREFIX.length);
};

// ─── Internal: deflate/inflate via WHATWG CompressionStream ────────────────
// CompressionStream lands in browsers as a global; Node 21+ exposes it as
// a global too. The vitest node env (we're on Node 24) has it. If a future
// runtime drops it we'd surface the failure here, not at the call site.
//
// We feed the input bytes directly through the writer interface instead of
// the more idiomatic `new Blob([bytes]).stream().pipeThrough(...)`.
// Reason: jsdom 29's Blob doesn't implement `.stream()`, and we want the
// production code path (not a test-only branch) to be the one that runs
// under jsdom's UI tests. The writer/reader form is fully portable.

const streamThroughTransform = async (
  input: Uint8Array,
  transform: GenericTransformStream,
): Promise<Uint8Array> => {
  const writer = transform.writable.getWriter();
  // When the underlying transform errors mid-stream (the malformed-input
  // case for DecompressionStream), BOTH the writer's promises and the
  // readable's consumer reject independently. We surface the error via
  // the readable side (`await new Response(...).arrayBuffer()` below);
  // the writer-side rejections need explicit `.catch` swallowing so they
  // don't surface as unhandled-rejection warnings in the test runner.
  writer.write(input).catch(() => {});
  writer.close().catch(() => {});
  // Reading everything into a Response coalesces multi-chunk output into
  // a single ArrayBuffer with minimal ceremony. Both jsdom and modern
  // Node support `new Response(ReadableStream)`.
  return new Uint8Array(await new Response(transform.readable).arrayBuffer());
};

const deflateRaw = (input: Uint8Array): Promise<Uint8Array> =>
  streamThroughTransform(input, new CompressionStream("deflate-raw"));

const inflateRaw = (input: Uint8Array): Promise<Uint8Array> =>
  streamThroughTransform(input, new DecompressionStream("deflate-raw"));

// ─── Internal: base64url codec ─────────────────────────────────────────────
// "URL-safe" base64: `+` → `-`, `/` → `_`, padding `=` stripped. The
// reverse on decode tolerates either form (with or without padding) for
// resilience against well-meaning URL shorteners that strip trailing `=`.

const toBase64Url = (bytes: Uint8Array): string => {
  // btoa wants a binary string; build it via String.fromCharCode in chunks
  // to avoid the 64K-arg call-stack limit on enormous payloads. Our typical
  // payload is ~1.5KB so this barely matters, but the chunked form is the
  // standard idiom and protects future use.
  const CHUNK = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    const slice = bytes.subarray(i, i + CHUNK);
    binary += String.fromCharCode(...slice);
  }
  const b64 = btoa(binary);
  return b64.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
};

const fromBase64Url = (s: string): Uint8Array => {
  // Restore standard base64 alphabet + padding before atob. atob throws on
  // any non-alphabet character; we let it, then wrap in DecodeResult.
  const b64 = s.replaceAll("-", "+").replaceAll("_", "/");
  const padding = (4 - (b64.length % 4)) % 4;
  const padded = b64 + "=".repeat(padding);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
};

// ─── Helpers ──────────────────────────────────────────────────────────────

const errMessage = (e: unknown): string => (e instanceof Error ? e.message : String(e));
