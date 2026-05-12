/**
 * CipherDocument file format (Slice 3 of the 2D editor plan).
 *
 * A `CipherDocument` wraps a `CipherSpec` with three optional sidecars —
 * graph layout, session bytes/selectors, and metadata — so users can save
 * their customized ciphers to disk, share them via URL hash, and reload
 * them next session. Today only the types + serialization round-trip ship;
 * the save/load UI (Slice 5) and URL share (Slice 7) consume this surface
 * later.
 *
 * Two design choices that future slices rely on:
 *
 *   1. **`LayoutSpec` is a sidecar, not fields on `StepNode`.** The plan
 *      `core/types.ts` declares "saved CipherSpec JSON references these
 *      shapes forever." Stashing view-only `{x, y}` on `StepLeaf` would
 *      break that contract. By keeping layout out of the spec, old
 *      documents (no layout) gracefully auto-layout, and the spec stays
 *      canonical regardless of where it's loaded from (file, URL, default).
 *
 *   2. **Stable serialization key order.** `serializeDocument` sorts every
 *      object's keys alphabetically before stringifying. URL hashes are
 *      derived from the serialized form (Slice 7), so byte-for-byte
 *      determinism across runs is required — otherwise the same document
 *      would produce different shareable URLs each session.
 *
 * Schema versioning anchor: `schemaVersion: 1` today. Future bumps will
 * land a `migrate(v1 → v2)` step inside `parseDocument`. Files with an
 * unknown version produce a friendly forward-incompat error rather than
 * crashing the loader.
 *
 * Types are hand-written rather than `z.infer`'d from `document-schema.ts`
 * because our project-wide `exactOptionalPropertyTypes: true` makes
 * `field?: T` distinct from `field?: T | undefined`. Zod 3's `.optional()`
 * infers the latter; the plan's contract uses the former. Validation
 * still routes through Zod via `safeParse`, with the result cast to the
 * hand-written types.
 */

import type { Cipher } from "@/ui/stores/cipher";
import type { CipherMode } from "@/ui/stores/cipher-mode";
import type { Mode } from "@/ui/stores/spec";
import { CipherDocumentSchema } from "./document-schema";
import type { ByteFormat } from "./format";
import type { PaddingScheme } from "./spec-mutations";
import type { CipherSpec } from "./types";

// ─── Schema-version anchor ────────────────────────────────────────────────

/** The version this app produces and accepts on load. */
export const CURRENT_SCHEMA_VERSION = 1 as const;

// ─── Public types ─────────────────────────────────────────────────────────
// Hand-written so optional fields are `field?: T` (not `T | undefined`) —
// matches the rest of the codebase under `exactOptionalPropertyTypes`.

/** Per-step position in a logical unit (1.0 = one node-width). */
export type StepPosition = {
  readonly x: number;
  readonly y: number;
};

/**
 * Sidecar graph layout. Positions keyed by `stepId` so a graph remembers
 * where the user dragged each node; container ids appear in
 * `collapsedGroups` when the user has clicked their chevron.
 *
 * `flowDirection: "ltr"` is the only value today; reserved field so a
 * future top-to-bottom layout doesn't need a schemaVersion bump.
 */
export type LayoutSpec = {
  readonly positions: { readonly [stepId: string]: StepPosition };
  readonly collapsedGroups: readonly string[];
  readonly flowDirection: "ltr";
};

/**
 * Snapshot of the user's exploration session. Captures the four selector
 * stores (mode, cipher, cipherMode, padding) + the byte-format
 * preference, plus optional input + key bytes for full reproducibility.
 *
 * Save/Load offer a checkbox controlling whether `inputBytes` / `keyBytes`
 * are included — the spec + layout variants stay shareable without
 * leaking the user's plaintext into a URL hash they paste publicly.
 */
export type SessionSnapshot = {
  readonly mode: Mode;
  readonly cipher: Cipher;
  readonly cipherMode: CipherMode;
  readonly padding: PaddingScheme;
  readonly byteFormat: ByteFormat;
  readonly inputBytes?: readonly number[];
  readonly keyBytes?: readonly number[];
};

/** Naming + timestamps. Forensic value when loading an old file. */
export type DocumentMetadata = {
  readonly name?: string;
  readonly createdAt?: number;
  readonly appVersion?: string;
};

/**
 * The top-level file format. `spec` is required; everything else is
 * optional and gracefully absent for minimal documents (e.g. a vanilla
 * canonical spec with no customization).
 */
export type CipherDocument = {
  readonly schemaVersion: typeof CURRENT_SCHEMA_VERSION;
  readonly spec: CipherSpec;
  readonly layout?: LayoutSpec;
  readonly session?: SessionSnapshot;
  readonly metadata?: DocumentMetadata;
};

// ─── Parse result ─────────────────────────────────────────────────────────
// Discriminated `{ ok }` so callers can pattern-match without try/catch
// for the common bad-input case. Hard programmer errors (passing a non-
// string to parseDocument) still throw.

export type ParseDocumentResult =
  | { readonly ok: true; readonly doc: CipherDocument }
  | { readonly ok: false; readonly error: string };

// ─── Serialization ────────────────────────────────────────────────────────

/**
 * Recursively rebuild a value with object keys in alphabetical order.
 * Arrays preserve their order (positional semantics); only objects get
 * sorted. Primitives pass through unchanged.
 *
 * The rebuilt value's key insertion order is what `JSON.stringify` walks
 * to produce its output, so this is sufficient for byte-stable encoding.
 *
 * `noUncheckedIndexedAccess` makes `o[k]` return `unknown | undefined`
 * even though `Object.keys(o)` guarantees `k` is a real own-property —
 * the `undefined` branch is impossible at runtime but accepted by the
 * type checker since `sortKeysDeep` takes `unknown`.
 */
const sortKeysDeep = (v: unknown): unknown => {
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  const o = v as Record<string, unknown>;
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(o).sort()) {
    sorted[k] = sortKeysDeep(o[k]);
  }
  return sorted;
};

/**
 * Serialize a `CipherDocument` to a deterministic JSON string. Calling
 * twice on inputs that compare deep-equal produces byte-identical output,
 * which is the property URL-share (Slice 7) needs to produce stable links.
 *
 * The output is compact (no indentation); the file-save UI (Slice 5) can
 * pretty-print on the way to disk if that's preferred, but the canonical
 * form for hashing / comparison is the compact one.
 */
export const serializeDocument = (doc: CipherDocument): string => JSON.stringify(sortKeysDeep(doc));

// ─── Parsing ──────────────────────────────────────────────────────────────

/**
 * Parse + validate a serialized `CipherDocument`. Returns a discriminated
 * `{ ok }` result so the UI can show a friendly inline error instead of
 * throwing into the void.
 *
 * Two-phase validation:
 *  1. `JSON.parse` — structural; fails on syntax errors.
 *  2. `schemaVersion` pre-check — produces a friendlier message than the
 *     schema's literal-mismatch ("schemaVersion N is not supported" vs.
 *     "Invalid literal value, expected 1"). The pre-check fires before
 *     the full schema so a v2 file doesn't trigger a wall of irrelevant
 *     errors about every other field shape.
 *  3. `CipherDocumentSchema.safeParse` — full Zod validation. The
 *     wrapper layers (Document / Layout / Session / Metadata) are
 *     `.strict()`, so unknown fields at those layers are caught; the
 *     `CipherSpec` interior stays loose for forward-compat within v1.
 *
 * Error messages from phase 3 are formatted as `path: message` joined by
 * `; ` so the user sees "spec.steps.0.kind: Invalid discriminator value..."
 * rather than Zod's default JSON-string error.
 */
export const parseDocument = (text: string): ParseDocumentResult => {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, error: `invalid JSON: ${msg}` };
  }

  // Phase 2: schemaVersion pre-check. A document with a numeric
  // `schemaVersion` that doesn't match what we read gets a forward/
  // backward-compat error rather than the raw Zod literal mismatch.
  if (raw !== null && typeof raw === "object" && !Array.isArray(raw)) {
    const sv = (raw as { schemaVersion?: unknown }).schemaVersion;
    if (typeof sv === "number" && sv !== CURRENT_SCHEMA_VERSION) {
      return {
        ok: false,
        error: `schemaVersion ${sv} is not supported (this app reads version ${CURRENT_SCHEMA_VERSION}; the file may be from a different app version)`,
      };
    }
  }

  // Phase 3: full schema validation.
  const result = CipherDocumentSchema.safeParse(raw);
  if (!result.success) {
    return { ok: false, error: formatZodError(result.error) };
  }

  // Cast: Zod's inferred type uses `T | undefined` for optional fields,
  // but our hand-written `CipherDocument` uses `field?: T` (same shape at
  // runtime — the cast is the type-level reconciliation).
  return { ok: true, doc: result.data as unknown as CipherDocument };
};

/**
 * Format a Zod error into a single readable line. Each issue becomes
 * `path: message`; the root issue (path = []) becomes `(root): message`.
 */
const formatZodError = (e: {
  issues: readonly { path: readonly (string | number)[]; message: string }[];
}): string =>
  e.issues
    .map((i) => `${i.path.length > 0 ? i.path.join(".") : "(root)"}: ${i.message}`)
    .join("; ");
