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

/**
 * The version this app produces. Phase 4 of `docs/plans/des-feistel.md`
 * bumped this from 1 → 2 when DES entered the cipher selector and users
 * could start saving documents containing `feistel-round` nodes.
 *
 * Backwards compatibility for v1 documents (every AES `.cipher.json` and
 * URL-share link from prior sessions) is preserved via `migrateDocument`
 * below — v1 → v2 is a pure version-bump migration since v1 documents
 * cannot contain any `feistel-round` nodes (DES wasn't selectable),
 * so no node-level changes are required.
 */
export const CURRENT_SCHEMA_VERSION = 2 as const;

/**
 * The set of historical schema versions this app can load (after
 * applying `migrateDocument`). Used by the friendly pre-check in
 * `parseDocument` so a v2-only build still reads v1 docs without
 * erroring out at "schemaVersion 1 is not supported."
 */
export const ACCEPTED_SCHEMA_VERSIONS: readonly number[] = [1, 2];

// ─── Public types ─────────────────────────────────────────────────────────
// Hand-written so optional fields are `field?: T` (not `T | undefined`) —
// matches the rest of the codebase under `exactOptionalPropertyTypes`.

/** Per-step position in a logical unit (1.0 = one node-width). */
export type StepPosition = {
  readonly x: number;
  readonly y: number;
};

/**
 * Per-source override for the high-fanout-replica transform. `"always"`
 * forces replication regardless of fanout count; `"never"` suppresses
 * replication even when the source's fanout exceeds the global threshold.
 * Absence of an entry (the implicit `"auto"`) defers to the threshold —
 * the default behavior shipped in commit 4 of the graph-readability
 * sequence. Commit 5 of that sequence introduced this field.
 */
export type ReplicationMode = "always" | "never";

/**
 * Sidecar graph layout. Positions keyed by `stepId` so a graph remembers
 * where the user dragged each node; container ids appear in
 * `collapsedGroups` when the user has clicked their chevron.
 *
 * `flowDirection: "ltr"` is the only value today; reserved field so a
 * future top-to-bottom layout doesn't need a schemaVersion bump.
 *
 * `replicationModes` carries per-source overrides for the high-fanout-
 * replica transform (commit 5 of the graph-readability sequence). Absent
 * keys take the `"auto"` default; only `"always"` and `"never"` overrides
 * are stored. The field rides on `LayoutSpec` so that a shared
 * `.cipher.json` carries the author's annotated view of which sources to
 * replicate, while the byte-stability gate (`hasUserLayout`) still skips
 * the layout sidecar when the modes map is empty AND no positions /
 * collapsed groups exist.
 */
/**
 * Per-node relative offset (Slice opened 2026-05-19). Pin model for nodes
 * whose auto position depends on another node — aux replicas (whose
 * "natural slot" is above their consumer) and block chips (whose slot is
 * at the iterate's old position). Storing an ABSOLUTE pin for these would
 * break the "follow the anchor" relationship; we store a delta from the
 * algorithm's chosen position so the chip rides along when the consumer /
 * iterate moves.
 *
 * The anchor is implicit in the node's relationship to the graph
 * (`replicaOf` → consumer; `blockChipOf` → iterate) — no `anchorId` field
 * needed. Layout re-derives the anchor's position each pass, then adds
 * `(dx, dy)`.
 *
 * Stored in viewBox units at the layout's CURRENT density. `rescaleAllPositions`
 * also rescales these so they stay in logical-equivalent positions across
 * density flips. See `docs/plans/draggable-replicas.md`.
 */
export type RelativePosition = {
  readonly dx: number;
  readonly dy: number;
};

export type LayoutSpec = {
  readonly positions: { readonly [stepId: string]: StepPosition };
  readonly collapsedGroups: readonly string[];
  readonly flowDirection: "ltr";
  readonly replicationModes?: { readonly [sourceId: string]: ReplicationMode };
  /**
   * Relative-to-anchor pins for synthetic ids (aux replica
   * `${source}@->${consumer}`, block chip `${iterateId}@block${i}`). See
   * `RelativePosition` above for the model. Absent / empty when no chip
   * has been dragged — same byte-stability discipline as `replicationModes`.
   */
  readonly relativePositions?: { readonly [syntheticId: string]: RelativePosition };
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
  // IV bytes (Phase 2). Strictly 16 bytes when present. Optional so
  // pre-Phase-2 documents that predate the IV store still round-trip
  // without conversion.
  readonly ivBytes?: readonly number[];
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
 *
 * `cipher` is a lightweight selector hint (Phase 6e of
 * `docs/plans/des-feistel.md`). Save always emits it so a spec-only
 * .cipher.json or URL-share document tells the loader "this spec was
 * authored for cipher X." Without it, loading a non-AES spec into a
 * recipient defaulted to AES-128 left the cipher selector mismatched
 * with the spec — DES (8-byte block) loaded against an AES-128 default
 * key field (16 bytes) immediately erred with "expected 8 bytes."
 *
 * The hint is OPTIONAL so v1/v2 documents from before this field landed
 * still load — pre-hint behavior (no selector change on load) is the
 * absent-field fallback. When present, `setSpecFromDocument` reads it
 * and flips the cipher selector; it also adjusts `cipherMode` to
 * `"single-block"` if the current mode isn't supported for the loaded
 * cipher (e.g. switching from AES-128/ecb to DES, which is single-block
 * only).
 *
 * Why a top-level field vs. always including a session: the existing
 * "include session" toggle protects users from leaking plaintext bytes
 * into shareable URLs. The cipher selector value isn't sensitive — it's
 * just metadata about which cipher the spec implements — so it belongs
 * at the document root, not inside the session.
 */
export type CipherDocument = {
  readonly schemaVersion: typeof CURRENT_SCHEMA_VERSION;
  readonly spec: CipherSpec;
  readonly cipher?: Cipher;
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

  // Phase 2: schemaVersion pre-check + migration. A document with a
  // numeric `schemaVersion` that the app doesn't accept gets a
  // forward/backward-compat error; an accepted older version gets
  // migrated forward to `CURRENT_SCHEMA_VERSION` before schema
  // validation.
  if (raw !== null && typeof raw === "object" && !Array.isArray(raw)) {
    const sv = (raw as { schemaVersion?: unknown }).schemaVersion;
    if (typeof sv === "number") {
      if (!ACCEPTED_SCHEMA_VERSIONS.includes(sv)) {
        return {
          ok: false,
          error: `schemaVersion ${sv} is not supported (this app reads versions ${ACCEPTED_SCHEMA_VERSIONS.join(", ")}; the file may be from a different app version)`,
        };
      }
      if (sv !== CURRENT_SCHEMA_VERSION) {
        // `migrateDocument` walks v1 → v2 → ... → CURRENT, applying
        // any per-version transforms. v1 → v2 is a pure version bump
        // since v1 documents cannot contain `feistel-round` nodes.
        raw = migrateDocument(raw as Record<string, unknown>, sv);
      }
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
 * Migrate a document object forward from `fromVersion` to
 * `CURRENT_SCHEMA_VERSION`. Pure: returns a new object; never mutates
 * the input.
 *
 * **v1 → v2 migration** (Phase 4 of `docs/plans/des-feistel.md`): pure
 * version bump. v1 documents predate DES being in the cipher selector,
 * so they cannot contain any `feistel-round` nodes — the StepNode union
 * was already widened to accept feistel-round in Phase 2 of the plan,
 * `CipherDocumentSchema` accepts the wider union under either version.
 * The only thing the migration does is rewrite the `schemaVersion`
 * field so the post-bump literal validation passes.
 *
 * Future migrations chain here: a v2 → v3 step would land alongside
 * the v1 → v2 step, and a v1 document would walk through both.
 */
const migrateDocument = (
  doc: Record<string, unknown>,
  fromVersion: number,
): Record<string, unknown> => {
  // Spread to a fresh object so the caller's input isn't mutated.
  // Forward-compat: if `fromVersion` < 2, bump the field to 2. Future
  // chained migrations would add their own conditionals here.
  let migrated: Record<string, unknown> = { ...doc };
  if (fromVersion === 1) {
    migrated = { ...migrated, schemaVersion: 2 };
  }
  return migrated;
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
