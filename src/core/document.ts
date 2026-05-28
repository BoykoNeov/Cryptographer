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

import type { Algorithm, Cipher } from "@/ui/stores/cipher";
import type { CipherMode } from "@/ui/stores/cipher-mode";
import type { Mode } from "@/ui/stores/spec";
import { CipherDocumentSchema } from "./document-schema";
import type { ByteFormat } from "./format";
import type { PaddingScheme } from "./spec-mutations";
import type { CipherSpec } from "./types";

// ─── Schema-version anchor ────────────────────────────────────────────────

/**
 * The version this app produces.
 *
 * **v1 → v2** (Phase 4 of `docs/plans/des-feistel.md`): pure version bump
 * when DES entered the cipher selector and `feistel-round` nodes became
 * representable. v1 documents cannot contain `feistel-round` nodes (DES
 * wasn't selectable), so no node-level changes are required.
 *
 * **v2 → v3** (Slice 2.10b of `docs/plans/universal-port-dataflow.md`,
 * 2026-05-25): the top-level cipher-hint field is renamed `cipher` →
 * `algorithm` and widens from `Cipher` to `Algorithm = Cipher | Hash`.
 * This is the schema change that lets SHA-256 (the first non-cipher
 * primitive) ride through the save/load surface honestly. v2 documents
 * carry `cipher: <Cipher>` which the v2 → v3 migration step renames to
 * `algorithm: <Cipher>` — the value passes through unchanged since
 * every v2 document predates the hash family. Old `.cipher.json` files
 * and URL-share links still load via `migrateDocument` below.
 *
 * **No v3 → v4 bump for the container port contract** (scaffolding-
 * suppression plan Phase A Slice A2, 2026-05-28). A2 adds optional
 * `seedInput` / `bodyOutput` `PortBinding` fields to the looping container
 * node kinds. The decision (deliberate, after weighing a 3→4 bump) is
 * **additive within schemaVersion 3**, consistent with every prior node-
 * kind/field addition (`for-each-subgraph`, `defaultCollapsed`,
 * `portInputs`, `narrationOverride`, `cipherConstants`). A bump would
 * friendly-error *unchanged-cipher* docs (AES/Speck/Serpent/DES) in old
 * apps to protect a near-nonexistent old-reader population, and the
 * reliance hazard (a spec that actually depends on the fields) only
 * arrives in A3 (SHA-256 cleanup), not A2 — at A2 no shipped spec carries
 * the fields. Old apps reading a future A3 doc would strip the unknown
 * container fields and fall back to state-seeding; we accept that
 * forward-only-degrade risk for a solo-dev, forward-evolving tool.
 */
export const CURRENT_SCHEMA_VERSION = 3 as const;

/**
 * The set of historical schema versions this app can load (after
 * applying `migrateDocument`). Used by the friendly pre-check in
 * `parseDocument` so a v3-only build still reads v1/v2 docs without
 * erroring out at "schemaVersion N is not supported."
 */
export const ACCEPTED_SCHEMA_VERSIONS: readonly number[] = [1, 2, 3];

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
  /**
   * Explicit user-expansion overrides for containers the spec marks
   * `defaultCollapsed: true` (Slice 2.6d follow-up, 2026-05-25). The
   * presence of a container id here means "the user expanded this
   * container; show it expanded even though the spec author wanted it
   * collapsed by default."
   *
   * Effective collapsed set is computed as
   *   (spec defaults ∪ collapsedGroups) − expandedGroups
   * in `core/spec-defaults.ts::getEffectiveCollapsedSet`. The two
   * persisted sets are MUTUALLY EXCLUSIVE by `toggleCollapse`'s
   * invariant: a container id never appears in BOTH at once.
   *
   * Why a second set instead of repurposing `collapsedGroups` as a
   * tri-state map: the existing presence/absence semantic on
   * `collapsedGroups` survives unchanged, every reader stays
   * monomorphic, and the byte-stability gate (`hasUserLayout`) treats
   * the new set the same way it treats `collapsedGroups` /
   * `relativePositions`. Absent / empty when no default-collapsed
   * container has been expanded by the user — same byte-stability
   * discipline as the other optional fields.
   */
  readonly expandedGroups?: readonly string[];
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
 * `algorithm` is a lightweight selector hint (Phase 6e of
 * `docs/plans/des-feistel.md`, widened from `cipher: Cipher` to
 * `algorithm: Algorithm = Cipher | Hash` in Slice 2.10b of
 * `docs/plans/universal-port-dataflow.md`). Save always emits it so a
 * spec-only .cipher.json or URL-share document tells the loader "this
 * spec was authored for algorithm X." Without it, loading a non-AES spec
 * into a recipient defaulted to AES-128 left the selector mismatched
 * with the spec — DES (8-byte block) loaded against an AES-128 default
 * key field (16 bytes) immediately erred with "expected 8 bytes."
 *
 * The hint is OPTIONAL so v1/v2/v3 documents from before this field
 * landed (or with the absent-field fallback) still load — pre-hint
 * behavior was "no selector change on load." When present,
 * `setSpecFromDocument` reads it and dispatches:
 *   - For a `Cipher` value: flips the cipher selector and adjusts
 *     `cipherMode` to `"single-block"` if the current mode isn't
 *     supported for the loaded cipher.
 *   - For a `Hash` value: constructs a `kind: "hash"` SpecsByMode with
 *     the document's spec as the single slot.
 *
 * Field naming history: `cipher` in schemaVersion 2; renamed to
 * `algorithm` in schemaVersion 3 (the rename IS the v2 → v3 migration
 * because the universe of values widened from `Cipher` to `Algorithm`).
 * `migrateDocument` handles the field rename for older documents.
 *
 * Why a top-level field vs. always including a session: the existing
 * "include session" toggle protects users from leaking plaintext bytes
 * into shareable URLs. The algorithm selector value isn't sensitive —
 * it's just metadata about which primitive the spec implements — so it
 * belongs at the document root, not inside the session.
 */
export type CipherDocument = {
  readonly schemaVersion: typeof CURRENT_SCHEMA_VERSION;
  readonly spec: CipherSpec;
  readonly algorithm?: Algorithm;
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

// ─── cipherConstants hex codec (scaffolding-suppression A1) ────────────────
// `spec.cipherConstants` holds `Uint8Array` at runtime, but JSON has no byte
// type — `JSON.stringify` would emit a typed array as `{"0":..,"1":..}` and
// `parseDocument`'s Zod schema (which validates hex strings) would reject it.
// So we hex-encode on the way out and decode on the way back in. Hex matches
// the app's byte-display convention and keeps the serialized form compact +
// byte-stable for URL-share.

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

/**
 * Return a structural clone of `doc` with `spec.cipherConstants` hex-encoded
 * (`Uint8Array` → hex string), or `doc` untouched when there are no
 * constants. The result is no longer a typed `CipherDocument` (the constants
 * are now strings), so it's typed `unknown` for the stringify path.
 */
const encodeCipherConstants = (doc: CipherDocument): unknown => {
  const constants = doc.spec.cipherConstants;
  if (!constants) return doc;
  const encoded: Record<string, string> = {};
  for (const [name, bytes] of Object.entries(constants)) encoded[name] = bytesToHex(bytes);
  return { ...doc, spec: { ...doc.spec, cipherConstants: encoded } };
};

/**
 * Inverse of `encodeCipherConstants` for the parse path: rebuild
 * `spec.cipherConstants` as `Uint8Array` from the validated hex strings.
 * Operates on the post-Zod object (where constants are `Record<string,
 * string>`); returns the object unchanged when there are no constants.
 */
const decodeCipherConstants = (data: unknown): unknown => {
  if (data === null || typeof data !== "object") return data;
  const spec = (data as { spec?: { cipherConstants?: Record<string, string> } }).spec;
  if (!spec || !spec.cipherConstants) return data;
  const decoded: Record<string, Uint8Array> = {};
  for (const [name, hex] of Object.entries(spec.cipherConstants)) decoded[name] = hexToBytes(hex);
  return { ...data, spec: { ...spec, cipherConstants: decoded } };
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
export const serializeDocument = (doc: CipherDocument): string =>
  JSON.stringify(sortKeysDeep(encodeCipherConstants(doc)));

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
  // Decode `spec.cipherConstants` hex strings back to Uint8Array (the
  // runtime form). No-op for docs without constants (every legacy doc).
  return { ok: true, doc: decodeCipherConstants(result.data) as unknown as CipherDocument };
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
 * The only thing the v1 step does is rewrite the `schemaVersion` field
 * so the chained migration can continue.
 *
 * **v2 → v3 migration** (Slice 2.10b of
 * `docs/plans/universal-port-dataflow.md`, 2026-05-25): the top-level
 * cipher-hint field is renamed `cipher` → `algorithm`. The value passes
 * through unchanged since every v2 document predates the hash family —
 * `cipher: <Cipher>` becomes `algorithm: <Cipher>` (still a valid
 * `Algorithm`). Documents with no `cipher` field (every v1 doc, plus
 * pre-Phase-6e v2 docs) simply emerge from this step still missing the
 * optional field — schema validation accepts the absence.
 *
 * Chained migrations: a v1 document walks v1 → v2 → v3 in two steps.
 * Each conditional adds its own transform; the order matters because
 * later steps may consume fields earlier steps produced.
 */
const migrateDocument = (
  doc: Record<string, unknown>,
  fromVersion: number,
): Record<string, unknown> => {
  // Spread to a fresh object so the caller's input isn't mutated.
  let migrated: Record<string, unknown> = { ...doc };

  // v1 → v2: pure version-field bump. No node-level rewriting needed.
  if (fromVersion <= 1) {
    migrated = { ...migrated, schemaVersion: 2 };
  }

  // v2 → v3: rename the cipher-hint field to algorithm. Value is
  // preserved (every v2 cipher value is still a valid Algorithm).
  // Destructured rename keeps the type of `algorithm` carrying through
  // without an explicit cast on the optional field.
  if (fromVersion <= 2) {
    const { cipher, ...rest } = migrated as { cipher?: unknown } & Record<string, unknown>;
    migrated = { ...rest, schemaVersion: 3 };
    if (cipher !== undefined) {
      migrated = { ...migrated, algorithm: cipher };
    }
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
