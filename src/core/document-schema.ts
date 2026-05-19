/**
 * Zod schemas for the CipherDocument file format (Slice 3 of the 2D editor
 * plan). Validation-only: the public TS types live in `document.ts` so the
 * surface uses our project-wide `exactOptionalPropertyTypes`-aware
 * `field?: T` shape rather than Zod's inferred `field?: T | undefined`.
 *
 * Strictness split:
 *   • Wrapper layers (CipherDocument / LayoutSpec / SessionSnapshot /
 *     DocumentMetadata) are `.strict()` — unknown fields force a
 *     `schemaVersion` bump rather than getting silently passed through.
 *   • CipherSpec and StepNode shapes inherit Zod's default looseness so
 *     spec-level extensions can land without forcing a migration. They
 *     mirror the contracts in `core/types.ts`, which the project declares
 *     "load-bearing forever."
 *
 * The cipher / cipherMode / padding / byteFormat enum tuples are mirrored
 * from `ui/stores/*` with type-only imports + a compile-time `Exclude`
 * coverage check, so adding a new variant to those unions surfaces here at
 * `tsc` time. Type-only imports get erased — this file does NOT pull
 * solid-js into the core layer.
 *
 * StepNode is intentionally validated via `z.discriminatedUnion` for
 * pinpoint error paths ("steps.3.kind: invalid discriminator value" beats
 * Zod's union fallback "matched 0 of 3 options"). Recursion is handled by
 * `z.lazy` at the children-array site rather than at the union itself —
 * that lets each per-kind ZodObject keep its concrete type so it satisfies
 * `z.discriminatedUnion`'s per-option constraint without explicit casts.
 */

import type { Cipher } from "@/ui/stores/cipher";
import type { CipherMode } from "@/ui/stores/cipher-mode";
import { z } from "zod";
import { ALL_BYTE_FORMATS } from "./format";
import type { ByteFormat } from "./format";
import type { PaddingScheme } from "./spec-mutations";
import type { Json } from "./types";

// ─── Cipher / mode / padding enums ────────────────────────────────────────
// Listed as `as const` tuples so Zod's `z.enum(...)` accepts them. The
// `satisfies readonly Cipher[]` lower-bound check ensures every literal is
// a valid Cipher; the `Exclude<...>` upper-bound check (below) ensures the
// tuple covers every Cipher value. Together they pin both directions.

export const CIPHER_IDS = [
  "aes-128",
  "aes-192",
  "aes-256",
  "speck-32-64-be",
  "speck-32-64-le",
  "serpent-128",
  "serpent-192",
  "serpent-256",
  // DES — Phase 4 of `docs/plans/des-feistel.md`. Single-block only; the
  // tuple change here is what passes the compile-time exhaustiveness check
  // `assertCipherCoverage` against the `Cipher` union in `ui/stores/cipher.ts`.
  "des",
] as const satisfies readonly Cipher[];

export const CIPHER_MODES = [
  "single-block",
  "ecb",
  "cbc",
  "ctr",
] as const satisfies readonly CipherMode[];

export const PADDING_SCHEMES = [
  "none",
  "pkcs7",
  "zero-pad",
  "iso7816-4",
] as const satisfies readonly PaddingScheme[];

export const BYTE_FORMATS = ALL_BYTE_FORMATS as readonly ByteFormat[];

// Compile-time exhaustiveness: if a new Cipher variant lands in
// `ui/stores/cipher.ts` and the author forgets to add it to `CIPHER_IDS`,
// `MissingCipher` becomes a non-`never` union and `assertCipherCoverage`
// fails to typecheck. Same for cipherMode + padding. The assertions are
// `export`ed so `noUnusedLocals` doesn't flag them (TypeScript exempts
// exported declarations from the unused check; nothing actually imports
// these — they exist purely for the type-level check).
type MissingCipher = Exclude<Cipher, (typeof CIPHER_IDS)[number]>;
type MissingCipherMode = Exclude<CipherMode, (typeof CIPHER_MODES)[number]>;
type MissingPaddingScheme = Exclude<PaddingScheme, (typeof PADDING_SCHEMES)[number]>;
export const assertCipherCoverage: [MissingCipher] extends [never] ? true : never = true;
export const assertCipherModeCoverage: [MissingCipherMode] extends [never] ? true : never = true;
export const assertPaddingCoverage: [MissingPaddingScheme] extends [never] ? true : never = true;

// ─── Json (recursive) ─────────────────────────────────────────────────────
// Mirrors the `Json` type in core/types.ts. `z.lazy` is the standard
// pattern for self-referential Zod schemas; the explicit `z.ZodType<Json>`
// annotation is required because TS can't infer recursive types.

export const JsonSchema: z.ZodType<Json> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.number(),
    z.string(),
    z.array(JsonSchema),
    z.record(JsonSchema),
  ]),
);

// ─── StateShape ───────────────────────────────────────────────────────────

export const StateShapeSchema = z.enum(["bytes", "matrix4x4-bytes", "bitvec", "bigint"]);

// ─── StepNode (recursive discriminated union) ─────────────────────────────
// Each per-kind schema stays a concrete `z.object(...)` so it satisfies
// `z.discriminatedUnion`'s per-option constraint without any `as` casts.
// Recursion lives in the `children` fields via `z.lazy(() => StepNodeSchema)`
// — block-scoped consts work inside lambda bodies because the lambda only
// fires at parse time, after the module's top-level evaluation has
// reached the StepNodeSchema declaration below.
//
// `StepNodeSchema: z.ZodTypeAny` is the deliberate "break the circular
// inference" anchor. The schema STILL validates the right shape at
// runtime; we only lose static `z.infer<...>` precision at use sites,
// which doesn't matter — `document.ts` casts `result.data` to the
// hand-written `CipherDocument` after `safeParse` anyway.

export const StepLeafSchema = z.object({
  kind: z.literal("step"),
  id: z.string(),
  type: z.string(),
  params: JsonSchema,
});

export const StepGroupSchema = z.object({
  kind: z.literal("group"),
  id: z.string(),
  label: z.string(),
  children: z.array(z.lazy(() => StepNodeSchema)),
});

export const IterateGroupSchema = z.object({
  kind: z.literal("iterate"),
  id: z.string(),
  // `label` is optional in the TS contract — `.optional()` accepts the
  // key being absent (the serialized form omits undefined values).
  label: z.string().optional(),
  countFromAux: z.string(),
  blocksFromAux: z.string(),
  outBlocksAux: z.string(),
  children: z.array(z.lazy(() => StepNodeSchema)),
});

// Feistel branching primitive (Phase 2 of `docs/plans/des-feistel.md`).
// The CombineKind union is mirrored as a `z.enum` so adding a new kind
// surfaces a literal compile error here once the TS union widens. Keep the
// list in sync with `core/types.ts::CombineKind`.
export const CombineKindSchema = z.enum([
  "feistel-standard",
  "feistel-no-swap",
  "feistel-add-into-left",
  "feistel-add-into-right",
]);

export const BranchTrackSchema = z.object({
  name: z.string().optional(),
  inputBytes: z.array(z.number().int().nonnegative()),
  children: z.array(z.lazy(() => StepNodeSchema)),
});

export const FeistelRoundGroupSchema = z.object({
  kind: z.literal("feistel-round"),
  id: z.string(),
  label: z.string().optional(),
  tracks: z.array(BranchTrackSchema),
  combineKind: CombineKindSchema,
});

// Note on `schemaVersion`: Phase 4 of `docs/plans/des-feistel.md` bumped
// the literal to 2 when DES entered the cipher selector. The StepNode
// union was already widened to accept feistel-round in Phase 2 (so the
// schema can validate documents at either version); only the top-level
// `schemaVersion` literal flips. Backwards compatibility for v1 docs
// (AES `.cipher.json` files + URL-share links from prior sessions) is
// preserved via `migrateDocument` in `document.ts`, which bumps the
// version field before schema validation.
export const StepNodeSchema: z.ZodTypeAny = z.discriminatedUnion("kind", [
  StepLeafSchema,
  StepGroupSchema,
  IterateGroupSchema,
  FeistelRoundGroupSchema,
]);

// ─── CipherSpec ───────────────────────────────────────────────────────────
// Mirrors `core/types.ts::CipherSpec`. Loose by default (no `.strict()`) so
// future spec-level fields can land without forcing a schemaVersion bump.

export const CipherSpecSchema = z.object({
  id: z.string(),
  name: z.string(),
  stateShape: StateShapeSchema,
  inputs: z.object({
    plaintext: z.object({ shape: StateShapeSchema }),
    key: z.object({ byteLength: z.number().int().nonnegative() }),
  }),
  steps: z.array(StepNodeSchema),
});

// ─── LayoutSpec ───────────────────────────────────────────────────────────
// Sidecar layout data. `.strict()` so accidental extra keys (e.g. a future
// "ttb" / vertical layout adding new fields) force a schemaVersion bump.

const PositionSchema = z
  .object({
    x: z.number(),
    y: z.number(),
  })
  .strict();

// Per-source override for the replication transform. Plain object
// (`{ [sourceId]: "always" | "never" }`) at the JSON layer; the absence of
// an entry is the implicit `"auto"` default and is never serialized. The
// enum is closed (no `"auto"`) so a serialized doc never contains
// redundant defaults — keeps the byte-stability gate clean.
const ReplicationModeSchema = z.enum(["always", "never"]);

// Per-node relative offset (delta from auto-laid position). Used for
// synthetic ids like aux replicas and block chips whose anchor follows
// another node. See `RelativePosition` in `document.ts` and
// `docs/plans/draggable-replicas.md`.
const RelativePositionSchema = z
  .object({
    dx: z.number(),
    dy: z.number(),
  })
  .strict();

export const LayoutSpecSchema = z
  .object({
    positions: z.record(PositionSchema),
    collapsedGroups: z.array(z.string()),
    flowDirection: z.literal("ltr"),
    replicationModes: z.record(ReplicationModeSchema).optional(),
    relativePositions: z.record(RelativePositionSchema).optional(),
  })
  .strict();

// ─── SessionSnapshot ──────────────────────────────────────────────────────
// User's exploration session: which selectors were set, optional plaintext
// + key bytes. `inputBytes` / `keyBytes` are `number[]` rather than
// `Uint8Array` so they survive JSON.stringify (Uint8Array serializes to an
// object-shape `{ "0": ..., ... }` — useless).

export const SessionSnapshotSchema = z
  .object({
    mode: z.enum(["encrypt", "decrypt"]),
    cipher: z.enum(CIPHER_IDS),
    cipherMode: z.enum(CIPHER_MODES),
    padding: z.enum(PADDING_SCHEMES),
    byteFormat: z.enum(["hex", "decimal", "ascii"]),
    inputBytes: z.array(z.number().int().min(0).max(255)).optional(),
    keyBytes: z.array(z.number().int().min(0).max(255)).optional(),
    // IV bytes — written by the App when the saved session was in CBC
    // (and, in future phases, CFB/OFB/CTR). Strictly 16 bytes when
    // present; absent for single-block / ECB sessions. Optional so
    // pre-Phase-2 documents (no ivBytes field) still validate.
    ivBytes: z.array(z.number().int().min(0).max(255)).length(16).optional(),
  })
  .strict();

// ─── DocumentMetadata ─────────────────────────────────────────────────────

export const DocumentMetadataSchema = z
  .object({
    name: z.string().optional(),
    createdAt: z.number().optional(),
    appVersion: z.string().optional(),
  })
  .strict();

// ─── CipherDocument (top level) ───────────────────────────────────────────
// `schemaVersion: z.literal(2)` does the structural validation. The
// friendlier "this app reads versions ..." error for cross-version files
// lives in `document.ts::parseDocument` as a pre-check, which also
// applies the v1 → v2 migration so older documents validate cleanly.

export const CipherDocumentSchema = z
  .object({
    schemaVersion: z.literal(2),
    spec: CipherSpecSchema,
    layout: LayoutSpecSchema.optional(),
    session: SessionSnapshotSchema.optional(),
    metadata: DocumentMetadataSchema.optional(),
  })
  .strict();
