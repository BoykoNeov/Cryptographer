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

import type { Asymmetric, Cipher, Hash, Lattice, Prng } from "@/ui/stores/cipher";
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
  // Blowfish — `docs/plans/blowfish.md`. Single fixed variant; the tuple entry
  // is what satisfies the `assertCipherCoverage` exhaustiveness check against
  // the `Cipher` union in `ui/stores/cipher.ts`.
  "blowfish",
  // ChaCha20 — `docs/plans/fluffy-orbiting-shannon.md`. The first stream
  // cipher, and the first entry here whose only supported mode is "stream";
  // same exhaustiveness-check role as the entries above.
  "chacha20",
  "salsa20",
  // Twofish — `docs/plans/twofish.md`. Single fixed 128-bit variant; same
  // exhaustiveness-check role as the entries above.
  "twofish",
] as const satisfies readonly Cipher[];

/**
 * Hash variants — Slice 2.10b of `docs/plans/universal-port-dataflow.md`.
 * SHA-256 is the first member; SHA-3 / SHA-512 / MAC / KDF growth extends
 * this tuple when those variants land. The compile-time check
 * `assertHashCoverage` below pins it against the `Hash` union in
 * `ui/stores/cipher.ts` so a future addition surfaces here at `tsc` time.
 */
export const HASH_IDS = [
  "sha-256",
  "sha3-256",
  "shake128",
  "shake256",
  "cshake128",
  "cshake256",
  "kmac128",
  "kmac256",
  "kmacxof128",
  "kmacxof256",
] as const satisfies readonly Hash[];

/**
 * Asymmetric (public-key) variants — `docs/plans/shimmying-booping-moth.md`.
 * RSA is the first member. `assertAsymmetricCoverage` below pins it against
 * the `Asymmetric` union in `ui/stores/cipher.ts`.
 */
export const ASYMMETRIC_IDS = ["rsa"] as const satisfies readonly Asymmetric[];

/**
 * Pseudo-random generator variants — `docs/plans/iterative-dancing-ocean.md`.
 * `assertPrngCoverage` below pins this against the `Prng` union in
 * `ui/stores/cipher.ts`.
 */
export const PRNG_IDS = [
  "minstd-rand0",
  "minstd-rand",
  "ansi-c-lcg",
  "mt19937",
  "chacha20-csprng",
] as const satisfies readonly Prng[];

/**
 * Lattice variants — `docs/plans/unified-stargazing-quasar.md`. The
 * number-theoretic transform is the first member. `assertLatticeCoverage` below
 * pins this against the `Lattice` union in `ui/stores/cipher.ts`.
 */
export const LATTICE_IDS = ["ntt-3329-256"] as const satisfies readonly Lattice[];

/**
 * Concatenation of cipher + hash + asymmetric + prng + lattice ids. Used by the top-level
 * document's `algorithm` field, which accepts any cryptographic-primitive
 * family. Composed at the tuple level so the `z.enum(ALGORITHM_IDS)` below
 * stays a static-enum schema rather than a runtime union — so a saved RSA
 * document's `algorithm: "rsa"` hint round-trips through validation.
 *
 * **Widening this list does NOT bump `schemaVersion`.** Per `docs/versioning.md`
 * the bump triggers are about wrapper-layer FIELDS (added, removed, or changed
 * in meaning), not about a field gaining new legal values. Adding a family here
 * is the same shape of change RSA made at v3 without a bump. The only
 * consequence is forward-compat — an older build rejects a document naming an
 * algorithm it has never heard of — which is the intended behaviour, and is
 * reported by the existing friendly enum error rather than a silent misparse.
 */
export const ALGORITHM_IDS = [
  ...CIPHER_IDS,
  ...HASH_IDS,
  ...ASYMMETRIC_IDS,
  ...PRNG_IDS,
  ...LATTICE_IDS,
] as const;

export const CIPHER_MODES = [
  "single-block",
  "ecb",
  "cbc",
  "ctr",
  "cfb",
  "ofb",
  // ChaCha20's mode. Not a mode of operation like the six above — a stream
  // cipher IS its own keystream rule — but it rides the same axis so that
  // padding-disengagement and IV presence fall out of the existing predicates.
  "stream",
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
type MissingHash = Exclude<Hash, (typeof HASH_IDS)[number]>;
type MissingAsymmetric = Exclude<Asymmetric, (typeof ASYMMETRIC_IDS)[number]>;
type MissingPrng = Exclude<Prng, (typeof PRNG_IDS)[number]>;
type MissingLattice = Exclude<Lattice, (typeof LATTICE_IDS)[number]>;
export const assertCipherCoverage: [MissingCipher] extends [never] ? true : never = true;
export const assertCipherModeCoverage: [MissingCipherMode] extends [never] ? true : never = true;
export const assertPaddingCoverage: [MissingPaddingScheme] extends [never] ? true : never = true;
export const assertHashCoverage: [MissingHash] extends [never] ? true : never = true;
export const assertAsymmetricCoverage: [MissingAsymmetric] extends [never] ? true : never = true;
export const assertPrngCoverage: [MissingPrng] extends [never] ? true : never = true;
export const assertLatticeCoverage: [MissingLattice] extends [never] ? true : never = true;

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

export const StateShapeSchema = z.enum(["bytes", "matrix4x4-bytes"]);

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

// PortBinding (universal-port plan Phase 2 Slice 2.6a). Sink-side edge
// wiring for port-native leaves. Both fields required — a partial binding
// is meaningless. Validated structurally here; reference-resolution
// (target node exists, target port exists on that node) lives in the
// spec-shapes validator + runtime, NOT here, to keep schema validation
// purely structural and to give the user a graph-warning surface in
// the editor before Run.
export const PortBindingSchema = z.object({
  node: z.string(),
  port: z.string(),
});

// Slice 2.8 (2026-05-26) — `narrationOverride: StepDocumentation` on
// spec leaves carries cipher-specific prose that shadows the registry's
// generic doc. The Slice 1.10 foundation added the field to
// `core/types.ts` but did not extend the document Zod schema; Slice 2.8
// is the first shipped use (SHA-256 spec), so the schema gains the
// override here.
//
// **Why these four fields only.** `StepDocumentation` also has optional
// `params: ReadonlyMap<string, string>` and `shapeContract:
// StepShapeContract`. Both are reserved for future use and not present
// on any shipped override; modeling them would require either a Map
// transformer (params doesn't JSON.stringify natively — Map produces
// `{}` with no enumerable own keys) or pulling the StateShape union
// into the schema. Deferred until a real consumer ships.
//
// **Strict (default Zod) `.object()`** — additional fields on a future
// override would be silently stripped on the parse path. Acceptable
// for now: this slice's overrides only use these four fields. Bump
// schemaVersion when a future override needs more.
export const StepDocumentationSchema = z.object({
  name: z.string(),
  summary: z.string(),
  detail: z.string(),
  references: z.array(z.string()).optional(),
});

export const StepLeafSchema = z.object({
  kind: z.literal("step"),
  id: z.string(),
  type: z.string(),
  params: JsonSchema,
  // Slice 2.6a — optional sink-side port-edge wiring. Record-shaped so
  // it serializes to JSON natively (Map keys would need a custom Zod
  // transformer). At runtime the leaf reads this via Object.entries.
  portInputs: z.record(z.string(), PortBindingSchema).optional(),
  // Slice 2.8 — per-leaf cipher-specific narration override (see above).
  narrationOverride: StepDocumentationSchema.optional(),
});

// Shared Slice 2.6a container port-edge wiring fields. Every container
// kind below gets these; the runtime publishes container exit-state
// bytes to the parent scope's nodeOutputs under each declared
// outputPorts entry (default `["out"]` when absent). See `StepGroup`
// in `core/types.ts` for the full semantics.
//
// `defaultCollapsed` (Slice 2.6d follow-up, 2026-05-25) is the author-
// declared default-collapse signal — see the doc comment on
// `StepGroup.defaultCollapsed` in `core/types.ts`. Folded into the
// shared container fields so every container kind (group, iterate,
// feistel-round, for-each-subgraph, for-each-subgraph-with-history)
// validates the optional field identically. Spec-level addition — no
// schemaVersion bump (CipherSpecSchema is loose by default, so older
// readers ignore the field on docs that lack it).
const containerPortEdgeFields = {
  portInputs: z.record(z.string(), PortBindingSchema).optional(),
  outputPorts: z.array(z.string()).optional(),
  defaultCollapsed: z.boolean().optional(),
};

// Container port contract (scaffolding-suppression A2 + A3b). `seedInput` /
// `bodyOutput` name the byte sources that the containers used to move through
// `state` via `bytes-to-state@1` bridge leaves. Declared explicitly (NOT left
// to the loose CipherSpec object) because per-kind container schemas are
// default `z.object()` which STRIPS undeclared keys — the same gotcha
// `cipherConstants` hit in A1; without this the wiring would silently vanish
// on save/load round-trip. A2 spread these into the three looping containers;
// A3b extends them to plain `group` too (a single body walk, no iteration —
// SHA-256's compression rounds carry port-to-port through `seedInput`/
// `bodyOutput`). `feistel-round` still omits them (its branch tracks have
// their own contract). Additive within schemaVersion 3 — no bump, same
// posture as `cipherConstants` and the other container fields; see
// `document.ts` for the deliberate decision.
const loopingContainerSeedFields = {
  seedInput: PortBindingSchema.optional(),
  bodyOutput: PortBindingSchema.optional(),
};

export const StepGroupSchema = z.object({
  kind: z.literal("group"),
  id: z.string(),
  label: z.string(),
  children: z.array(z.lazy(() => StepNodeSchema)),
  ...containerPortEdgeFields,
  ...loopingContainerSeedFields,
});

export const IterateGroupSchema = z.object({
  kind: z.literal("iterate"),
  id: z.string(),
  // `label` is optional in the TS contract — `.optional()` accepts the
  // key being absent (the serialized form omits undefined values).
  label: z.string().optional(),
  // Aux mode (legacy matrix CBC/CTR) — required there, absent in port mode
  // (byte-native ECB, scaffolding-suppression B1.4) where `seedInput` +
  // `blockByteLength` + `bodyOutput` drive the loop instead.
  countFromAux: z.string().optional(),
  blocksFromAux: z.string().optional(),
  outBlocksAux: z.string().optional(),
  // Port mode — block split width (16 for AES). Required when `seedInput` set.
  blockByteLength: z.number().int().positive().optional(),
  // Cross-iteration feedback (B1.4b — byte-native CBC). `chainInput` (parent
  // scope, the IV) + `chainFeedback` (body scope, per-iteration carry). Both
  // optional + both-or-neither at runtime; declared so they survive Save/Load
  // (Zod strips undeclared keys — same gotcha as `seedInput`/`cipherConstants`).
  chainInput: PortBindingSchema.optional(),
  chainFeedback: PortBindingSchema.optional(),
  // Fold harvest (Slice 2.11a) — publishes the final carried chain value on
  // a named output port (the dual of `chainInput`). SHA-256 multi-block uses
  // it to read out the running hash as the digest. Additive optional (no
  // schemaVersion bump); declared so it survives Save/Load.
  chainOutput: z.string().optional(),
  // Ragged tail (2026-07-20) — CTR's stream-mode relaxation: the message may
  // end mid-block, so the count becomes `ceil` and the final iteration gets a
  // short `in` block. Additive optional (no schemaVersion bump); declared here
  // for the same reason as `chainInput`/`chainOutput` above — **Zod strips
  // undeclared keys**, so leaving it out would silently drop the flag on every
  // Save/Load and URL-share round-trip. That failure has no error and no
  // visual tell: a shared CTR link would simply start rejecting the partial
  // input it was built to accept. Pinned by
  // `tests/ctr-partial-block-document-roundtrip.test.ts`.
  allowPartialFinalBlock: z.boolean().optional(),
  children: z.array(z.lazy(() => StepNodeSchema)),
  ...containerPortEdgeFields,
  ...loopingContainerSeedFields,
});

// (The Feistel branching primitive's schema — `CombineKindSchema` /
// `BranchTrackSchema` / `FeistelRoundGroupSchema` — was removed in Phase 5
// Slice 5.3e with the `feistel-round` node kind. It was never released
// outside `[Unreleased]` (DES went port-native in B4 before any tag), so a
// document containing a `feistel-round` node now fails Zod validation
// (reject-at-parse) rather than parsing into a node kind the runtime no
// longer walks. No `schemaVersion` change.)

// `for-each-subgraph` spec node kind (Slice 2.0a of
// `docs/plans/universal-port-phase-2-slices.md`, widened in Slice 2.0b).
// Two modes:
//   - State-thread (Slice 2.0a): `iterationCount` set; the four item-array
//     fields all absent. First shipped consumer: SHA-256's compression.
//   - Item-array (Slice 2.0b): four fields `inputArrayPort` /
//     `outputsPort` / `blockByteLength` / `blockLayout` all set;
//     `iterationCount` absent (auto-derives from parent state length /
//     `blockByteLength`).
//
// Mode-exclusivity invariants are enforced in `core/spec-shapes.ts` AND
// at runtime, NOT here — Zod's `.refine` could cover it but the duplicate
// validator would split the error attribution between the load boundary
// and the pre-run boundary. Keep schema validation structural; reserve
// semantic checks for the validator that surfaces graph-view warnings.
//
// iterationCount accepts either a literal `number` (the common case) or
// `{ fromParam: string }` (param-form, runtime resolution deferred to the
// first param-form consumer). The schema validates both forms; the runtime
// throws on `fromParam` until Phase 2's first param-form spec lands.
//
// No `schemaVersion` bump: the StepNode discriminated union widens, but
// pre-Slice-2.0b documents (every shipped v2 doc) carry no
// `for-each-subgraph` node and continue to validate unchanged.
const ForEachIterationCountSchema = z.union([
  z.number().int().nonnegative(),
  z.object({ fromParam: z.string() }),
]);

export const ForEachSubgraphSchema = z.object({
  kind: z.literal("for-each-subgraph"),
  id: z.string(),
  label: z.string().optional(),
  children: z.array(z.lazy(() => StepNodeSchema)),
  iterationCount: ForEachIterationCountSchema.optional(),
  inputArrayPort: z.string().optional(),
  outputsPort: z.string().optional(),
  blockByteLength: z.number().int().positive().optional(),
  blockLayout: StateShapeSchema.optional(),
  ...containerPortEdgeFields,
  ...loopingContainerSeedFields,
});

// `for-each-subgraph-with-history` spec node kind (Slice 2.0c of
// `docs/plans/universal-port-phase-2-slices.md`). Per-iteration lookback
// primitive — body reads named priors from a runtime-maintained history
// buffer via `aux["prior-{N}"]`. Sibling node kind to `for-each-subgraph`
// (NOT a third mode) per Q2 user pick 2026-05-24: keeps each kind's
// invariant block local rather than multiplying the mode-discriminator
// matrix.
//
// `iterationCount` is REQUIRED (unlike for-each-subgraph where it's
// optional because item-array mode auto-derives it). No item-array
// equivalent here — the data fed into the body comes from lookback aux
// reads, not a sliced input array. `historyEntryByteLength` is also
// required (drives three shape invariants enforced at runtime).
//
// `lookbackOffsets` must be non-empty with all positive integers; the
// runtime enforces this too. Schema validates structurally — every
// number must be a positive integer — and leaves the "non-empty" check
// (the more illuminating error) to the runtime, mirroring the
// for-each-subgraph posture.
//
// No schemaVersion bump: pre-Slice-2.0c documents carry no node of this
// kind and validate unchanged through the widened discriminated union.
export const ForEachSubgraphWithHistorySchema = z.object({
  kind: z.literal("for-each-subgraph-with-history"),
  id: z.string(),
  label: z.string().optional(),
  children: z.array(z.lazy(() => StepNodeSchema)),
  iterationCount: ForEachIterationCountSchema,
  lookbackOffsets: z.array(z.number().int().positive()),
  historyEntryByteLength: z.number().int().positive(),
  ...containerPortEdgeFields,
  ...loopingContainerSeedFields,
  // Container-to-scratchpad output (scaffolding-suppression A3a). Names the
  // aux key the runtime publishes the full history into at exit, retiring
  // the `state-to-aux-bytes` "publish" bridge. Declared only here (the type
  // adds `outputAux` to `ForEachSubgraphWithHistoryNode` alone, not the
  // other looping kinds); Zod strips undeclared keys, so this is required
  // for the field to survive round-trip. Additive within schemaVersion 3.
  outputAux: z.string().optional(),
});

// Note on `schemaVersion`: Phase 4 of `docs/plans/des-feistel.md` bumped
// the literal to 2 when DES entered the cipher selector. Slice 2.10b of
// `docs/plans/universal-port-dataflow.md` (2026-05-25) bumped it again
// to 3 when the top-level cipher-hint field was renamed `cipher` →
// `algorithm` (widened from `Cipher` to `Algorithm = Cipher | Hash`)
// to support SHA-256 in the save/load surface. Backwards compatibility
// for v1/v2 docs (`.cipher.json` files + URL-share links from prior
// sessions) is preserved via `migrateDocument` in `document.ts`, which
// applies the version bump AND the field rename before schema
// validation.
export const StepNodeSchema: z.ZodTypeAny = z.discriminatedUnion("kind", [
  StepLeafSchema,
  StepGroupSchema,
  IterateGroupSchema,
  ForEachSubgraphSchema,
  ForEachSubgraphWithHistorySchema,
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
  // Published cipher constants (scaffolding-suppression A1). Serialized as
  // hex byte-pairs — `document.ts` encodes the runtime `Uint8Array` form to
  // hex on save and decodes back on load. Additive within schemaVersion 3
  // (legacy specs omit it). Declared explicitly (not just left to the
  // loose object) because Zod STRIPS undeclared keys, which would silently
  // drop the constants on round-trip.
  cipherConstants: z
    .record(
      z.string().regex(/^([0-9a-fA-F]{2})*$/, "cipherConstants values must be hex byte pairs"),
    )
    .optional(),
  // Cipher exit port (scaffolding-suppression A3a). Names the port whose
  // bytes become `finalState`, retiring the terminal `bytes-to-state@1`
  // bridge. Declared explicitly (Zod strips undeclared keys — same gotcha
  // as `cipherConstants`); additive within schemaVersion 3, no bump.
  outputFrom: PortBindingSchema.optional(),
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
    // Explicit user-expansion override for containers that the spec
    // declares `defaultCollapsed: true` (Slice 2.6d follow-up,
    // 2026-05-25). Effective collapsed set =
    //   (spec defaults ∪ collapsedGroups) − expandedGroups.
    // Additive optional field; older readers tolerate the absence,
    // newer docs ride through. Precedent for "additive optional on
    // .strict() LayoutSpec without schemaVersion bump" is
    // `relativePositions` (2026-05-19). Empty array is never
    // serialized — see `layout.ts::buildLayoutSpec`.
    expandedGroups: z.array(z.string()).optional(),
    // Per-source stroke-style overrides (Part A of the graph-legibility
    // plan, 2026-07-09). Canonical source id → stroke-style name (from
    // `source-strokes.ts`). Kept a permissive `z.record(z.string())` — NOT
    // an enum of the 24 catalogue names — so a document written by a future,
    // larger catalogue opens on an older build without hard-failing (the
    // renderer falls back to `solid` for unrecognised names). Additive
    // optional field; its position is pinned for byte-stability (insertion
    // order), so a newer optional appends AFTER it rather than displacing it.
    // No schemaVersion bump — same precedent as `expandedGroups` /
    // `relativePositions`. Empty map is never serialized (see
    // `layout.ts::buildLayoutSpec`).
    strokeStyles: z.record(z.string()).optional(),
    // Container ids whose squeezed header label the user clicked to render
    // at natural width ("Option B", V2 of the 2026-05-13 label-truncation
    // work). Additive optional field; MUST stay last for byte-stability.
    // No schemaVersion bump — same precedent as every optional above it.
    // Empty array is never serialized (see `layout.ts::buildLayoutSpec`).
    expandedLabels: z.array(z.string()).optional(),
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
    schemaVersion: z.literal(3),
    spec: CipherSpecSchema,
    // Algorithm selector hint (Phase 6e of `docs/plans/des-feistel.md`,
    // widened in Slice 2.10b of `docs/plans/universal-port-dataflow.md`
    // from `cipher: Cipher` to `algorithm: Algorithm`). See the comment
    // on `CipherDocument` in `document.ts` for the why. Optional so
    // documents authored before this field landed still validate; the
    // v2 → v3 migration renames `cipher` → `algorithm` for older docs.
    algorithm: z.enum(ALGORITHM_IDS).optional(),
    layout: LayoutSpecSchema.optional(),
    session: SessionSnapshotSchema.optional(),
    metadata: DocumentMetadataSchema.optional(),
  })
  .strict();
