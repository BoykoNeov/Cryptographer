/**
 * Step-narration registry. Cipher-agnostic surface for per-frame
 * *value-prose* — "what just happened to THESE specific bytes in THIS
 * frame" — rendered by `<StepNarration />` in linear mode below the
 * port-flow inspector.
 *
 * Architectural decision: this is a *separate* registry from the core
 * step registry, NOT a new field on `StepDocumentation`. The two
 * registries answer two different questions:
 *
 *   - Core step registry (`src/core/registry.ts`) — runtime:
 *     "how does this step execute? what does its doc panel say?"
 *   - Narration registry (THIS file) — pedagogy:
 *     "for this frame, what's a learner-friendly per-conceptual-unit
 *      breakdown of the transformation?"
 *
 * (A third, parallel *provenance* registry once answered "for cell
 * hover, which cells feed which output cell?" — it was retired in the
 * Slice 2.9c-e honest close once the value inspector / step strip /
 * RunExplorer became port-aware; see
 * `docs/plans/slice-2-9-port-aware-provenance.md`.)
 *
 * Keeping the registries separate means a runtime refactor doesn't reach
 * into pedagogy code (and vice versa). A new cipher with novel cell
 * shapes can register its own narration fn without touching the core
 * step-registration path.
 *
 * Coverage after Phase 3:
 *   - AES round body: SubBytes, ShiftRows, MixColumns, AddRoundKey.
 *   - Serpent byte-level + bit-permutation: SubBytes, AddRoundKey,
 *     Bit-Permutation (IP / FP) — the bit-permutation narrator uses
 *     the two-tier "structural overview + per-output-byte drill"
 *     pattern documented in `feedback_bit_level_narration_pattern.md`.
 *   - Speck: Round (forward), Round-inverse.
 *   - Padding: pkcs7 pad/unpad, zero pad/unpad, iso7816-4 pad/unpad.
 *   - Boundary: load-block, store-block, split-blocks, concat-blocks,
 *     compute-block-count.
 *   - Aux primitives: aux-load, aux-xor, aux-copy, iv-load,
 *     xor-aux-into-state, state-to-aux.
 * The `NARRATION_NO_OP_ALLOWLIST` is now at its irreducible size
 * (6 entries — see the doc-string on the constant below).
 *
 * A contract test (`tests/narration-registry-contract.test.ts`) walks
 * the core registry and asserts every shipped matrix-shape AND
 * bytes-shape step type EITHER has a narration fn here OR sits on the
 * explicit allowlist. So a future cipher addition can't silently slip
 * past with no narration support.
 *
 * ## Authoring conventions
 *
 * - **Per-conceptual-unit `<details>`** — match the visual rhythm of
 *   `KeyScheduleExplorer`'s `.key-schedule-aes-stage` rows. ShiftRows
 *   → 4 row units. MixColumns → 4 column units. SubBytes → 16 byte
 *   units. AddRoundKey → 16 cell units. Speck round → 3 ARX sub-ops.
 *   AVOID per-byte disclosure on large states (a future SHAKE / Keccak
 *   step on a 200-byte state must NOT emit 200 `<details>` — pick a
 *   coarser conceptual unit or land it on the allowlist with reason).
 *
 * - **`Prose` is a Component, not bare JSX.** This is what keeps
 *   `<details>` `open` state alive across the byte-format toggle. The
 *   builder closure captures frame bytes once; only `fmt` propagates
 *   reactively into each Prose body. See the rationale at
 *   `src/ui/components/KeyScheduleExplorer.tsx:295-304`.
 *
 * - **Return `null` for "decline to narrate this frame"** — wrong-shape
 *   params, missing aux. The component then renders nothing for that
 *   frame. The contract test still requires either registration or an
 *   allowlist entry; returning `null` doesn't substitute for registry
 *   absence.
 */

import type { ByteFormat } from "@/core/format";
import type { TraceFrame } from "@/core/types";
import type { Component } from "solid-js";

/**
 * One disclosable unit of a step's narration. The user sees `label` in
 * the `<summary>`; expanding the `<details>` renders `<Prose fmt={...} />`
 * in the body.
 *
 * `Prose` is a Component (not a JSX expression) so the format toggle
 * surgically updates byte text inside the open body without recreating
 * the parent `<details>` element. If we passed JSX directly, every
 * format toggle would rebuild the unit array (because reading `fmt`
 * lives outside the Prose component) and snap every open disclosure
 * shut — bad UX.
 */
export type NarrationUnit = {
  /**
   * Stable key for `<For each={...}>`. Used as `data-key` on the
   * `<details>` element so tests can assert by stable identity. Must
   * be unique within one narration's unit list. Convention:
   * `"<step-kind>:<index>"` — e.g. `"byte:5"`, `"row:1"`, `"col:2"`.
   */
  readonly key: string;
  /** `<summary>` text — short, scannable. Example: `"byte 5 (row 1, col 1)"`. */
  readonly label: string;
  /** Body component. Receives the current byte format reactively. */
  readonly Prose: Component<{ readonly fmt: ByteFormat }>;
};

/**
 * Per-step narration builder. Runs once per frame swap; the returned
 * Prose components close over frame-derived values (before/after bytes,
 * params, aux snapshots).
 *
 * Returning `null` means "decline to narrate this specific frame" —
 * e.g. params were malformed, required aux was missing. The component
 * renders nothing in that case. This is distinct from "no narration
 * registered for this step type" (which is what `lookupNarration`
 * returning `null` means — the allowlist contract still applies).
 */
export type NarrationFn = (frame: TraceFrame) => readonly NarrationUnit[] | null;

const REGISTRY = new Map<string, NarrationFn>();

/**
 * Register a narration function for a step type. Throws on duplicate
 * registration so the contract test catches accidental double-registers
 * (the same accident that would shadow one cipher's fn with another).
 */
export const registerNarration = (stepType: string, fn: NarrationFn): void => {
  if (REGISTRY.has(stepType)) {
    throw new Error(`narration: step type "${stepType}" is already registered`);
  }
  REGISTRY.set(stepType, fn);
};

/**
 * Look up a narration function. Returns null when none is registered —
 * the component renders nothing in that case. The contract test
 * enforces that every cell-shape step type is either registered here
 * or on the allowlist.
 */
export const lookupNarration = (stepType: string): NarrationFn | null =>
  REGISTRY.get(stepType) ?? null;

/** Predicate variant of the lookup. O(1). */
export const hasNarrationFn = (stepType: string): boolean => REGISTRY.has(stepType);

/**
 * Step types that *intentionally* have no narration fn. After Phase 3 the
 * list is at its irreducible 6 entries — 4 key-expansion step types
 * (covered by `<KeyScheduleExplorer />` with much richer per-stage
 * narration than the unit-list this registry produces) plus the
 * 2 bit-level Serpent linear transforms (where byte-level prose would
 * mislead — see below).
 *
 * Reasons for the irreducible set:
 *
 *   - **Serpent key expansion** (`serpent.key-expansion@1`) — covered by
 *     `<KeyScheduleExplorer />` with much richer per-stage narration than the
 *     unit-list this registry produces. Narrating it again would double up.
 *   - **AES key expansion** (`aes.key-expansion@1/@2`) — NO LONGER covered by
 *     `<KeyScheduleExplorer />` (its AES branch was retired in
 *     key-schedule-decomposition K1c; the RotWord/SubWord/Rcon/word-XOR steps
 *     are now real, narrated trace frames inside the decomposed `key-schedule`
 *     group). These monolithic executors are no longer used by any shipped
 *     spec — they survive registered only as the FIPS oracle for
 *     `aes-key-schedule-decomposition.test.ts` and for loading pre-K1 saved
 *     docs — so they are aux-only no-op steps with no narration to write.
 *     (Slated for deletion in a future release per `docs/versioning.md`.)
 *   - **Speck key schedule** (`speck.key-schedule@1`) — aux-only; not in
 *     `<KeyScheduleExplorer />` at all, so there is no richer surface, but the
 *     state-passthrough step has no per-frame value-prose worth a unit fn.
 *
 *   - **Bit-level Serpent linear transforms**
 *     (`serpent.linear-transform@1`, `serpent.inv-linear-transform@1`)
 *     — each output bit derives from 6–7 input bits via XOR over
 *     GF(2). Byte-level prose would be misleading ("everything
 *     contributes to everything" isn't useful). A future per-bit
 *     narration surface could cover these honestly; the byte-level
 *     registry shouldn't.
 *
 *     NOTE: `serpent.bit-permutation@1` is NOT in this category. Each
 *     output bit there comes from a *single* input bit, which makes
 *     the per-output-byte drill (8 source-bit highlights) honest and
 *     pedagogically rich. Phase 2 narrates it with the structural-
 *     overview + per-output-byte drill pattern.
 *
 * Adding an entry is a deliberate "we considered narration and it's
 * not worth a fn" — NOT "we forgot to write one." The contract test
 * enforces every step type is either registered or here.
 */
export const NARRATION_NO_OP_ALLOWLIST: ReadonlySet<string> = new Set([
  // Serpent: still covered by <KeyScheduleExplorer /> (richer surface).
  "serpent.key-expansion@1",
  // AES @1/@2: explorer AES branch retired in K1c — now unused-by-any-spec
  // aux-only no-op executors kept as FIPS oracle / pre-K1 doc back-compat.
  "aes.key-expansion@1",
  "aes.key-expansion@2",
  // Speck: aux-only schedule, not in the explorer; no per-frame value-prose.
  "speck.key-schedule@1",
  // The aux-publish tail of the DECOMPOSED AES key schedule
  // (key-schedule-decomposition K1a). An identity passthrough that mirrors the
  // round keys into aux — per-frame value-prose is the wrong surface (the
  // interesting math is the recurrence leaves above it, each of which IS
  // narrated via its `narrationOverride`).
  "aes.publish-round-keys@1",
  // Bit-level linear transforms — byte-level prose would be misleading.
  // (Bit-permutation is honest at byte granularity — narrated in Phase 2.)
  "serpent.linear-transform@1",
  "serpent.inv-linear-transform@1",
  // (The `feistel.toy-add-k@1` toy entry was removed in Phase 5 Slice 5.3e
  // when the toy step type was decommissioned with the Feistel scaffolding.)
  // `des.key-schedule@1` — covered by the future `DesKeyScheduleSimulator`
  // (Phase 5e of the plan). The per-frame narration produced by this
  // registry is the wrong surface for a multi-round PC-1 → 16 shifts →
  // PC-2 walk; the explorer view that replaces FrameStateView is the
  // right one, matching how AES and Serpent key expansions are handled.
  "des.key-schedule@1",
  // The SHA-256 coarse-granularity helpers (sha2.message-schedule-step@1 /
  // compression-round@1 / final-add@1) were retired in Phase 5 Slice 5.1
  // (2026-05-30) — the Slice 2.6d in-spec decomposition into the
  // port-native rotate/xor/and/not vocabulary superseded them, and each
  // leaf now carries its own port-native narration.
]);

/**
 * Pick the aux name a frame consumed under a single-aux step. (Was
 * shared in spirit with the retired provenance registry's helper of the
 * same name; kept local so the narration module stands alone.)
 *
 * Returns null if `auxRead` has zero or more-than-one entries.
 * AddRoundKey (forward + inverse) consumes exactly one aux per frame,
 * which is the common case.
 */
export const singleAuxNameFromFrame = (frame: TraceFrame): string | null => {
  const keys = Array.from(frame.auxRead.keys());
  return keys.length === 1 ? (keys[0] ?? null) : null;
};

/** Internal: clear the registry. Test-only. */
export const __resetNarrationForTests = (): void => {
  REGISTRY.clear();
};
