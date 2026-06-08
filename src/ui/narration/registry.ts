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
 * - **Per-conceptual-unit `<details>`** — one disclosure per natural
 *   sub-unit of the step. ShiftRows
 *   → 4 row units. MixColumns → 4 column units. SubBytes → 16 byte
 *   units. AddRoundKey → 16 cell units. Speck round → 3 ARX sub-ops.
 *   AVOID per-byte disclosure on large states (a future SHAKE / Keccak
 *   step on a 200-byte state must NOT emit 200 `<details>` — pick a
 *   coarser conceptual unit or land it on the allowlist with reason).
 *
 * - **`Prose` is a Component, not bare JSX.** This is what keeps
 *   `<details>` `open` state alive across the byte-format toggle. The
 *   builder closure captures frame bytes once; only `fmt` propagates
 *   reactively into each Prose body.
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
 * Step types that *intentionally* have no narration fn. The list grew
 * past its "Phase 3 irreducible 6" baseline as key-schedule decomposition
 * (K1, K2) split each monolithic schedule into a tree of port-native
 * leaves and introduced a meta-bearing aux-publish tail per cipher — the
 * leaves narrate via their own `narrationOverride`, the tails are
 * identity passthroughs with no per-frame prose worth a unit fn.
 *
 * Reasons for the current set:
 *
 *   - **Monolithic key-expansion oracle executors** (`aes.key-expansion@1/@2`,
 *     `serpent.key-expansion@1`, `des.key-schedule@1`) — every key schedule is
 *     now decomposed into port-native primitives (AES in K1, Speck K2, Serpent
 *     K3, DES K4), so the per-stage math those executors hid (RotWord/SubWord/
 *     Rcon/word-XOR for AES; the prekey recurrence + bitsliced S-box + IP for
 *     Serpent; PC-1 → 16× rotate → PC-2 for DES) is now real, narrated trace
 *     frames inside the decomposed `key-schedule` group. The monolithic
 *     executors are no longer emitted by any shipped spec — they survive
 *     registered only as the KAT oracle for the decomposition tests and for
 *     loading pre-decomposition saved docs — so they are aux-only no-op steps
 *     with no narration to write. (The `<KeyScheduleExplorer />` UI that used
 *     to fake their decomposition was retired in K4b, 2026-06-02, once DES, the
 *     last monolithic schedule, decomposed. These executors are slated for
 *     deletion in a future release per `docs/versioning.md`.)
 *   - **Speck key schedule** — the monolithic `speck.key-schedule@1` step
 *     type was FULLY RETIRED at the K2c follow-up (2026-06-01): the executor,
 *     its StepDocumentation, the file `src/steps/speck-key-schedule.ts`,
 *     the registration in `default-registry.ts`, AND this allowlist entry
 *     are all gone. The decomposed schedule's publish tail
 *     (`speck.publish-round-keys@1`) holds the residual allowlist parity
 *     with `aes.publish-round-keys@1`.
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
  // Monolithic key-expansion oracle executors — decomposed into port-native
  // primitives (AES K1, Serpent K3, DES K4), so unused by any shipped spec;
  // kept registered only as KAT oracle + pre-decomposition doc back-compat.
  // Aux-only no-ops with no per-frame prose to write.
  "serpent.key-expansion@1",
  "aes.key-expansion@1",
  "aes.key-expansion@2",
  // The aux-publish tail of the DECOMPOSED AES key schedule
  // (key-schedule-decomposition K1a). An identity passthrough that mirrors the
  // round keys into aux — per-frame value-prose is the wrong surface (the
  // interesting math is the recurrence leaves above it, each of which IS
  // narrated via its `narrationOverride`).
  "aes.publish-round-keys@1",
  // The aux-publish tail of the DECOMPOSED Speck32/64 key schedule
  // (key-schedule-decomposition K2a, 2026-06-01). Same posture as the AES
  // analog above: an identity passthrough that mirrors the round-key words
  // into aux. The interesting math (ROR / + mod 2¹⁶ / ⊕ / ROL / ⊕ per
  // Beaulieu et al. 2013 §3) is in the recurrence leaves above it, each
  // narrated via its own `narrationOverride`. Below the cell-shape gate
  // anyway (`input: "any"`) — listed here for parity with the AES tail.
  "speck.publish-round-keys@1",
  // The aux-publish tail of the DECOMPOSED Serpent key schedule
  // (key-schedule-decomposition K3a, 2026-06-02). Same posture as the AES /
  // Speck analogs above: an identity passthrough that mirrors the 33 round
  // keys into aux. The interesting math (the 132-step prekey recurrence + the
  // per-group bitsliced S-box + IP) is in the leaves above it, each narrated
  // via its own `narrationOverride`. Below the cell-shape gate anyway
  // (`input: "any"`) — listed here for parity with the AES / Speck tails.
  "serpent.publish-round-keys@1",
  // The aux-publish tail of the DECOMPOSED DES key schedule
  // (key-schedule-decomposition K4a, 2026-06-02). Same posture as the AES /
  // Speck / Serpent analogs above: an identity passthrough that mirrors the 16
  // round keys into aux. The interesting math (PC-1 → 16× rotate-halves →
  // PC-2) is in the leaves above it, each narrated via its own
  // `narrationOverride`. Below the cell-shape gate anyway (`input: "any"`) —
  // listed here for parity with the AES / Speck / Serpent tails.
  "des.publish-round-keys@1",
  // The aux-publish tail of the RSA "Key Generation" group (RSA Phase 2,
  // 2026-06-08). Identity passthrough that mirrors the computed n / e / d into
  // aux["rsa.n" | "rsa.e" | "rsa.d"] so the exponentiation ladder reads them
  // back across the group wall. Same posture as the four publish-round-keys
  // tails: the interesting math (n = p·q, φ = (p−1)(q−1), d = e⁻¹ mod φ) is in
  // the leaves above it, each narrated via its own `narrationOverride`. Below
  // the cell-shape gate anyway (`input: "any"`) — listed here for parity.
  "rsa.publish-key-params@1",
  // Bit-level linear transforms — byte-level prose would be misleading.
  // (Bit-permutation is honest at byte granularity — narrated in Phase 2.)
  "serpent.linear-transform@1",
  "serpent.inv-linear-transform@1",
  // (The `feistel.toy-add-k@1` toy entry was removed in Phase 5 Slice 5.3e
  // when the toy step type was decommissioned with the Feistel scaffolding.)
  // `des.key-schedule@1` — the monolithic DES schedule oracle. Decomposed
  // in K4a into port-native `des.bit-permute@1` (PC-1/PC-2) + `des.rotate-
  // halves@1` + the `des.publish-round-keys@1` tail, each narrated via its own
  // `narrationOverride`; this executor is no longer emitted by any shipped
  // spec (same posture as the AES/Serpent oracles above).
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
