/**
 * Key-schedule simulator registry. Maps step-type names to their viz-only
 * simulators, decoupled from the core step-registry (`src/core/registry.ts`)
 * because the concerns differ:
 *
 *   - The core step registry pairs an executor with a doc block. Used by
 *     the runtime to actually execute the cipher.
 *   - This registry pairs a step type with a per-cipher "yield the
 *     internal stages" simulator. Used by `<KeyScheduleExplorer />` to
 *     visualize what the executor *did* internally.
 *
 * Keeping them separate means a new cipher with a novel key schedule can
 * register its simulator here without touching the runtime registration
 * path — and vice versa, a runtime-only refactor doesn't reach into
 * pedagogy code.
 *
 * The discriminated-union shape lets the UI switch on `kind` to render
 * the right per-cipher view. Only DES remains today (a per-round
 * PC-1/shift/PC-2 table). New cipher families add a new variant when
 * their schedule shape doesn't fit an existing one.
 */

import { type DesScheduleTrace, type DesSimParams, simulateDesKeySchedule } from "./des";

// NOTE (key-schedule-decomposition K1c, 2026-06-01 + K3b, 2026-06-02): the AES
// AND Serpent simulators were RETIRED here. Both key schedules are now
// decomposed into port-native primitives
// (`aes-key-schedule-builder-native.ts` / `serpent-key-schedule-builder-native.ts`),
// so the RotWord / SubWord / Rcon / word-XOR stages (AES) and the prekey
// recurrence / bitsliced-S-box / IP stages (Serpent) those swimlanes used to
// simulate are now real, scrubbable trace frames — each branch was both
// unreachable (no `aes.key-expansion@1` / `serpent.key-expansion@1` frame ships
// from a builder-routed spec) and redundant. DES is the last monolithic
// schedule, so its simulator stays until K4 decomposes it.

/**
 * Discriminated union over simulator shapes. Each variant carries the
 * trace type it produces; consumers narrow via `kind` before invoking
 * `simulate`. Adding a new cipher family adds a new variant + trace type.
 * Today only DES is monolithic enough to need one.
 */
export type ScheduleSimulator = {
  readonly kind: "des";
  readonly simulate: (masterKey: Uint8Array, params: DesSimParams) => DesScheduleTrace;
};

/**
 * Step-type → simulator. Only the still-monolithic DES schedule registers
 * here; AES (K1c) and Serpent (K3b) decomposed and now show their stages
 * directly in the trace.
 */
const REGISTRY = new Map<string, ScheduleSimulator>([
  [
    "des.key-schedule@1",
    {
      kind: "des",
      simulate: simulateDesKeySchedule,
    },
  ],
]);

/**
 * Look up a simulator for a step type. Returns null when the type has no
 * registered simulator (every step type that isn't a key-expansion variant)
 * — callers should treat that as "no explorer for this frame; render the
 * standard FrameStateView."
 */
export const lookupScheduleSimulator = (stepType: string): ScheduleSimulator | null =>
  REGISTRY.get(stepType) ?? null;

/**
 * Predicate variant of the lookup. Cheap O(1); use to decide whether to
 * render the explorer at all before parsing params.
 */
export const isKeyExpansionStepType = (stepType: string): boolean => REGISTRY.has(stepType);
