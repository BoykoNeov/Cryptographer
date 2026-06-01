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
 * the right per-cipher view (AES per-word swimlane vs Serpent multi-stage
 * pipeline). New cipher families add a new variant when their schedule
 * shape doesn't fit either existing one.
 */

import { type DesScheduleTrace, type DesSimParams, simulateDesKeySchedule } from "./des";
import { type SerpentScheduleTrace, simulateSerpentKeySchedule } from "./serpent";

// NOTE (key-schedule-decomposition K1c, 2026-06-01): the AES simulator was
// RETIRED here. AES's key schedule is now decomposed into port-native
// primitives (`aes-key-schedule-builder-native.ts`), so the RotWord / SubWord
// / Rcon / word-XOR stages the AES swimlane used to simulate are now real,
// scrubbable trace frames — the explorer's AES branch was both unreachable (no
// `aes.key-expansion@1` frame ships) and redundant. Serpent + DES schedules
// remain monolithic until K3/K4 decompose them, so their simulators stay.

/**
 * Discriminated union over simulator shapes. Each variant carries the
 * trace type it produces; consumers narrow via `kind` before invoking
 * `simulate`. Adding a new cipher family adds a new variant + trace type.
 */
export type ScheduleSimulator =
  | {
      readonly kind: "serpent";
      readonly simulate: (masterKey: Uint8Array) => SerpentScheduleTrace;
    }
  | {
      readonly kind: "des";
      readonly simulate: (masterKey: Uint8Array, params: DesSimParams) => DesScheduleTrace;
    };

/**
 * Step-type → simulator. Only the still-monolithic schedules (Serpent, DES)
 * register here; AES decomposed (K1c) and now shows its stages directly in
 * the trace.
 */
const REGISTRY = new Map<string, ScheduleSimulator>([
  [
    "serpent.key-expansion@1",
    {
      kind: "serpent",
      simulate: simulateSerpentKeySchedule,
    },
  ],
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
