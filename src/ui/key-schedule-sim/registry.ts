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

import { type AesScheduleTrace, simulateAesKeySchedule } from "./aes";
import { type DesScheduleTrace, type DesSimParams, simulateDesKeySchedule } from "./des";
import { type SerpentScheduleTrace, simulateSerpentKeySchedule } from "./serpent";

/**
 * AES simulator-input bundle. The step's `params` carry the S-box, Rcon
 * seed, and `rounds` count — the simulator needs all three to match the
 * executor's output byte-for-byte. The component extracts this from
 * `frame.params` at render time.
 */
export type AesSimParams = {
  readonly sbox: readonly number[];
  readonly rcon: readonly number[];
  readonly rounds: number;
};

/**
 * Discriminated union over simulator shapes. Each variant carries the
 * trace type it produces; consumers narrow via `kind` before invoking
 * `simulate`. Adding a new cipher family adds a new variant + trace type.
 */
export type ScheduleSimulator =
  | {
      readonly kind: "aes";
      readonly simulate: (masterKey: Uint8Array, params: AesSimParams) => AesScheduleTrace;
    }
  | {
      readonly kind: "serpent";
      readonly simulate: (masterKey: Uint8Array) => SerpentScheduleTrace;
    }
  | {
      readonly kind: "des";
      readonly simulate: (masterKey: Uint8Array, params: DesSimParams) => DesScheduleTrace;
    };

/**
 * Step-type → simulator. Same simulator function for AES `@1` and `@2`
 * because the algorithm body is identical between them — only the
 * runtime's input validation differs (`@1` requires `rounds === Nk + 6`;
 * `@2` accepts `rounds >= Nk + 1`). The simulator accepts both bounds
 * by construction, so each variant gets the same registration.
 */
const REGISTRY = new Map<string, ScheduleSimulator>([
  [
    "aes.key-expansion@1",
    {
      kind: "aes",
      simulate: (key, p) => simulateAesKeySchedule(key, p.sbox, p.rcon, p.rounds),
    },
  ],
  [
    "aes.key-expansion@2",
    {
      kind: "aes",
      simulate: (key, p) => simulateAesKeySchedule(key, p.sbox, p.rcon, p.rounds),
    },
  ],
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
