/**
 * Step registry: maps `stepType` strings to executors and (optionally)
 * human-readable docs. The runtime walks a CipherSpec and looks up each
 * leaf's executor here; the UI looks up the same key for documentation.
 *
 * The single map keyed by stepType keeps the two concerns in sync — you
 * cannot register an executor without (at most) overlooking its docs, and
 * a doc-only registration is impossible too.
 *
 * The internal storage type is `StepRegistration` — the single port-native
 * registration contract. Historically this was a discriminated union over a
 * `kind: "legacy"` single-thread executor and a `kind: "ported"` contract, and
 * `register()` normalized bare `StepExecutor` / `StepDefinition` shapes into
 * the legacy arm. Phase C / universal-port Phase 5 retired the legacy contract:
 * `register()` now takes a `StepRegistration` directly and `getRegistration()`
 * is the runtime's lookup. (The `kind: "ported"` tag is kept as a single-member
 * discriminator so every registration literal compiles unchanged.)
 */

import type { PortedExecutor, StepDocumentation, StepRegistration } from "./types";

export class StepRegistry {
  private readonly defs = new Map<string, StepRegistration>();

  /**
   * Register a step type from its `StepRegistration` (the single port-native
   * contract — `{ kind: "ported", executor, shape, doc, meta? }`). The legacy
   * bare-`StepExecutor` / `StepDefinition` shapes and their normalization were
   * retired in Phase C / universal-port Phase 5 along with the legacy contract.
   *
   * Throws if the same `stepType` is already registered — there is no
   * sensible "re-register" flow; conflicting registrations are a bug.
   */
  register(stepType: string, registration: StepRegistration): void {
    if (this.defs.has(stepType)) {
      throw new Error(`step type already registered: ${stepType}`);
    }
    this.defs.set(stepType, registration);
  }

  /**
   * Look up the full registration for a step type. Returns undefined if the
   * step type was never registered. This is the runtime's lookup for a leaf's
   * executor, port contract, and projection metadata.
   */
  getRegistration(stepType: string): StepRegistration | undefined {
    return this.defs.get(stepType);
  }

  /**
   * Look up the docs for a step type. Returns undefined if the step type
   * doesn't exist (a `StepRegistration` always carries `doc` by contract).
   * Callers should treat missing docs as "show a fallback"; never throw,
   * since the runtime is happy without docs.
   */
  getDoc(stepType: string): StepDocumentation | undefined {
    return this.defs.get(stepType)?.doc;
  }

  has(stepType: string): boolean {
    return this.defs.has(stepType);
  }

  types(): readonly string[] {
    return [...this.defs.keys()];
  }
}

// Re-export the ported executor type so call sites that build a
// `kind: "ported"` registration in this module's neighborhood don't have
// to reach across to `core/types`. Cheap, keeps the registry file
// self-contained.
export type { PortedExecutor };
