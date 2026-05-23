/**
 * Step registry: maps `stepType` strings to executors and (optionally)
 * human-readable docs. The runtime walks a CipherSpec and looks up each
 * leaf's executor here; the UI looks up the same key for documentation.
 *
 * The single map keyed by stepType keeps the two concerns in sync — you
 * cannot register an executor without (at most) overlooking its docs, and
 * a doc-only registration is impossible too.
 *
 * Phase-1 Slice 1.1 (universal-port-dataflow): the internal storage type
 * widens from `StepDefinition` to `StepRegistration`, a discriminated
 * union over `{ kind: "legacy" }` and `{ kind: "ported" }`. The public
 * API stays back-compatible — `register()` still accepts a bare
 * `StepExecutor` or a `StepDefinition` and normalizes both to
 * `{ kind: "legacy", ... }` at the entry boundary. A new
 * `getRegistration()` accessor exposes the full union for the runtime,
 * which will branch on `kind` once Slice 1.2 lands the first ported
 * entry. Until then this slice is intentionally a no-op: nothing
 * registers as ported, every dispatch path is unchanged, and the gate
 * is "1622 existing tests stay green."
 */

import type {
  PortedExecutor,
  StepDefinition,
  StepDocumentation,
  StepExecutor,
  StepRegistration,
} from "./types";

export class StepRegistry {
  private readonly defs = new Map<string, StepRegistration>();

  /**
   * Register a step type. Accepts any of three shapes for back-compat
   * across the Slice 1.1 cutover:
   *
   *   1. A bare `StepExecutor` function — legacy, docs omitted.
   *   2. A `StepDefinition` (`{ executor, doc? }`) — legacy with docs.
   *      This is what every shipped `default-registry.ts` entry passes
   *      today; the registration is normalized to `kind: "legacy"`.
   *   3. A pre-built `StepRegistration` — either `kind: "legacy"` or
   *      `kind: "ported"`. Slice 1.2+ uses the ported branch.
   *
   * Throws if the same `stepType` is already registered — there is no
   * sensible "re-register" flow; conflicting registrations are a bug.
   */
  register(stepType: string, registration: StepExecutor | StepDefinition | StepRegistration): void {
    if (this.defs.has(stepType)) {
      throw new Error(`step type already registered: ${stepType}`);
    }
    this.defs.set(stepType, normalizeRegistration(registration));
  }

  /**
   * Look up the legacy executor for a step type. Throws if unknown, and
   * throws if the step type is registered as `kind: "ported"` — the
   * legacy-shape `(state, params, ctx) → StepResult` executor isn't
   * directly accessible from a ported registration.
   *
   * Callers that need to handle either kind should use `getRegistration()`
   * and branch on `kind` themselves; this accessor is the legacy-path
   * convenience and stays available throughout Phase 1 because the
   * runtime's legacy dispatch site still calls it directly.
   */
  get(stepType: string): StepExecutor {
    const def = this.defs.get(stepType);
    if (!def) throw new Error(`unknown step type: ${stepType}`);
    if (def.kind === "ported") {
      throw new Error(
        `step type "${stepType}" is registered as ported; use getRegistration() to access it`,
      );
    }
    return def.executor;
  }

  /**
   * Look up the full registration (legacy OR ported) for a step type.
   * Returns undefined if the step type was never registered. This is the
   * accessor the runtime's ported-dispatch path uses to discover whether
   * a leaf should run on the legacy or the ported contract; legacy-only
   * call sites can keep using `get()`.
   */
  getRegistration(stepType: string): StepRegistration | undefined {
    return this.defs.get(stepType);
  }

  /**
   * Look up the docs for a step type. Returns undefined if the step type
   * was registered without docs (legacy variant — ported registrations
   * always carry docs by contract) or doesn't exist. Callers should treat
   * missing docs as "show a fallback"; never throw, since the runtime is
   * happy without docs.
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

/**
 * Normalize any of the three accepted registration shapes to the
 * internal `StepRegistration` discriminated union.
 *
 * The discriminator check (`"kind" in r`) is structural rather than a
 * `typeof` test because both `StepDefinition` and `StepRegistration` are
 * plain object literals — the only way to tell them apart is the
 * presence of the `kind` field. A registration that happens to have a
 * stray `kind` property would already be invalid TypeScript at the
 * `register()` call site, so trusting the discriminator here is safe.
 */
const normalizeRegistration = (
  r: StepExecutor | StepDefinition | StepRegistration,
): StepRegistration => {
  if (typeof r === "function") {
    return { kind: "legacy", executor: r };
  }
  if ("kind" in r) {
    return r;
  }
  // StepDefinition: { executor, doc? } — wrap as legacy. Spread the
  // optional doc only when present so the resulting object matches
  // `exactOptionalPropertyTypes` exactly (no `doc: undefined` field).
  return r.doc !== undefined
    ? { kind: "legacy", executor: r.executor, doc: r.doc }
    : { kind: "legacy", executor: r.executor };
};

// Re-export the ported executor type so future call sites that build a
// `kind: "ported"` registration in this module's neighborhood don't have
// to reach across to `core/types`. Cheap, keeps the registry file
// self-contained for the migration's reader.
export type { PortedExecutor };
