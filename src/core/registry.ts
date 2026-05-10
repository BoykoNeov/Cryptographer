/**
 * Step registry: maps `stepType` strings to executors and (optionally)
 * human-readable docs. The runtime walks a CipherSpec and looks up each
 * leaf's executor here; the UI looks up the same key for documentation.
 *
 * The single map keyed by stepType keeps the two concerns in sync — you
 * cannot register an executor without (at most) overlooking its docs, and
 * a doc-only registration is impossible too.
 */

import type { StepDefinition, StepDocumentation, StepExecutor } from "./types";

export class StepRegistry {
  private readonly defs = new Map<string, StepDefinition>();

  /**
   * Register a step type. Accepts either a bare executor (handy when you
   * don't yet have docs) or a `{ executor, doc }` definition. Either form
   * throws if the same `stepType` is already registered — there is no
   * sensible "re-register" flow; conflicting registrations are a bug.
   */
  register(stepType: string, executorOrDef: StepExecutor | StepDefinition): void {
    if (this.defs.has(stepType)) {
      throw new Error(`step type already registered: ${stepType}`);
    }
    const def: StepDefinition =
      typeof executorOrDef === "function" ? { executor: executorOrDef } : executorOrDef;
    this.defs.set(stepType, def);
  }

  /** Look up the executor for a step type. Throws if unknown. */
  get(stepType: string): StepExecutor {
    const def = this.defs.get(stepType);
    if (!def) throw new Error(`unknown step type: ${stepType}`);
    return def.executor;
  }

  /**
   * Look up the docs for a step type. Returns undefined if the step type
   * was registered without docs (or doesn't exist) — callers should treat
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
