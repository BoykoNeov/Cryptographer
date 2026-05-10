import type { StepExecutor } from "./types";

export class StepRegistry {
  private readonly executors = new Map<string, StepExecutor>();

  register(stepType: string, executor: StepExecutor): void {
    if (this.executors.has(stepType)) {
      throw new Error(`step type already registered: ${stepType}`);
    }
    this.executors.set(stepType, executor);
  }

  get(stepType: string): StepExecutor {
    const exec = this.executors.get(stepType);
    if (!exec) throw new Error(`unknown step type: ${stepType}`);
    return exec;
  }

  has(stepType: string): boolean {
    return this.executors.has(stepType);
  }

  types(): readonly string[] {
    return [...this.executors.keys()];
  }
}
