/**
 * Renders the documentation for the current step: a heading, a one-line
 * summary, full markdown detail, parameter explanations, and references.
 *
 * Pulls docs from the UI-side registry singleton — same registry the
 * runtime uses for executors, so docs are guaranteed in sync with what's
 * actually being run.
 *
 * If a step type has no docs registered, the component shows a graceful
 * fallback. New ciphers/step types will get their docs picked up here
 * automatically just by registering them.
 */

import { findStep } from "@/core/spec-mutations";
import { canonicalStepId } from "@/core/step-id";
import type { StepDocumentation, TraceFrame } from "@/core/types";
import { For, Show } from "solid-js";
import { registry } from "../stores/registry";
import { useSpec } from "../stores/spec";
import { Markdown } from "./Markdown";

type Props = {
  /** The frame whose step docs we should display. */
  frame: TraceFrame | null;
};

export const StepDescription = (props: Props) => {
  const spec = useSpec();
  /**
   * Slice 1.10 lookup order:
   *   1. If the spec's leaf for this frame carries a `narrationOverride`,
   *      use it. The override is per-instance; multiple specs may reuse
   *      the same step type but want different prose for it.
   *   2. Otherwise fall back to the registry's generic doc keyed by
   *      `stepType` (the long-shipped behavior).
   *
   * `canonicalStepId` strips `:b{i}` / `:t{name}` / `:rejoin` / `:swap`
   * runtime suffixes so frames emitted inside `iterate` or `feistel-round`
   * still resolve to their spec-leaf id. `findStep` returns `null` for
   * group ids (e.g. a `:rejoin` frame whose canonical id resolves to a
   * `feistel-round`, not a leaf); the registry fallback then keeps the
   * panel populated for those.
   */
  const doc = (): StepDocumentation | undefined => {
    const f = props.frame;
    if (!f) return undefined;
    const leaf = findStep(spec(), canonicalStepId(f.stepId));
    if (leaf?.narrationOverride) return leaf.narrationOverride;
    return registry.getDoc(f.stepType);
  };

  return (
    <div class="step-description">
      <Show
        when={doc()}
        fallback={
          <div class="step-description-empty muted">
            <Show when={props.frame} fallback="select a step to see its description">
              {(frame) => (
                <span>
                  no docs registered for step type <code>{frame().stepType}</code>
                </span>
              )}
            </Show>
          </div>
        }
      >
        {(getDoc) => (
          <>
            <header class="step-description-header">
              <h2 class="step-description-name">{getDoc().name}</h2>
              <p class="step-description-summary">{getDoc().summary}</p>
            </header>

            <div class="step-description-body">
              <Markdown source={getDoc().detail} />
            </div>

            {/* Param explanations — only shown when the step type
                actually documented its params. Useful for the user as
                they look at the ParamEditor below. */}
            <Show when={hasParams(getDoc())}>
              <section class="step-description-params">
                <h3>Parameters</h3>
                <dl>
                  <For each={[...(getDoc().params ?? new Map())]}>
                    {([name, desc]) => (
                      <>
                        <dt>
                          <code>{name}</code>
                        </dt>
                        <dd>{desc}</dd>
                      </>
                    )}
                  </For>
                </dl>
              </section>
            </Show>

            <Show when={(getDoc().references?.length ?? 0) > 0}>
              <section class="step-description-refs">
                <h3>References</h3>
                <ul>
                  <For each={getDoc().references ?? []}>{(ref) => <li>{ref}</li>}</For>
                </ul>
              </section>
            </Show>
          </>
        )}
      </Show>
    </div>
  );
};

const hasParams = (doc: StepDocumentation): boolean => (doc.params?.size ?? 0) > 0;
