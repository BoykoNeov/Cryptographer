/**
 * Degree-1 base-case multiplication diagram — the second lattice linear-view
 * picture, and the smallest of the family: it draws ONE leaf, not a round.
 *
 * Self-detects a `zq-base-case-mul@1` frame and renders nothing otherwise.
 *
 * **Why one leaf earns a diagram.** This is the step whose palette name has to
 * break the `zq-vec-` family prefix, because it is the one lattice operation
 * that is NOT element-wise. The transform stops at 128 degree-1 polynomials
 * rather than 256 numbers (`q − 1 = 2⁸ · 13` admits no primitive 512th root, so
 * the last split is impossible), and that single fact changes what
 * "multiplication in the transformed domain" means: it is 128 separate little
 * polynomial products, each in its own ring `Z_q[X]/(X² − γ)`.
 *
 * The consequence is the picture. Multiplying two linear polynomials gives a
 * quadratic, and the `X²` term has nowhere to go — except that in this ring
 * `X² = γ`, so it folds back onto the constant term:
 *
 * ```
 *   (a₀ + a₁X)(b₀ + b₁X)  =  a₀b₀ + (a₀b₁ + a₁b₀)X + a₁b₁X²
 *                                                     └── X² = γ ──┐
 *   c₀ = a₀b₀ + a₁b₁·γ  ◄───────────────────────────────────────────┘
 *   c₁ = a₀b₁ + a₁b₀
 * ```
 *
 * Four products, one of them folded. A learner who believes this step is
 * element-wise gets an implementation that is self-consistent and agrees with
 * nobody, which is exactly the class of error the lattice plan keeps recording;
 * the fold arrow is the shortest way to say why.
 *
 * The step's registered narrator says the same thing in prose with live values.
 * This is the complement: prose cannot draw an arrow from the `X²` term back
 * down to the constant one, and that arrow IS the ring.
 */

import { type BaseCaseMulDiagramModel, baseCaseMulDiagramModel } from "@/core/ntt-diagram";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useSpec } from "../stores/spec";

type Props = {
  frame: TraceFrame;
};

export const ZqBaseCaseMulDiagram = (props: Props) => {
  const spec = useSpec();

  const model = createMemo<BaseCaseMulDiagramModel | null>(() =>
    baseCaseMulDiagramModel(props.frame, spec()),
  );

  return (
    <Show when={model()}>
      {(getModel) => (
        <section class="zq-basecase-diagram" aria-label="degree-1 base-case multiplication diagram">
          <div class="zq-basecase-diagram-header">
            <span class="zq-basecase-diagram-title">degree-1 multiplication</span>
            <code class="zq-basecase-diagram-kind">
              {`${getModel().pairs} pairs · Z_q[X]/(X² − γ)`}
            </code>
          </div>

          <div class="zq-basecase-diagram-body">
            <div class="zq-basecase-diagram-expansion">
              <code>(a₀ + a₁X)(b₀ + b₁X) = a₀b₀ + (a₀b₁ + a₁b₀)X + a₁b₁X²</code>
              <span class="zq-basecase-diagram-fold">X² = γ, so the last term folds back ↓</span>
            </div>

            <For each={[0, 1] as const}>
              {(into) => (
                <div class="zq-basecase-diagram-row">
                  <code class="zq-basecase-diagram-out">{into === 0 ? "c₀" : "c₁"}</code>
                  <span class="zq-basecase-diagram-eq">=</span>
                  <For each={getModel().terms.filter((t) => t.into === into)}>
                    {(term, i) => (
                      <>
                        <Show when={i() > 0}>
                          <span class="zq-basecase-diagram-plus">+</span>
                        </Show>
                        <code
                          class={
                            term.folded
                              ? "zq-basecase-diagram-term zq-basecase-diagram-term-folded"
                              : "zq-basecase-diagram-term"
                          }
                        >
                          {term.label}
                        </code>
                      </>
                    )}
                  </For>
                </div>
              )}
            </For>
          </div>

          <p class="zq-basecase-diagram-note muted small">
            This is <strong>not</strong> an element-wise multiply, which is why its name breaks the{" "}
            <code>zq-vec-</code> family prefix. The transform stops at 128 degree-1 polynomials
            rather than 256 numbers, so each pair of coefficients multiplies as a little polynomial
            in its own ring — and the <code>X²</code> term the product creates has nowhere to go
            except back onto the constant term, scaled by γ.{" "}
            <span class="zq-basecase-diagram-ref">{getModel().reference}</span>
          </p>
        </section>
      )}
    </Show>
  );
};
