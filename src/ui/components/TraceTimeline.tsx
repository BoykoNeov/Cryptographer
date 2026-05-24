/**
 * Scrubber timeline with optional per-frame track-membership badges
 * (Phase 5f of `docs/plans/des-feistel.md`).
 *
 * The slider itself is the standard `<input type="range">` from before;
 * the badges are an overlay strip positioned above the slider track.
 * Each badge represents one frame and is absolutely positioned at
 * `(frameIndex / maxIndex) * 100%` so visual position lines up with the
 * slider thumb's position at that index.
 *
 * Badge types:
 *   - L / R / etc. (track-name letter) for in-track frames
 *     (`frame.branchPath` non-empty — the last entry is the track name).
 *   - ⇄ for synthetic rejoin frames (`stepType === REJOIN_STEP_TYPE`).
 *     The ⇄ glyph communicates "the two halves come back together here."
 *   - ⚠ for synthetic coercion frames (`stepType === COERCE_STEP_TYPE`)
 *     emitted by the runtime when a ported-dispatch input port's source
 *     bytes don't match its declared byteLength. Surfaces the
 *     warn-and-run coercion (Slice 1.12 of the universal-port plan) so
 *     a learner scrubbing the trace can SEE the mismatched-wiring event
 *     before landing on its frame. Loud-on-purpose: coercion is a
 *     warning event, not a normal pipeline step.
 *   - No badge for root-scope frames (IP, FP, key-schedule). The plain
 *     slider position already represents them — adding badges would
 *     pollute the strip with empty markers for ciphers like AES that
 *     have no track-aware frames at all.
 *
 * Performance: for DES the trace has ~330 frames. Rendering 300+ DOM
 * nodes for a strip overlay is borderline but fine on modern hardware
 * (we measure ~5ms render time in dev). If a future cipher pushes the
 * frame count above ~1000, this would need a virtualized strip or a
 * canvas-rendered overlay; not blocking today.
 *
 * Click-through: badges have `pointer-events: none` so the user can
 * click anywhere on the underlying slider track without the badge
 * intercepting. The badges are purely informational.
 */

import { REJOIN_STEP_TYPE } from "@/core/combine-kinds";
import { COERCE_STEP_TYPE } from "@/core/port-projection";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { getTrace, setFrame, useFrameIndex, useTraceVersion } from "../stores/trace";

/**
 * Per-frame badge descriptor. `position` is the index → percent across
 * the slider; `glyph` is the rendered text; `kind` drives the CSS
 * class (color, font weight, etc.).
 */
type Badge = {
  readonly index: number;
  readonly positionPercent: number;
  readonly glyph: string;
  readonly kind: "track" | "rejoin" | "coerce";
};

const computeBadges = (frames: readonly TraceFrame[]): Badge[] => {
  if (frames.length <= 1) return [];
  const maxIdx = frames.length - 1;
  const out: Badge[] = [];
  for (let i = 0; i < frames.length; i++) {
    const f = frames[i];
    if (!f) continue;
    // Rejoin synthetic frames get the ⇄ glyph regardless of
    // branchPath state (today the runtime drops branchPath on the
    // rejoin frame; defensive in case that changes).
    if (f.stepType === REJOIN_STEP_TYPE) {
      out.push({
        index: i,
        positionPercent: (i / maxIdx) * 100,
        glyph: "⇄",
        kind: "rejoin",
      });
      continue;
    }
    // Coercion synthetic frames get the ⚠ glyph. Emitted by the
    // ported-dispatch runtime when an input port's source bytes don't
    // match its declared byteLength (Slice 1.12 of the universal-port
    // plan). branchPath may or may not be set depending on whether the
    // mismatched leaf is inside a Feistel/iterate body; the check on
    // stepType comes first so we surface coercion uniformly across
    // those scopes.
    if (f.stepType === COERCE_STEP_TYPE) {
      out.push({
        index: i,
        positionPercent: (i / maxIdx) * 100,
        glyph: "⚠",
        kind: "coerce",
      });
      continue;
    }
    const branchPath = f.branchPath;
    if (branchPath && branchPath.length > 0) {
      // Use the innermost track name (last entry). For DES this is
      // always "R" (L track is empty passthrough). For future ciphers
      // both tracks may show up in the strip.
      const trackName = branchPath[branchPath.length - 1];
      if (trackName !== undefined) {
        // Short label: single character for one-letter track names,
        // first character otherwise. Keeps the strip visually quiet
        // when names get longer (e.g. "left" → "l").
        out.push({
          index: i,
          positionPercent: (i / maxIdx) * 100,
          glyph: trackName.length === 1 ? trackName : trackName.charAt(0).toLowerCase(),
          kind: "track",
        });
      }
    }
  }
  return out;
};

export const TraceTimeline = () => {
  const frameIndex = useFrameIndex();
  const version = useTraceVersion();

  const trace = () => {
    void version();
    return getTrace();
  };

  const max = () => Math.max(0, (trace()?.frames.length ?? 1) - 1);

  // Track / rejoin badges. Recomputes on trace version change (i.e.
  // each Run). Empty for ciphers without any Feistel frames — the
  // overlay strip then renders an empty div, taking the same vertical
  // space so the slider doesn't visually jump between cipher kinds.
  const badges = createMemo<Badge[]>(() => {
    void version();
    const t = getTrace();
    if (!t) return [];
    return computeBadges(t.frames);
  });

  return (
    <div class="trace-timeline">
      <Show when={trace()} fallback={<span class="muted">no trace yet — run the cipher</span>}>
        {(t) => (
          <>
            <button
              type="button"
              onClick={() => setFrame(frameIndex() - 1)}
              disabled={frameIndex() === 0}
            >
              ◀
            </button>
            <div class="trace-timeline-slider-wrap">
              <Show when={badges().length > 0}>
                <div class="trace-timeline-badge-strip" aria-hidden="true">
                  <For each={badges()}>
                    {(badge) => (
                      <span
                        class="trace-timeline-badge"
                        classList={{
                          "trace-timeline-badge-track": badge.kind === "track",
                          "trace-timeline-badge-rejoin": badge.kind === "rejoin",
                          "trace-timeline-badge-coerce": badge.kind === "coerce",
                        }}
                        style={{ left: `${badge.positionPercent}%` }}
                        title={`frame ${badge.index + 1}: ${
                          badge.kind === "rejoin"
                            ? "rejoin"
                            : badge.kind === "coerce"
                              ? "coerce (port byteLength mismatch)"
                              : `track ${badge.glyph.toUpperCase()}`
                        }`}
                      >
                        {badge.glyph}
                      </span>
                    )}
                  </For>
                </div>
              </Show>
              <input
                type="range"
                min="0"
                max={max()}
                value={frameIndex()}
                onInput={(e) => setFrame(Number(e.currentTarget.value))}
              />
            </div>
            <button
              type="button"
              onClick={() => setFrame(frameIndex() + 1)}
              disabled={frameIndex() >= max()}
            >
              ▶
            </button>
            <span class="frame-counter">
              frame {frameIndex() + 1} / {t().frames.length}
            </span>
          </>
        )}
      </Show>
    </div>
  );
};
