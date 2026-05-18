/**
 * Provenance hover store. Phase 3 of the linear-mode pedagogy plan.
 *
 * Carries the currently-hovered "where does THIS cell come from?" highlight
 * state across components: MatrixView's `after` grid sets it on mouseEnter,
 * MatrixView's `before` grid + the RoundKeyPanel both read it to decide
 * which of their cells get the `.provenance-source` outline.
 *
 * The signal carries the precomputed `ProvenanceSource[]` rather than the
 * frame + index so the consumers don't all have to re-run `lookupProvenance`.
 * Set-time is once per hover; read-time is on every cell render across two
 * surfaces — wasted work matters.
 *
 * Universal lifecycle: hover-leave resets to `null`, frame swap (scrub or
 * spec edit) implicitly clears via the scope guard in consumers — a
 * `.provenance-source` highlight from a stale frame would just be wrong,
 * so consumers check `payload.stepId === currentFrame.stepId` before
 * applying.
 */

import { createSignal } from "solid-js";
import type { ProvenanceSource } from "../provenance/registry";

export type ProvenanceHoverPayload = {
  /** stepId the hover originates from; consumers guard their renders by it. */
  readonly stepId: string;
  /** Linear cell index in `stateAfter.bytes` that was hovered. */
  readonly afterCellIndex: number;
  /** Precomputed sources — read-time cheap. */
  readonly sources: readonly ProvenanceSource[];
};

const [hover, setHover] = createSignal<ProvenanceHoverPayload | null>(null);

export const useProvenanceHover = () => hover;

/**
 * Set the active hover. Pass null to clear.
 */
export const setProvenanceHover = (payload: ProvenanceHoverPayload | null): void => {
  setHover(payload);
};

/**
 * Convenience: clear the hover. Same as `setProvenanceHover(null)` —
 * exists so callers can be more readable in their mouseLeave handlers.
 */
export const clearProvenanceHover = (): void => {
  setHover(null);
};

/** Test-only: reset to a known empty state between cases. */
export const __resetProvenanceHoverForTests = (): void => {
  setHover(null);
};
