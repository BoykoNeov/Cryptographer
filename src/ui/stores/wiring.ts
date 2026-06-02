/**
 * Transient "armed input port" state for the canvas port-wiring gesture
 * (universal-port plan Phase 4d-bis, Slice E — click-to-arm).
 *
 * The gesture is two clicks: click an input-port handle on a leaf to ARM that
 * port, then click a legal upstream source's output handle to BIND it. This
 * store holds only the momentary "which port is armed" between those two
 * clicks.
 *
 * **Deliberately NOT a viewer preference and NOT persisted.** Unlike zoom /
 * density / collapsed-set (which live in per-spec sidecars and travel through
 * Save/Share), the armed port is a sub-second interaction state — it has no
 * meaning across a reload and must never serialize. So it's a bare module
 * signal, the same shape as a text-cursor position (see
 * `feedback_viewer_preference_pattern`: the litmus is "would a recipient
 * inherit this or want their own?" — neither; it's not theirs to inherit).
 */

import { createSignal } from "solid-js";

/** The leaf input port currently armed for rebinding, or `null` if none. */
export type ArmedPort = {
  readonly stepId: string;
  readonly portName: string;
};

const [armedPort, setArmedPortSignal] = createSignal<ArmedPort | null>(null);

/** Read accessor — the armed port, or `null`. */
export const useArmedPort = () => armedPort;

/**
 * Arm `portName` on `stepId`, or DISARM if that exact port is already armed
 * (clicking the same handle twice toggles off). Arming a different port just
 * moves the arm.
 */
export const toggleArmPort = (stepId: string, portName: string): void => {
  const current = armedPort();
  if (current !== null && current.stepId === stepId && current.portName === portName) {
    setArmedPortSignal(null);
    return;
  }
  setArmedPortSignal({ stepId, portName });
};

/** Disarm — clears any armed port (Esc, canvas click, or a completed bind). */
export const disarmPort = (): void => {
  setArmedPortSignal(null);
};

/** Test-only reset. */
export const __resetWiringForTests = (): void => {
  setArmedPortSignal(null);
};
