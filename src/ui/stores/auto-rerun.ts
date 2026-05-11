/**
 * Auto/manual rerun preference store. Two signals:
 *   • `autoRerun`  — when true (default), spec edits trigger the existing
 *                    debounced re-run loop in App.tsx. When false, edits
 *                    instead set the `dirty` flag and the user must press
 *                    Run to apply them. Persisted in localStorage so the
 *                    preference survives reloads.
 *   • `dirty`      — runtime-only: true when there are unrun spec edits.
 *                    Cleared on the next successful run.
 *
 * Why split: `autoRerun` is a user preference (sticky across sessions);
 * `dirty` is in-session state about the current spec vs. the last-run
 * spec. Bundling them would persist a fleeting "edits pending" flag
 * across reloads, which would be confusing.
 *
 * Why the user wanted this: with the 5-deep run-history buffer, batched
 * spec edits in auto-rerun mode would push the original snapshot off the
 * end before they could compare. Manual mode lets the user batch a flurry
 * of edits into ONE deliberate Run, preserving the prior snapshot for
 * the "compare runs" tile.
 */

import { createSignal } from "solid-js";

const STORAGE_KEY = "cryptographer.autoRerun";

const loadInitial = (): boolean => {
  // Same defensive pattern as the format store: localStorage may be
  // missing in vitest's node environment or denied in private browsing.
  try {
    if (typeof localStorage === "undefined") return true;
    const raw = localStorage.getItem(STORAGE_KEY);
    // Only "false" disables auto-rerun. Any other value (including null
    // for a fresh visitor) keeps the friendlier auto-rerun default.
    if (raw === "false") return false;
  } catch {
    // Storage denied — fall through to default.
  }
  return true;
};

const [autoRerun, setAutoRerunSignal] = createSignal<boolean>(loadInitial());

// The dirty flag is session-only — not persisted. A fresh reload always
// starts un-dirty because there are no in-session edits yet.
const [dirty, setDirtySignal] = createSignal<boolean>(false);

export const useAutoRerun = () => autoRerun;
export const useDirty = () => dirty;

/**
 * Set the auto-rerun preference. When flipping ON, also clear the dirty
 * flag — the upcoming `createEffect` re-run will catch up to the current
 * spec, so the "edits pending" banner would just be stale visual noise.
 */
export const setAutoRerun = (next: boolean): void => {
  setAutoRerunSignal(next);
  if (next) setDirtySignal(false);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, next ? "true" : "false");
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

export const setDirty = (v: boolean): void => {
  // Wrap so we drop the solid-js setter's return value — declared `: void`.
  setDirtySignal(v);
};
export const clearDirty = (): void => {
  setDirtySignal(false);
};

/** Test-only reset. Production code never calls this. */
export const __resetAutoRerunForTests = (): void => {
  setAutoRerunSignal(true);
  setDirtySignal(false);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
