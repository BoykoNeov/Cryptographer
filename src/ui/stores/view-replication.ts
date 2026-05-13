/**
 * View-replication store. Toggles the high-fanout-source replica transform
 * in the graph view (commit 4 of the graph-readability sequence).
 *
 * When ON, sources with more than `REPLICATION_THRESHOLD` outgoing aux edges
 * are visually replicated next to each consumer — so AES-128's
 * `key-expansion` (11 outgoing roundKey edges) renders as 11 small chips
 * scattered through the round groups instead of one node on the far left
 * with 11 long lines fanning across the whole canvas. Shortens edges, but
 * grows canvas height (each round group gains an extra row).
 *
 * Default OFF: replication changes the picture significantly for AES, and
 * "edges fanning out from one source" is a legitimate pedagogical view too
 * (it makes the "one key schedule, many consumers" structure visible). The
 * user opts in via the graph toolbar.
 *
 * Why a global bool + constant for v1 (not a numeric input or per-node mode):
 *   - Commit 4 ships the global threshold (this file).
 *   - Commit 5 will add per-node modes (`auto` / `always` / `never`); the
 *     "auto" branch will reuse `REPLICATION_THRESHOLD` as its default.
 *   - Exposing the threshold as a number input now adds UI surface that
 *     commit 5's per-node controls will subsume. Hardcoded 6 catches AES
 *     (11 round keys), Speck (22), and Serpent (32) cleanly while leaving
 *     small-fanout sources untouched.
 */

import { createSignal } from "solid-js";

/**
 * Fanout threshold above which a source is eligible for replication. Hard-
 * coded for v1 to keep the user-facing surface a simple on/off toggle.
 * Commit 5 will surface per-node overrides; this constant becomes the
 * default for the "auto" mode there.
 */
export const REPLICATION_THRESHOLD = 6;

const STORAGE_KEY = "cryptographer.replicationEnabled";

const loadInitial = (): boolean => {
  // Defensive: missing localStorage / private mode / disabled cookies all
  // fall back to OFF (the conservative default).
  try {
    if (typeof localStorage === "undefined") return false;
    return localStorage.getItem(STORAGE_KEY) === "true";
  } catch {
    return false;
  }
};

const [replicationEnabled, setReplicationEnabledSignal] = createSignal<boolean>(loadInitial());

export const useReplicationEnabled = () => replicationEnabled;

export const setReplicationEnabled = (enabled: boolean): void => {
  setReplicationEnabledSignal(enabled);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, enabled ? "true" : "false");
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

/** Test hard-reset. Production code never calls this. */
export const __resetReplicationForTests = (): void => {
  setReplicationEnabledSignal(false);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
