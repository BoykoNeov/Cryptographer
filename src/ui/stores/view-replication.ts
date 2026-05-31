/**
 * View-replication store. Toggles the high-fanout-source replica transform
 * in the graph view (commit 4 of the graph-readability sequence).
 *
 * When ON, sources with more than `DEFAULT_REPLICATION_THRESHOLD` outgoing aux edges
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
 *     "auto" branch will reuse `DEFAULT_REPLICATION_THRESHOLD` as its default.
 *   - Exposing the threshold as a number input now adds UI surface that
 *     commit 5's per-node controls will subsume. Hardcoded 6 catches AES
 *     (11 round keys), Speck (22), and Serpent (32) cleanly while leaving
 *     small-fanout sources untouched.
 */

import { createSignal } from "solid-js";

/**
 * Default fanout threshold above which a source is eligible for "auto"
 * replication. Catches AES-128 key-expansion (11 round keys), Speck (22
 * round keys), Serpent (32 round keys), SHA-256's K/W/H-aux constants (64
 * each), AND SHA-256's `seed-schedule` history-seed fanout (4 — the four
 * lookback fetches inside `msg-schedule`). The user can override this at
 * runtime via the toolbar number input — see `useReplicationThreshold`.
 *
 * Lowered from 6 → 3 on 2026-05-26 alongside the introduction of the
 * `history-seed` synthetic aux edges (Slice S2(l) of
 * `docs/plans/sha-256-density-polish.md`). Predicate is strict `>`
 * (graph.ts:2136), so threshold 3 means "fanout ≥ 4 auto-replicates" —
 * the smallest setting that fans seed-schedule's 4 history-seed edges
 * out into the expanded msg-schedule body on first load. Blast radius
 * on shipped specs is empty: every other fanout source on AES / Speck /
 * Serpent / DES / SHA-256 is already ≥ 11.
 *
 * Why "default" (not "the" threshold): per-spec persistence of a numeric
 * threshold would land in `LayoutSpec`, which is the byte-stability surface
 * (`docs/versioning.md`); a missing-when-default discipline keeps Save/Share
 * deterministic, but adds noise to the spec layer for a knob most users
 * won't change. Session-only is the pragmatic v1 — power users adjust it,
 * the default ships everywhere else.
 */
export const DEFAULT_REPLICATION_THRESHOLD = 3;

/** Bounds for the toolbar's numeric input. Lower bound 1 (replicate on any
 * fanout above 1); upper bound a safe sentinel that exceeds any realistic
 * cipher's fanout (Serpent's 32 round keys is the current ceiling). */
export const REPLICATION_THRESHOLD_MIN = 1;
export const REPLICATION_THRESHOLD_MAX = 99;

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

/**
 * Session-only tracker: has the user explicitly toggled the replication
 * checkbox in THIS session? Used by GraphView to force replication ON for
 * port-native specs (e.g. SHA-256) where the high-fanout source-coloring
 * payoff is essential for legibility — but ONLY until the user makes their
 * own choice, after which we respect it across every spec.
 *
 * Why per-session (not persisted): the auto-on default for ported specs
 * is itself a pedagogical default; we don't want a user who toggled off
 * for AES six months ago to land on SHA-256 today with replication off,
 * confused by the chip wall. Each page reload re-prompts the auto-on
 * behavior; explicit in-session intent wins.
 *
 * Read in `GraphView`'s `replicate` memo: when this is false (user hasn't
 * toggled this session), replication defaults ON for every spec (all
 * port-native since Phase C).
 */
const [replicationUserToggledThisSession, setReplicationUserToggledThisSessionSignal] =
  createSignal<boolean>(false);

export const useReplicationUserToggledThisSession = () => replicationUserToggledThisSession;

export const setReplicationEnabled = (enabled: boolean): void => {
  setReplicationUserToggledThisSessionSignal(true);
  setReplicationEnabledSignal(enabled);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, enabled ? "true" : "false");
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

/**
 * Session-only signal for the user-adjustable fanout threshold. Lives at the
 * module scope so it shares the same boundary as `replicationEnabled` — both
 * are graph-view-global preferences, neither belongs in `LayoutSpec`.
 *
 * Why no persistence: keeps `LayoutSpec` byte-stable for share-URL hashing,
 * and avoids the "is `threshold: 6` an explicit user choice or just the
 * default?" ambiguity that bites the omit-when-default discipline elsewhere.
 * The user re-picks per session; the default catches every cipher we ship.
 */
const [replicationThreshold, setReplicationThresholdSignal] = createSignal<number>(
  DEFAULT_REPLICATION_THRESHOLD,
);

export const useReplicationThreshold = () => replicationThreshold;

/**
 * Set the active replication threshold. Out-of-range inputs are clamped
 * silently — a number-input's `min`/`max` attributes are advisory in most
 * browsers; pasting "999" still fires the change. Non-finite (`NaN`,
 * `Infinity`) falls back to the default.
 */
export const setReplicationThreshold = (value: number): void => {
  let next: number;
  if (!Number.isFinite(value)) {
    next = DEFAULT_REPLICATION_THRESHOLD;
  } else {
    next = Math.round(value);
    if (next < REPLICATION_THRESHOLD_MIN) next = REPLICATION_THRESHOLD_MIN;
    if (next > REPLICATION_THRESHOLD_MAX) next = REPLICATION_THRESHOLD_MAX;
  }
  setReplicationThresholdSignal(next);
};

/**
 * Session-only signal for the replication overrides panel's open/closed state.
 *
 * With the `fanout ≥ 1` filter the panel rarely empties — every cipher we
 * ship has at least one aux-edge source. The four panel rows then occupy
 * ~140 px of vertical real estate above the canvas, even for users who only
 * tuned one override and don't need to see the others. A collapse toggle
 * lets them close the panel after they're done.
 *
 * Why session-only (not in `LayoutSpec`): same reason as the threshold above
 * — UI state for a panel knob doesn't belong in the byte-stable share-URL
 * surface. The default is derived from "does this spec have any user-set
 * overrides?" — see `GraphView.tsx`'s effect that watches `spec().id` and
 * calls `setReplicationPanelOpen` accordingly on each spec change. That way
 * loading a spec with custom overrides shows the user *why* their canvas
 * looks the way it does, while a fresh spec stays decluttered.
 */
const [replicationPanelOpen, setReplicationPanelOpenSignal] = createSignal<boolean>(false);

export const useReplicationPanelOpen = () => replicationPanelOpen;

export const setReplicationPanelOpen = (open: boolean): void => {
  setReplicationPanelOpenSignal(open);
};

/** Convenience for the header click handler. */
export const toggleReplicationPanelOpen = (): void => {
  setReplicationPanelOpenSignal((prev) => !prev);
};

/** Test hard-reset. Production code never calls this. */
export const __resetReplicationForTests = (): void => {
  setReplicationEnabledSignal(false);
  setReplicationUserToggledThisSessionSignal(false);
  setReplicationThresholdSignal(DEFAULT_REPLICATION_THRESHOLD);
  setReplicationPanelOpenSignal(false);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
