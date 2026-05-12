---
name: Preserve current trace frame across re-runs
description: When a re-run is triggered (manual Run button, param edit auto-rerun, mode swap), keep the scrubber on the same step the user was viewing — don't reset to frame 0. Applies to all current and future ciphers.
type: feedback
originSessionId: 546b09da-2f17-44cb-a183-39a4f500103a
---
When `setTrace(trace)` runs in `src/ui/stores/trace.ts`, do not reset `frameIndex` to 0. Instead, preserve the current frame by `stepId`:

1. Capture the current frame's `stepId` before swapping the trace.
2. Find the same `stepId` in the new trace's frames; set `frameIndex` to that position.
3. Fallback when the stepId is gone (removed/renamed): clamp the previous numeric index into the new trace's length.
4. First run (no previous trace): index 0.

This applies to every code path that creates a new trace — Run button, debounced auto-rerun after a param edit, encrypt/decrypt mode swap. The principle extends to all future ciphers, not just AES.

**Why:** the user explicitly requested this on 2026-05-11 with rationale: "if a user enters a changed value somewhere and clicks run, it would be more informative to see how this changes the values at the current frame." They wrote: "let this principle remain in the future for all manual changes on all future ciphers."

**How to apply:** any time you touch `setTrace`, the run flow, or introduce a new mechanism that produces a Trace, this preservation must come along. When building features like run-history snapshots (planned phase 2 in `docs/plans/suggestions-1-4.md`), per-run frame alignment in the comparison UI also uses `stepId` rather than raw indices for the same reason.
