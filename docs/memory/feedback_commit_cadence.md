---
name: Commit cadence — every batch of changes
description: After completing each batch of changes, commit to GitHub before moving to the next batch — don't accumulate unpushed work
type: feedback
originSessionId: 6b61fd45-f36d-4cdd-afa1-767f88971b99
---
After completing each batch of related changes, commit and push to GitHub before moving to the next batch.

**Why:** User explicitly requested this (2026-05-10) when starting the Cryptographer project. They want incremental, pushed history rather than one big commit at the end.

**How to apply:** Treat each completed task or coherent unit of work as a commit boundary. After finishing a feature, fix, or refactor batch — stage, commit with a meaningful message, push. Don't ask for re-confirmation on each commit; the standing instruction covers it. Continue to confirm before destructive operations (force-push, reset --hard, etc.).
