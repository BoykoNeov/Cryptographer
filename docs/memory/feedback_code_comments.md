---
name: Code commenting style — comment often
description: When writing code for this user, add comments frequently — explain what sections do, reference specs, note non-obvious choices
type: feedback
originSessionId: 6b61fd45-f36d-4cdd-afa1-767f88971b99
---
Add comments frequently when writing code for this user. Explain what blocks of code do, reference relevant specs/standards (e.g. "FIPS-197 §5.2"), note non-obvious choices, and document parameter contracts at the top of step executors.

**Why:** User explicitly requested this (2026-05-10) on the Cryptographer project. Default Claude Code instructions say "default to writing no comments" — this user overrides that. Likely reason: educational/exploratory project where the *user themselves* will read and learn from the code, not just maintain it.

**How to apply:** Override the default "comments only when WHY is non-obvious" rule. Add per-file headers that explain purpose, per-function docstrings or short descriptions, inline comments at non-obvious branches, and spec citations where the code implements a published algorithm. Don't go overboard with redundant `// increment i` style — comments should still be useful, just much more frequent than the default. This applies to .ts/.tsx code but probably not to JSON/CSS unless the user signals otherwise.
