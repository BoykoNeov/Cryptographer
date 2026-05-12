---
name: AES & cryptography pitfalls in this project
description: Algebraic identities and spec-reading gotchas Claude has stumbled on while working on the Cryptographer project — verify these before asserting anything cryptographic
type: feedback
originSessionId: 6b61fd45-f36d-4cdd-afa1-767f88971b99
---
When working on AES (or any block cipher) code in the Cryptographer project, there are a handful of facts Claude has actually got wrong in this codebase. Verify these before writing tests or asserting intermediate values.

**Why:** Each of these caused a failing test or a wrong assertion in this project's git history. The mistakes are subtle enough that compile + lint + a passing local check don't catch them — they pass through and only surface when you run a known-answer test against an external reference.

**How to apply:** Before writing or revising any AES test, intermediate-state assertion, or cipher-logic claim, walk through the relevant item below.

## FIPS-197 has multiple appendices with different keys

Appendix B uses key `2b7e151628aed2a6abf7158809cf4f3c` and plaintext `3243f6a8...`.
Appendix C.1 uses key `000102030405060708090a0b0c0d0e0f` and plaintext `00112233...ff`.
Appendix C.2 uses a 24-byte AES-192 key.

Don't quote a value from one appendix to test a vector from another. The first time this came up in the project, an expanded-round-key value from A.1 was used to assert against a C.1 run — they didn't match, and the test failed for "the wrong reason."

## SubBytes and ShiftRows commute

Both are byte-wise permutations. Swapping their order in a round produces *identical* ciphertext. This is a well-known algebraic identity used by efficient AES implementations (the "T-table" optimization).

If you're writing a test that says "reordering steps changes the output," swap **ShiftRows ↔ MixColumns** instead — those genuinely don't commute.

## AES state matrix is column-major

Byte at row `r`, col `c` is at `bytes[r + 4*c]`. The first 4 bytes of the input go into column 0 (top-to-bottom), not row 0 (left-to-right). Many visualization conventions get this wrong.

When eyeballing intermediate states like `193de3bea0f4e22b9ac68d2ae9f84808`, the first column is `19 a0 9a e9` (rows 0..3 of column 0).

## GF(2^8) polynomial is `x^8 + x^4 + x^3 + x + 1` (= 0x11b)

The reduction-when-MSB-is-set part of `xtime` uses 0x1b, but that's NOT the polynomial itself; it's the polynomial minus the leading `x^8` bit. Don't mix them up.

## Key expansion uses the FORWARD S-box even when decrypting

Both `aes-128.ts` and `aes-128-decrypt.ts` register the same `aes.key-expansion@1` step verbatim, with the forward S-box passed as a param. The inverse cipher consumes the same round keys in reverse order; it does not re-derive them with the inverse S-box.

## Solid-specific: createMemo for derived values read multiple times

A plain accessor function `() => computeStuff()` re-evaluates on every read. If you reference it three times in JSX, you compute three times. Use `createMemo` for any derived value that's read more than once per render — `StepStrip` had this exact bug before the cleanup commit.

## Windows PowerShell: don't `2>&1` native commands

PowerShell 5.1 wraps native command stderr lines in `NativeCommandError` records and sets `$?` to false even when the exit code was 0. Captured stdout looks fine, but error handling fires falsely. Use bash via the Bash tool when you need stderr handling.
