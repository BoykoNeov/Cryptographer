# ChaCha20 — the first stream cipher (RFC 8439)

Status: **P1–P4 SHIPPED 2026-07-20** · P5 (diagrams) OPEN

> **Shipped:** `rotate-bits-left@1` (`09fe61b`), the cipher + KAT (`1d2d0b9`),
> the UI wiring + `"stream"` mode (`cf2510f`). What follows is the plan as
> approved; deviations found during the build are recorded at the end.

## Context

Every cipher in the app so far is a block cipher. That was invisible while it
was universally true: `hasBlockCipherCore(cipher)` doubles as "gets a mode
dropdown + a padding selector", `cipherModeUsesIv` is keyed on the *mode*, and
`isCipher(algorithm)` is the gate for the whole symmetric UI block. RSA escaped
all of it by living in a different `category`; ChaCha20 cannot, because it is
genuinely a symmetric cipher.

ChaCha20 is worth building for three reasons beyond "one more cipher":

1. **It is the first cipher with no `BlockCipherCore`** — so it is the first
   real exercise of the `Partial<Record<Cipher, …>>` in
   `stores/block-cipher-cores.ts`, whose absence-is-meaningful shape has been
   load-bearing-in-theory since Twofish closed the table.
2. **It is a counter-mode stream cipher that is not a *mode*.** The keystream
   machinery — `iterate` at a fixed block width, `allowPartialFinalBlock`,
   `truncate-to-reference@1`, `xor@1`, `increment-counter@1` — is exactly
   CTR's, but reached without a `BlockCipherCore` in sight. If the `iterate`
   runtime is as decoupled from the mode machine as it claims, this proves it.
   (Verified: `runtime.ts:257-392` dispatches on `seedInput !== undefined` and
   mentions no cipher, core, or mode.)
3. **It is natively little-endian**, and the ARX vocabulary is big-endian.

Intended outcome: ChaCha20 in the cipher dropdown, encrypting messages of any
length ≥ 1, with a fully decomposed and scrubbable quarter-round.

**Scope decision (user):** ChaCha20 only. Salsa20 shares the ARX primitives but
has a different quarter-round update order, a different state layout
(constants at 0/5/10/15), and column-then-**row** instead of
column-then-diagonal — separate wiring *and* a separate diagram. It is a real
second phase, not a freebie, and is out of scope here.

## Locked design decisions

### 1. `"stream"` is a new `CipherMode`, not a new predicate

ChaCha20 is `isCipher`-true, so it falls inside the symmetric UI block
(`App.tsx:1645`) and needs padding suppressed and an IV field shown. Two ways:

- an `isStreamCipher(cipher)` predicate OR'd in at every site — **7 sites**
  (`cipherModeUsesIv` ×3, `isStreamCipherMode` ×4), which is the
  "wired into 2 of 3 fails silently" footgun CLAUDE.md names, freshly duplicated;
- a sixth `CipherMode`, `"stream"` — **0 new sites**. `isStreamCipherMode`
  and `cipherModeUsesIv` each gain one arm and everything downstream (padding
  disengagement at all three sites, aux seeding, session export, the IV field)
  falls out of predicates that already exist.

Going with `"stream"`. It also keeps the persisted document honest — storing an
unbounded stream cipher as `"single-block"` would be a lie in the save file.
`SUPPORTED_CIPHER_MODES_BY_CIPHER.chacha20 = ["stream"]` and nothing else; the
mode `<select>` shows one enabled entry.

**Watch:** `spec.ts`'s `resolveDefault` / `setCipher` fall back to
`"single-block"` when the active mode is unsupported. ChaCha20 is the first
cipher that does **not** support `"single-block"`, so that fallback needs to
resolve to the cipher's first supported mode rather than a hardcoded constant.

**Also:** the mode `<select>` hardcodes its `<option>`s (`App.tsx:1667-1730`).
Rather than paste a seventh, render them from `SUPPORTED_CIPHER_MODES` with
`<For>` — same behaviour, and the next mode costs nothing.

### 2. Words travel the ports BIG-ENDIAN; add `rotate-bits-left@1`

`add-mod-32@1` and `rotate-bits-right@1` are big-endian-hardcoded
(`decodeBE32`). Twofish already set the precedent
(`twofish-spec-builder.ts:6-9`): travel BE, localize the LE↔BE crossing to
**visible `permute@1` word-reversals at the endpoints**. That gets
`add-mod-32@1` and `xor@1` for free.

Rotations do **not** come for free, and this is where the cheap answer is
wrong. ChaCha's rotations are all left; expressing them as
`rotate-bits-right@1` with `bits = 32 − n` renders the quarter-round as
**16/20/24/25** where RFC 8439 says **16/12/8/7**. For a tool whose entire
purpose is that the user reads the trace against the spec, that is a real
regression. So: **one new bare-name primitive, `rotate-bits-left@1`** — a
mirror of `rotate-bits-right.ts`, same `{ bits, wordBits }` params.

Rotation is defined on the 32-bit *value*, independent of serialization, so
`ROL n` on a BE-travelling word is honest.

### 3. The counter rides `chain` as a 4-byte word — nothing wider

`increment-counter@1` is big-endian over the **whole input port**. Carrying
`counter‖nonce` (16 bytes, the CTR-lookalike shape) would be **wrong**: a BE
increment over 16 bytes carries into the nonce and mis-orders the LE counter.
Carrying the 4-byte counter word alone, BE-serialized, makes
`increment-counter@1` exactly a 32-bit `+1` with wraparound at 2³² — which is
RFC 8439's rule (no carry into the nonce). Existing step, no changes.

### 4. Nonce + counter share `aux["iv"]` as a 16-byte `counter(4, LE) ‖ nonce(12)`

Matches OpenSSL's ChaCha20 IV layout exactly, so the existing IV field and
`aux["iv"]` slot serve with zero new plumbing — CTR's stated philosophy
(`ctr.ts:116-120`). Unlike CTR's IV this blob has real internal structure, so
the IV field gets a ChaCha-specific caption naming which bytes are which.

**The default IV's counter word is 1, not 0.** RFC 8439 §2.3.2 and §2.4.2 both
start at 1; an initial-counter off-by-one is the classic ChaCha bug and
produces plausible-looking wrong output. Pin it to the RFC, not to recall.

### 5. No key schedule; encrypt and decrypt are the same spec

ChaCha20 has no key expansion — the key enters the state directly. It is loaded
**inside** the iterate body via `aux-load-bytes@1` on `aux["key"]` (aux is
global and crosses the iterate scope freely), which is honest: the key really
does enter every block's state.

Because the message meets only an XOR, encrypt and decrypt are structurally
identical specs — CTR's and OFB's symmetry. **This means round-trip proves
nothing** (the same trap OFB documented): one spec used both ways round-trips
by construction even if the whole quarter-round is wrong. Verification budget
goes elsewhere — see below.

## Spec shape

State = 16 words, travelling as 16 separate 4-byte word ports rather than one
64-byte buffer, so a quarter-round wires the four words it touches and the
other twelve simply keep their previous binding. No split/concat churn between
rounds.

```
aux["key"]  ──aux-load-bytes──► permute (8× word reversal, LE→BE) ──► k0..k7
aux["iv"]   ──aux-load-bytes──► byte-slice[4..16] ──► permute (3×) ──► n0..n2
constant-load "expa nd 3 2-by te k"                                ──► c0..c3
port(iterate,"chain")                                              ──► counter (already BE)

state = [c0..c3, k0..k7, counter, n0..n2]

rounds (group, default-collapsed)
  double-round.0 … double-round.9        (group each)
    qr.column.0..3, qr.diagonal.0..3     (group each — 12 leaves)
       a+=b · d^=a · d<<<16 · c+=d · b^=c · b<<<12
       a+=b · d^=a · d<<<8  · c+=d · b^=c · b<<<7

final-add   16× add-mod-32@1  (working word + original state word)
serialize   16× permute (BE→LE) ──► concat(16) ──► keystream (64 B)
```

Iterate tail, copied verbatim from `ctr.ts:322-338`:

| leaf | type | wiring |
|---|---|---|
| `chacha-trim` | `truncate-to-reference@1` | `input: keystream`, `reference: port(iterate,"in")` |
| `chacha-xor` | `xor@1 {inputCount:2}` | trimmed keystream ⊕ message block → `bodyOutput` |
| `chacha-increment` | `increment-counter@1` | `counter: port(iterate,"chain")` → `chainFeedback` |

Iterate: `blockByteLength: 64`, `allowPartialFinalBlock: true`,
`chainInput` = the BE counter word bootstrapped from `aux["iv"][0..4]`.

**Frame budget:** 80 quarter-rounds × 12 leaves ≈ 1000 leaves per 64-byte
block — comparable to SHA-256's per-block count, which ships fully decomposed.
Default plaintext should be one block; consider SHA-256's precedent of a
trace-legibility input cap.

## Phases

Crypto lands verified before the UI seam is touched.

**P1 — primitive + quarter-round.** `rotate-bits-left@1` (+ its own test file,
same commit — the pre-commit hook enforces it). Quarter-round builder. Gate:
RFC 8439 **§2.1.1** QR test vector.

**P2 — block function + keystream.** Full 20-round state, final add, LE
serialization. Gate: RFC 8439 **§2.3.2** block-function vector (the 64-byte
keystream, byte-exact).

**P3 — iterate + encryption.** Multi-block fold, partial final block, XOR.
Gate: RFC 8439 **§2.4.2** encryption vector + `node:crypto` `chacha20` across
the full length range including `L < 64` and non-multiples of 64.

**P4 — UI + `"stream"` mode.** All the registration tables, the mode taxonomy,
the annotated IV caption, `ParamEditor` blurb.

**P5 — diagrams.** Canonical quarter-round graph cell (`core/chacha-shape.ts` +
`core/chacha-layout.ts`, recognized by wiring, no spec tag — the
`twofish-shape.ts` model) plus a linear `<ChaChaQuarterRoundDiagram />` over a
pure `core/chacha-diagram.ts` presentation model.

## Critical files

**New:** `src/steps/rotate-bits-left.ts`; `src/ciphers/chacha20.ts` (spec
builder); `src/core/chacha-shape.ts`, `src/core/chacha-layout.ts`,
`src/core/chacha-diagram.ts`; `src/ui/components/ChaChaQuarterRoundDiagram.tsx`.

**Registration tables** (all compiler-enforced except where noted):
`src/ui/stores/cipher.ts` — the `Cipher` union, `ALL_CIPHERS` (**not**
type-checked — a miss silently omits the dropdown option), `CIPHER_LABELS`,
`CIPHER_DESCRIPTIONS`, `CIPHER_HISTORY`, `DEFAULT_{KEY,PT,CT}_BYTES_BY_CIPHER`;
`src/core/document-schema.ts` — `CIPHER_IDS` **and** `CIPHER_MODES` (both have
exhaustiveness asserts that surface as a cryptic
`Type 'true' is not assignable to type 'never'`);
`src/ui/stores/cipher-mode.ts` — `CipherMode`, `SUPPORTED_CIPHER_MODES`,
`SUPPORTED_CIPHER_MODES_BY_CIPHER`, `CIPHER_MODE_LABELS`, and the new arm on
`isStreamCipherMode` + `cipherModeUsesIv`; `src/ui/stores/spec.ts` — `defaults`
and the `resolveDefault`/`setCipher` fallback; `src/ciphers/default-registry.ts`.

**Gates that will go red and need a conscious edit:**
- `tests/ctr-all-cores-kat.test.ts:198` — asserts
  `ALL_CIPHERS.every(c => hasBlockCipherCore(c))`. ChaCha20 is the first
  counterexample; this is the pin doing its job.
- `tests/port-provenance-coverage.test.ts` **and** `tests/port-provenance.test.ts`
  — `rotate-bits-left@1` is a bare name, so it needs an entry in
  `PROVENANCE_NO_OP_ALLOWLIST` (`core/port-provenance.ts:332`, rationale
  "approximate", exactly like `rotate-bits-right@1` at `:343`) **and** in the
  test's own literal copy.
- `tests/param-editor-coverage.test.tsx` — walks every leaf of every shipped
  spec; `rotate-bits-left@1` reuses `rotate-bits-right@1`'s `<Match>` block.
- `tests/default-ciphertext-table.test.ts`, `tests/cipher-mode-fallback.test.ts`,
  `tests/byte-native-ports-contract.test.ts` (ports must be `layout: "raw"`).

Not applicable: the narration contract test (port-native steps omit
`shapeContract` and skip it — but see verification), and
`cross-mode-mirror-registry` (ChaCha20 has no class-1/2 params, and encrypt and
decrypt share one spec).

## Verification

**External oracle first**, per the project rule — and already run:
`node:crypto`'s `chacha20` with IV = `counter(4, LE) ‖ nonce(12)` reproduces
RFC 8439 §2.4.2 byte-exactly. Confirmed in this session, counter starting at 1.

`tests/chacha20-kat.test.ts`, ranked by what actually discriminates:

1. **RFC 8439 §2.1.1** — the quarter-round in isolation.
2. **RFC 8439 §2.3.2** — the 64-byte block-function keystream. The primary
   anchor: it pins the rotation constants, the state layout, the LE
   serialization, and the counter start all at once.
3. **RFC 8439 §2.4.2** — full encryption, multi-block.
4. **`node:crypto` `chacha20`** across the length range: 1, 63, 64, 65, 127,
   128 bytes — the partial-final-block path in both directions.
5. **Counter-advance contrast** — block *n*'s keystream must equal the block
   function at counter `initial + n`. Catches a counter that fails to advance,
   the failure a single-block KAT cannot see.
6. **Round-trip, ranked LAST** — it is a tautology here (one spec used both
   ways) and proves nothing on its own. Documented as such in the test file, on
   the OFB precedent.

**Perturbation, run rather than assumed** (the OFB/CFB discipline): flip each
rotation constant to its ROR complement and confirm the suite goes red; start
the counter at 0 and confirm §2.4.2 fails. If either stays green, the test is
not testing what it claims.

**Browser smoke, not just tests.** Two things the unit suite structurally
cannot see, both of which have bitten this project before: the quarter-round
cell must actually *render* as a cell (Twofish's round split needed
`never`-replication or it scattered into chips — check ChaCha's word fanout
against the replication threshold), and a bare-name port-native step can ship
with **zero narration** while CI stays green. Scrub to a `rotate-bits-left@1`
frame in the browser and read what it says.

Finally: `npm run check`, and a `docs/gotchas.md` + `README.md` + `CHANGELOG.md`
pass, since the user-visible surface gains a cipher and a mode.


## What the build changed vs this plan

Three things the plan got wrong or did not anticipate. All were found by
checking rather than by assuming, and all are now in `docs/gotchas.md`.

1. **Quarter-round groups are not representable.** The plan sketched
   `rounds > double-round > qr` as nested groups. A group body is seeded with
   exactly ONE value (`port(groupId, "in")`), and a quarter round consumes
   four words. Only the double round — which consumes and produces the whole
   64-byte state — can be a group. This is the same constraint that keeps
   Twofish's 4-rail rounds flat, and it should have been checked before the
   spec shape was drawn.

2. **`permute@1` takes `indices`, not `permutation`.** The exploration pass
   reported the wrong param name; the executor was read before use. Exactly the
   port-native param-name divergence `docs/gotchas.md` already warns about.

3. **The IV bug, which no test could have caught.** Plan decision #4 assumed a
   ChaCha-specific default IV would be enough. It was not: `reconcileIvWidth`
   short-circuits when the width is unchanged, and AES and ChaCha20 both want
   16 bytes — so the canonical default never landed and the block counter
   silently started at `0x03020100`. The whole suite stayed green because every
   test supplies the IV explicitly. Found by opening the app in a browser, and
   the reason `tests/app-chacha20-stream.test.tsx` exists.

Also worth recording: the plan's frame-count estimate (~1000 leaves/block) was
right — 995 — and the double-round grouping keeps the graph at ~123 rendered
SVG groups rather than a chip wall.

## P5 — remaining

Canonical quarter-round graph cell (`core/chacha-shape.ts` +
`core/chacha-layout.ts`, recognized by wiring on the `twofish-shape.ts` model)
and a linear `<ChaChaQuarterRoundDiagram />` over a pure
`core/chacha-diagram.ts`. **Not started — and this is APPROVED SCOPE that
remains outstanding, not an optional follow-up.** The user selected
"QR graph layout + linear diagram" explicitly when this plan was agreed.
Twofish deferred its diagrams, but that was Twofish's own call and the
precedent does not transfer to work asked for up front.

Two consequences of P5 being absent, both confined to it:

- Expanding a double-round container in the graph shows a raw 96-leaf stack
  rather than eight readable quarter-round cells. The groups ship
  default-collapsed so first render is fine, but the canonical cell is what
  makes an expanded round legible.
- The round split's port fanout should be checked against the replication
  threshold when the cell lands — Twofish needed `never`-replication on its
  round members or the cell scattered into per-consumer chips, and that was
  caught by browser smoke rather than by unit tests.
