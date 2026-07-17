# Cipher-agnostic block modes — `BlockCipherCore` + generic mode builders

> **Status (2026-07-17): Phases A + B + C ALL SHIPPED. The plan is closed.**
> Scope decided with the user: build the machine, prove it on **one 8-byte
> cipher (Blowfish)**, and **design for CTR without building it**. All three
> delivered.
>
> Phase C made the block-size-generic claim real: Blowfish ECB/CBC ships, and an
> 8-byte block now drives the mode builders, the iterate, the IV, and the padding
> overlay in the actual app rather than in a fake-core unit test. The remaining
> four ciphers (Speck/Serpent/DES/Twofish) are cheap follow-ups templated on
> `src/ciphers/blowfish-core.ts`; each costs its own seed-threading plus the
> three table rows.

## Context

Today only AES has ECB/CBC. `src/ciphers/aes-ecb-builder.ts` and
`aes-cbc-builder.ts` are ~90% cipher-agnostic mode logic that happens to call
AES-specific builders. Every other cipher is `single-block` only.

The user's ask, verbatim: *"can we make the machine as agnostic as realistic,
so that if at some point we have tens of ciphers, and several multi block
modes, we can implement the multi block modes on those ciphers relatively
easily, with less work"* — i.e. **N ciphers + M modes, not N × M**. Adding a
cipher should yield every mode; adding a mode should yield every cipher.

The stated blocker is a ghost. Five separate comments
(`padding.ts:113-138`, `cipher-mode.ts:67-77`) claim multi-block is blocked on
*"block-size-aware load-block/store-block (currently 16-byte-only)"* and that
*"the padding overlay is hardcoded for MatrixState"*. **`MatrixState` and those
matrix steps were retired in Phase 5 Slice 5.1 (2026-05-30).** The comments
describe a blocker that no longer exists. What actually remains is much
smaller — see "The real blocker set".

**Intended outcome:** a `BlockCipherCore` contract + mode builders that consume
it, so Blowfish ECB/CBC lands as a repeatable unit and the remaining four
ciphers become cheap follow-ups.

## What's already agnostic (verified, do not rebuild)

- **The runtime.** The port-mode `iterate` is fully block-size-generic:
  `blockByteLength` is a validated field (`runtime.ts:269-272`), no hardcoded 16.
- **Key schedules.** All five non-AES ciphers *already* expose the key schedule
  as a single top-level `StepNode` reading `aux["key"]`, publishing to aux, with
  zero `$input` dependency (`blowfish-spec-builder.ts:211`,
  `twofish-spec-builder.ts:354`, `des-key-schedule-builder-native.ts:116`,
  `serpent-key-schedule-builder-native.ts:233`,
  `speck-32-64-key-schedule-builder-native.ts:330`). `buildKeySchedule()` is a
  one-line wrap for each. Aux is global and crosses scopes freely — which is
  exactly why key-schedule-outside / body-inside works.
- **Group scoping.** Nesting a cipher body under an `iterate` is safe: nested
  groups resolve `seedInput` in the parent scope while that walk is live
  (`runtime.ts:213-224`). AES proves this today. The **only** scope violation is
  `$input`, which the runtime seeds at top scope only (`runtime.ts:1283-1289`).
- **IV plumbing** is mode-gated, never cipher-gated (`App.tsx:551`).

## Decisions

**1. The interface is designed against CTR, not just ECB/CBC.** CTR/CFB/OFB use
the **forward cipher only** (CTR *decryption* still encrypts the counter and
XORs) and need **no padding**. So the contract must not bake in "decrypt ⇒
inverse body" or "padding always applies", or CTR forces an interface rewrite —
the exact N×M tax we're removing.

```ts
// src/ciphers/block-cipher-core.ts  — AS SHIPPED (Phase A, 2026-07-17)
export interface BlockCipherCore {
  readonly id: string;                // NOT `Cipher` — see decision 1b
  readonly displayName: string;       // "AES-128" — the spec's `name`
  readonly familyName: string;        // "AES" — narration prose
  readonly blockByteLength: number;   // 16 AES/Serpent/Twofish, 8 DES/Blowfish, 4 Speck
  readonly keyByteLength: number;
  buildKeySchedule(): StepNode;
  /** Forward body. CTR/CFB/OFB call this for BOTH directions. */
  buildEncryptBody(seed: PortBinding): CipherBody;
  buildDecryptBody(seed: PortBinding): CipherBody;
}
export interface CipherBody {
  readonly nodes: readonly StepNode[];  // readonly — matches build*BodyNative
  readonly output: PortBinding;
}

export interface BlockMode {
  readonly id: string;
  readonly requiresPadding: boolean;  // ecb/cbc: true. ctr: false.
  readonly requiresIv: boolean;       // cbc/ctr: true. ecb: false.
  build(core: BlockCipherCore, direction: CipherDirection): CipherSpec;
}
```

**1b. `id` is a `string`, not the `Cipher` union — and the registry lives at
the consumption layer.** Nothing in `src/ciphers/` imports from `src/ui/`; the
dependency runs one way. Typing `id: Cipher` (as originally drafted) would
invert that layering for no gain: no mode builder branches on *which* cipher it
has, it only interpolates the id into a spec id. **A machine that enumerates the
cipher list is the very thing this interface exists to eliminate** — `id: Cipher`
isn't a lost type-safety win, it's the opposite of the goal. The `Cipher`-keyed
registry that maps a *selected* cipher to its core therefore lives in a
dedicated `src/ui/stores/block-cipher-cores.ts` (NOT hung off `spec.ts`: Phase B
needs `core.blockByteLength` in `padding.ts` and `iv.ts` too, and a registry
inside `spec.ts` risks a padding↔spec import cycle). Typed
`Partial<Record<Cipher, BlockCipherCore>>` — a total record would force all 11
cores to exist in Phase A, contradicting the phased rollout.

**Deferred to Phase B:** the registry itself. It has no consumer until the
Phase-B plumbing reads `blockByteLength` from it — `stores/spec.ts` imports
pre-built spec constants today. Landing it in Phase A would be dead code.
It is also the natural single source to later *derive*
`SUPPORTED_CIPHER_MODES_BY_CIPHER` from, collapsing one side of the two-table
gotcha.

**1c. `familyName` vs `displayName`.** The CBC narration prose says "AES", the
spec's `name` says "AES-128". Templating both from one field would have changed
AES's shipped prose ("Before AES runs" → "Before AES-128 runs") and broken the
Phase-A parity gate. Two fields keep AES byte-identical *and* generalize
correctly ("Before Blowfish runs").

`buildBody` must return an **explicit** `output` binding: Serpent and Speck have
no `outputFrom` today (they rely on the runtime's implicit last-leaf output,
which the iterate's required `bodyOutput` cannot use).

**2. Block size is a parameter, not a spec field — no schema change.**
`applyPaddingScheme(spec, mode, scheme)` gains a `blockByteLength` argument,
sourced from the core registry at the call site (`stores/spec.ts`). Rejected:
adding `CipherSpec.blockByteLength`, because the spec is serialized wholesale
into saved documents and a sometimes-present optional field threatens the
byte-stable-save property that URL-share hashes depend on. Deriving dodges the
`schemaVersion` question entirely.

**3. Single-block stays out of the abstraction.** Tempting to unify as
`buildBody($input)`, but single-block specs are the FIPS-197 first-impression
demo and the default. Rewriting them risks perturbing the canonical demo for no
user-visible gain. Prove on ECB/CBC (already builder-generated); fold in later
only if provably clean.

**4. Oracle = self-composed over the trusted core. Uniformly.**
`node:crypto` is **not** an option: verified on this machine (Node v24.14.1) that
`bf-cbc`/`bf-ecb`/`des-cbc`/`des-ecb` all fail with the OpenSSL 3 legacy-provider
error `0308010C:digital envelope routines::unsupported`, while `aes-128-cbc` is
`OK` (so the check is sound, not a harness artifact). This is fine and does
**not** violate `feedback_crypto_verification` ("external oracle BEFORE tests"):
that rule governs *new ciphers*. Blowfish's single-block core is already
KAT-verified against pycryptodome. ECB/CBC over an already-trusted primitive is
legitimately verified by composing the XOR-chain over that core inside the test.
Uniform across all five ciphers — no per-cipher oracle special-casing.

**5. Blowfish is the 8-byte proof.** With no oracle advantage either way, the
tiebreaker is surgery: Blowfish's `buildRound(roundIdx, pIdx, seedInput)`
(`blowfish-spec-builder.ts:305`) already takes a seed and its output binding is
named (`:470`). DES is a top-level **const, not a builder** (`des.ts:180`), with
IP/FP inline and double nesting — a worse first customer.

## The real blocker set (5 sites, all `16`) — ✅ all closed in Phase B

| # | Site | What | Resolution |
|---|---|---|---|
| 1 | `spec-mutations.ts` `AES_BLOCK_SIZE` + gate `isByteNativeAesSpec` | Padding overlay hardcodes 16 and is gated to AES **by spec-id prefix** | `blockByteLength` param + `overlayApplies`; both const and gate deleted |
| 2 | `stores/padding.ts` | `paddingLimits` is `isAesCipher`-gated; fixed one-block `min===max` per cipher, **ignoring `cipherMode`**. `MAX_BYTES = MAX_BLOCKS_UI * 16` | Derives from the core; `singleBlockLimits` fallback for coreless ciphers |
| 3 | `App.tsx` | `inputBytes.length % 16 !== 0`, message *"multiple of 16 bytes (whole AES blocks)"* | `% blockBytes`, cipher-named prose |
| 4 | `stores/iv.ts` | `IV_LENGTH = 16`; `setIvBytes` **throws** on any other length → DES/Blowfish need 8 | width is a param; `IvInput` takes a prop |
| 5 | `aes-cbc-builder.ts` `fetch-iv` `byteLength: BLOCK_SIZE` | — | **Already fixed in Phase A** (`modes/cbc.ts` reads `core.blockByteLength`) |

Site 2's switch **is already a per-cipher block-size table**, just badly
factored. It is NOT fully replaced yet: `core.blockByteLength` takes over per
cipher as cores land, and the switch is the fallback until every cipher has one.

## Phases

### Phase A — the contract, AES as first core (pure refactor) — ✅ SHIPPED 2026-07-17

1. ✅ `src/ciphers/block-cipher-core.ts` — interface only (registry deferred to
   Phase B, see decision 1b). Also rehomed `CipherDirection`, which was a
   generic `"encrypt"|"decrypt"` mis-filed in an AES file.
2. ✅ `src/ciphers/aes-core.ts` — `aesCore(variant)` wraps
   `buildAesKeyScheduleNative`, `buildAes{Encrypt,Decrypt}BodyNative`, and the
   output helpers. Also now hosts `AesVariant`.
3. ✅ `src/ciphers/modes/ecb.ts` + `modes/cbc.ts` — generic
   `buildEcbSpec(core, dir)` / `buildCbcSpec(core, dir)`. The AES-specific
   `aes-ecb-builder.ts` / `aes-cbc-builder.ts` were **deleted**, not shimmed:
   leaving no AES-specific mode code is the actual deliverable. The 4 thin spec
   files + 1 graph test were repointed (the test keeps its body verbatim via
   two local shims).

**Gate — passed, and stronger than planned.** The plan said "KATs stay
byte-identical", but KATs only assert ciphertext bytes: they'd pass even if a
node id or param drifted. The real gate ran instead — snapshot all 12 specs
(3 variants × ECB/CBC × encrypt/decrypt) before the refactor, deep-equal them
after (`node:util.isDeepStrictEqual`, not a string diff — key insertion order
would give false positives). Result: **12/12 deep-equal AND byte-identical
serialization**. Since frames are derived from the spec, a byte-identical spec
*guarantees* zero frame changes — a proof, not a sample. `tsc --noEmit` clean.

### Phase B — block-size-generic plumbing — ✅ SHIPPED 2026-07-17

The registry landed as planned (`src/ui/stores/block-cipher-cores.ts`,
`Partial<Record<Cipher, BlockCipherCore>>`, AES ×3). Site 5 (`fetch-iv`) turned
out to be **already fixed in Phase A** — `modes/cbc.ts` reads
`core.blockByteLength`. The other four:

1. ✅ `applyPaddingScheme(spec, mode, scheme, blockByteLength)` — the width is a
   **required, nullable** param, not optional. Optional would buy nothing (a
   3-arg call means "no overlay", so every existing test breaks either way) and
   would let a forgotten call site *silently* disable padding. `undefined` now
   means "the caller has no block cipher here" (hash/RSA/coreless cipher) and is
   what scopes the overlay — the `isByteNativeAesSpec` id-prefix gate is gone.
2. ✅ `paddingLimits` derives every bound from `core.blockByteLength`, honours
   `cipherMode`, and falls back to a fixed one-block `switch` for coreless
   ciphers (see "the switch stays" below).
3. ✅ `App.tsx` — `% blockBytes` + cipher-named prose; `formatLengthError` and
   the mode/padding selector gates key off `hasBlockCipherCore` instead of
   `isAesCipher`.
4. ✅ `iv.ts` — `setIvBytes(bytes, blockByteLength?)` / `randomizeIv(width)`.
   The width is passed IN (the App knows the active cipher; this module-scope
   signal doesn't, and reaching for the cipher store would invert the
   dependency). `IvInput` takes it as a prop.

Also purged the ghost comments, and **deleted the dead matrix multi-block
branch** in `applyPaddingScheme` (+ its two `hasIterateNode` /
`hasByteNativeIterate` helpers, whose only caller it was): every shipped
`iterate` is port-mode, and the aux-mode matrix iterate it served was retired
with `MatrixState` in Phase 5 Slice 5.1 along with the `split-blocks` steps that
made such a spec runnable at all.

**The switch stays — "core.blockByteLength replaces it outright" is only true
once EVERY cipher has a core.** Mid-rollout, `paddingLimits` still needs a width
for coreless ciphers, so `singleBlockLimits` keeps the per-cipher table. It
shrinks one entry per core landed; don't read "outright" as "delete it now."
Enumerating `Cipher` *here* is correct per decision 1b — the anti-pattern is
only in `src/ciphers/` mode builders.

**Early partial win — AES-192/256 ECB/CBC: shipped AND verified.** Generated
from the core in `spec.ts`'s `defaults` (`modesFromCore`) rather than as 8 new
`aes-192-ecb.ts`-style files — a file per (cipher × mode × direction) is the N×M
explosion this plan exists to kill. AES-128 keeps its file constants (~35
modules import them, some by reference).

The plan called this "a table-only change", i.e. correct by construction — so it
got a KAT anyway (`tests/aes-192-256-modes-kat.test.ts`), and it earned it:
`aesCore` at Nk=6/Nk=8 driving the mode builders was a path **no test had ever
run**, and its failure mode is silent (plausible-but-wrong ciphertext). Pinned
against the published SP 800-38A §F.1.3/§F.1.5/§F.2.3/§F.2.5 vectors *and*
`node:crypto`. 10/10 green.

**Verification — and its honest limit.** Gate green: 255 files / 3086 tests,
`tsc` clean, build clean. But **AES-192/256 gave ZERO non-16 coverage** — every
generalized path stays at 16 for AES, so `*blockBytes` / `%blockBytes` /
non-16 IV were correct-by-construction but unexercised. That gap is closed only
as far as unit tests can close it: `tests/block-size-generic-modes.test.ts`
feeds a **fake `BlockCipherCore` with an 8-byte block** to the real mode
builders and the real overlay, asserting the iterate splits at 8, `fetch-iv`
reads 8, and the pad's `blockSize` is 8. Pre-Phase-B that test fails twice over
(id-prefix gate rejects `fake-8-ecb@1`; `AES_BLOCK_SIZE` pads to 16).

**Phase B does NOT prove non-16 works in the app** — the fake core's body is a
passthrough leaf, not a cipher. That is Phase C's job (composed Blowfish CBC KAT
+ browser smoke). Don't let a green Phase B read as "8-byte blocks work."

**Phase C must decide:** the gate change couples "has a core" with "padding
overlay enabled **in single-block mode**". Today only AES has cores, so nothing
changes. But the day Blowfish gets a core it *also* gains PKCS#7 in single-block
— which it lacks today and which this plan lists as out of scope. Decide then
whether single-block padding follows core-presence or gets its own gate; a KAT
won't catch a first-impression demo quietly changing.

> **DECIDED in Phase C (user, 2026-07-17): option 1 — it follows core-presence.**
> See the Phase C section above for why the alternative was unwritable without
> re-encoding "AES is special". Note the framing above overstated the change: the
> padding default is `"none"`, so a fresh Blowfish load is unchanged; what moves
> is that the selector becomes clickable and the persisted scheme (one global
> preference shared across ciphers) starts applying.

### Phase C — Blowfish ECB/CBC (the repeatable unit) — ✅ SHIPPED 2026-07-17

1. ✅ `src/ciphers/blowfish-core.ts`. The seed-threading was smaller than
   budgeted: `buildRound` already took a `seedInput`, so only round 1's `$input`
   was hardcoded. Extracted `buildBlowfishBody(direction, seed) → {nodes, output}`
   (rounds + whitening, minus the key setup) and exported `buildKeySetup`;
   `buildBlowfishSpec` now delegates with `$input`.
2. ✅ Registered in all **three** tables (`BLOCK_CIPHER_CORES`, `defaults` via
   `modesFromCore`, `SUPPORTED_CIPHER_MODES_BY_CIPHER`).
3. ✅ Canary flipped. `blowfish` left `CORELESS_CIPHERS`; the
   "AES is exactly the set of ciphers with a core" pin was **inverted, not
   deleted** — it now asserts Blowfish has a core AND is not AES, which is what
   makes any surviving `isAesCipher` mode gate a bug.
4. ✅ `tests/blowfish-modes-kat.test.ts` — ECB **and** CBC (the plan named only
   CBC; ECB is a distinct builder path and the test was free).

**Refactor gate (as in Phase A, and it earned its keep):** snapshotted both
canonical Blowfish specs before the extraction, `isDeepStrictEqual` after —
2/2 byte-identical, so the single-block demo provably did not move a frame.

**The padding decision (the "Phase C must decide" item below): option 1 —
padding follows core-presence.** Blowfish gains PKCS#7 in single-block, as AES
has had since May 2026. The alternative needed a gate that could only encode
"AES is special": either resurrecting `isAesCipher` (the anti-pattern A+B
deleted) or a `supportsSingleBlockPadding` flag true for AES and false for
Blowfish for no discoverable reason. The one non-arbitrary variant — gate padding
on `cipherMode !== "single-block"` — regresses AES. Pinned by
`tests/blowfish-padding-overlay.test.ts`, which asserts OUTPUT BYTES rather than
`params.blockSize`: a param check passes even on a pad that is spliced in but
consumed by nothing.

**A real bug the browser smoke caught — see "IV width" below.**

**This phase is the template.** Remaining four ciphers = repeat C, cost
dominated by seed-threading (Serpent has an explicit `TODO(multi-block)` at
`serpent-round-builder.ts:209-212`; DES needs the const→builder extraction).

### Phase C addendum — the IV width bug (found by LOOKING, not by testing)

The Phase C smoke screenshotted Blowfish + CBC and showed a **16-byte IV**
(`000102…0f`, the AES default) in the field of a cipher whose block is 8.
`IvInput` passes Blowfish's 8 to `setIvBytes`, which throws on a mismatch — so
**the field displayed a value it would itself have rejected.** Phase B made the
IV width a *parameter* but never re-defaulted the *stored* value, which is
persisted and module-scope while `cipher`/`cipherMode` are session-only.

Fix: `reconcileIvWidth(blockByteLength)` in `stores/iv.ts`, called from BOTH
`changeCipher` and the cipher-mode `onChange`. The mode trigger is the one a
cipher-only fix misses — land on Blowfish in single-block (IV inert), flip to
CBC, and no cipher change fires. `DEFAULT_IV` is now generated by
`defaultIvOfWidth(n)` (the ascending run `00 01 02 …`), which reproduces the
published SP 800-38A §F vector byte-identically at n=16 and extends free to any
width. Deliberately in the two handlers rather than a global effect, which could
clobber the IV `applyDocument` just restored.

**Why no KAT for this, and the lesson:** the 16-byte default truncated to 8 by
the runtime's port-length coercion is `0001020304050607` — byte-identical to the
correct 8-byte default. Broken and fixed produce the **same ciphertext**
(confirmed: `af2dfa9b…` both ways). The defect is the stored/displayed VALUE, so
`tests/iv-width-reconcile.test.ts` pins that, and its sharpest assertion is that
the reconciled IV is one `setIvBytes` *accepts* at the same width. The drift also
runs BOTH ways: an 8-byte IV left from a Blowfish session survives a reload onto
AES + CBC.

## Critical files

**New:** `src/ciphers/block-cipher-core.ts`, `aes-core.ts`, `blowfish-core.ts`,
`modes/ecb.ts`, `modes/cbc.ts`, `tests/blowfish-cbc-kat.test.ts`.

**Modified:** `src/ciphers/aes-ecb-builder.ts`, `aes-cbc-builder.ts`,
`blowfish-spec-builder.ts` (seed threading), `src/core/spec-mutations.ts`
(padding param), `src/ui/stores/padding.ts`, `iv.ts`, `cipher-mode.ts`,
`spec.ts`, `src/ui/App.tsx`, `tests/cipher-mode-fallback.test.ts`.

**Reused, not rebuilt:** the port-mode `iterate` runtime; every
`build*KeyScheduleNative`; `applyPaddingScheme`'s byte-native branch;
`deriveAuxGraph`/`validateGraph`.

## Verification

1. **Phase A parity (the load-bearing gate):** `npx vitest run tests/aes-128-cbc-kat.test.ts tests/aes-128-ecb-kat.test.ts` — byte-identical, zero frame changes.
2. **Regression:** `tests/multi-block-padding-boundary.test.ts`, `spec-mutations-padding.test.ts`, `runtime-iterate*.test.ts`, `app-cbc-iv-flow.test.tsx`, `app-multi-block-roundtrip.test.tsx`, `port-sources.test.ts`.
3. **Phase C correctness:** composed-oracle Blowfish CBC KAT (multi-block, non-16 block, chain across ≥3 blocks).
4. **Browser smoke — required, not optional.** Per `feedback_visual_smoke_vs_property_tests`: `npm run dev`, pick Blowfish + CBC, enter >8 bytes, confirm the IV field accepts **8** bytes, padding selector enables, the graph draws per-block iterate chips, and the linear view scrubs `:b{i}` frames. Property tests cannot catch "the mode selector never appeared".

   **Phase B smoke — DONE 2026-07-17** (throwaway spec, deleted after per
   `feedback_playwright_dormant`). Real Chromium: AES-192 + CBC — the mode
   dropdown *enables* (the `isAesCipher` → `hasBlockCipherCore` gate), the IV
   field appears, and a Run driven entirely through the real selectors produced
   the published §F.2.3 ciphertext; AES-256 + ECB reachable and error-free;
   Blowfish keeps mode + padding *disabled* (the other half of the gate). 3/3.
   **Gotcha that cost a cycle:** another project's dev server held port 5173, and
   `reuseExistingServer: true` made Playwright drive **that app instead** —
   3 failures reading as "element(s) not found". See
   `feedback_playwright_port_collision`.
5. **Gate:** `npm run check` (~130s warm; cold >3min — background it).

## Out of scope

CTR/CFB/OFB implementation (designed for, not built); DES/Serpent/Twofish/Speck
rollout (cheap follow-ups once C is the template); folding single-block into the
abstraction; variable-length Blowfish key; GCM/AEAD.
