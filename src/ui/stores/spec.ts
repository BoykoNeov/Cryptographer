/**
 * Spec store. Holds the currently-displayed CipherSpec plus the UI
 * dimensions that select among the available canonical specs:
 *   • mode        — "encrypt" | "decrypt"
 *   • cipher      — "aes-128" | "aes-192" | "aes-256" | "speck-*"  (stores/cipher.ts)
 *   • cipherMode  — "single-block" | "ecb" | "cbc" | "ctr"          (stores/cipher-mode.ts)
 *
 * Together they pick from `defaults[cipher][cipherMode][mode]`. The padding
 * store is a fourth, orthogonal preference layered on TOP of the chosen
 * spec via `applyPaddingScheme`.
 *
 * Edits go through this module so the UI never builds new specs by hand —
 * all mutations route through src/core/spec-mutations.ts, which guarantees
 * the readonly tree is rebuilt correctly and reference equality holds on
 * untouched branches (cheaper Solid re-renders).
 *
 * Non-AES ciphers (Speck32/64) only support "single-block" today. The
 * defaults table records this with a partial inner record, and
 * `resolveDefault` falls back to single-block if a requested mode is
 * missing for the active cipher. That fallback lets the user pick "ECB"
 * for AES-128, then flip cipher to Speck without crashing — they just
 * land back in single-block on the Speck side.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128CbcDecryptSpec } from "@/ciphers/aes-128-cbc-decrypt";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes128EcbDecryptSpec } from "@/ciphers/aes-128-ecb-decrypt";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes192DecryptSpec } from "@/ciphers/aes-192-decrypt";
import { aes256Spec } from "@/ciphers/aes-256";
import { aes256DecryptSpec } from "@/ciphers/aes-256-decrypt";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
import type { CipherDocument } from "@/core/document";
import {
  type PaddingScheme,
  applyPaddingScheme,
  duplicateRoundGroup,
  findStepAndParent,
  insertStepAfter,
  insertStepBefore,
  removeStep,
  updateAllStepsByType,
  updateStepParams,
} from "@/core/spec-mutations";
import type { CipherSpec, Json, StepLeaf, StepNode } from "@/core/types";
import { createSignal } from "solid-js";
import { type Cipher, setCipher as setCipherSignal, useCipher } from "./cipher";
import {
  type CipherMode,
  isCipherModeSupported,
  setCipherMode as setCipherModeSignal,
  useCipherMode,
} from "./cipher-mode";
import { setByteFormat } from "./format";
import { setIvBytes } from "./iv";
import { renameSpecLayoutIds } from "./layout";
import { setPaddingScheme, usePaddingScheme } from "./padding";

// ─── Mode ────────────────────────────────────────────────────────────────

export type Mode = "encrypt" | "decrypt";

// 3D table of canonical specs: defaults[cipher][cipherMode][mode]. The
// inner per-cipherMode record is partial — Speck only supports
// single-block today; AES-128 ships single-block + ecb in Phase 1, with
// cbc/ctr arriving in later phases.
const defaults: Record<Cipher, Partial<Record<CipherMode, Record<Mode, CipherSpec>>>> = {
  "aes-128": {
    "single-block": { encrypt: aes128Spec, decrypt: aes128DecryptSpec },
    ecb: { encrypt: aes128EcbSpec, decrypt: aes128EcbDecryptSpec },
    cbc: { encrypt: aes128CbcSpec, decrypt: aes128CbcDecryptSpec },
  },
  "aes-192": {
    "single-block": { encrypt: aes192Spec, decrypt: aes192DecryptSpec },
  },
  "aes-256": {
    "single-block": { encrypt: aes256Spec, decrypt: aes256DecryptSpec },
  },
  "speck-32-64-be": {
    "single-block": { encrypt: speck32_64BeSpec, decrypt: speck32_64BeDecryptSpec },
  },
  "speck-32-64-le": {
    "single-block": { encrypt: speck32_64LeSpec, decrypt: speck32_64LeDecryptSpec },
  },
  "serpent-128": {
    "single-block": { encrypt: serpent128Spec, decrypt: serpent128DecryptSpec },
  },
  "serpent-192": {
    "single-block": { encrypt: serpent192Spec, decrypt: serpent192DecryptSpec },
  },
  "serpent-256": {
    "single-block": { encrypt: serpent256Spec, decrypt: serpent256DecryptSpec },
  },
};

/**
 * Pick the right canonical spec for the active (cipher, cipherMode, mode)
 * triple, falling back to single-block when the requested cipherMode isn't
 * registered for the cipher. The fallback keeps the UI from crashing when
 * the user switches cipher to one that doesn't support the active mode
 * (e.g. AES-128/ECB → Speck/ECB).
 */
const resolveDefault = (cipher: Cipher, cipherMode: CipherMode, mode: Mode): CipherSpec => {
  const byMode = defaults[cipher];
  const forCipherMode = byMode[cipherMode] ?? byMode["single-block"];
  if (!forCipherMode) {
    throw new Error(`No spec registered for cipher=${cipher}`);
  }
  return forCipherMode[mode];
};

// ─── Signals ─────────────────────────────────────────────────────────────
//
// Two-spec store: encrypt and decrypt are held simultaneously, in
// independent slots. Phase 4 of docs/plans/duplicate-round.md introduced
// this shape so the auto-mirror feature can write to both slots in one
// shot (`duplicateRoundInSpec` below) and so flipping mode preserves
// each side's customizations.
//
// Public surface stays compatible: `useSpec()` still returns an accessor
// for the currently active mode's spec. Behavior change worth noting:
// `setMode` no longer resets the spec to canonical — it just flips the
// active slot. `setCipher` / `setCipherMode` rebuild BOTH slots from
// canonical (a cipher swap is a clean break).

type SpecsByMode = { readonly encrypt: CipherSpec; readonly decrypt: CipherSpec };

const buildCanonicalPair = (
  cipher: Cipher,
  cipherMode: CipherMode,
  scheme: PaddingScheme,
): SpecsByMode => ({
  encrypt: applyPaddingScheme(resolveDefault(cipher, cipherMode, "encrypt"), "encrypt", scheme),
  decrypt: applyPaddingScheme(resolveDefault(cipher, cipherMode, "decrypt"), "decrypt", scheme),
});

const [mode, setModeSignal] = createSignal<Mode>("encrypt");
const [specs, setSpecs] = createSignal<SpecsByMode>(
  buildCanonicalPair(useCipher()(), useCipherMode()(), usePaddingScheme()()),
);

// Active-spec accessor — reads both signals so consumers tracking
// `useSpec()` re-render on mode flips AND on per-slot edits.
const activeSpec = (): CipherSpec => specs()[mode()];

export const useMode = () => mode;
export const useSpec = () => activeSpec;

/**
 * Read-only access to both slots. Used by the Save/Load surface so a
 * future "save both modes' specs" flow has a clean read boundary; today
 * only the active slot ships in the document, but the two-slot store
 * makes a richer save trivial later.
 */
export const useSpecsByMode = () => specs;

// Internal: replace only the active mode's slot. Used by edit helpers
// (params, palette inserts, deletes) so changes to one mode never leak
// into the other.
const updateActive = (updater: (s: CipherSpec) => CipherSpec): void => {
  const current = specs();
  const m = mode();
  const updated = updater(current[m]);
  if (updated === current[m]) return; // reference-equal → no-op write
  setSpecs({ ...current, [m]: updated } as SpecsByMode);
};

// Internal: replace both slots in one signal write. Used by selector
// changes that rebuild canonical (cipher / cipherMode / padding) and by
// duplicate-round's auto-mirror.
const updateBoth = (updater: (s: CipherSpec, m: Mode) => CipherSpec): void => {
  const current = specs();
  setSpecs({
    encrypt: updater(current.encrypt, "encrypt"),
    decrypt: updater(current.decrypt, "decrypt"),
  });
};

// ─── Mutators ────────────────────────────────────────────────────────────

/**
 * Switch between encrypt and decrypt. With the two-spec store this is a
 * pure index flip — the OTHER slot keeps whatever the user last left in
 * it (e.g. customizations from a prior session-in-this-mode). Cipher and
 * cipherMode swaps still rebuild both slots from canonical; this setter
 * doesn't.
 */
export const setMode = (m: Mode): void => {
  setModeSignal(m);
};

/**
 * Switch the active cipher. Both slots rebuild from canonical for the
 * new cipher × current cipherMode pair, then re-apply the active padding
 * overlay. If the new cipher doesn't support the current cipherMode,
 * the cipherMode signal RESETs to "single-block" first (same rationale
 * as the prior single-spec version: keeps `paddingLimits` consistent
 * with what the spec can actually accept).
 */
export const setCipher = (c: Cipher): void => {
  setCipherSignal(c);
  if (!isCipherModeSupported(c, useCipherMode()())) {
    setCipherModeSignal("single-block");
  }
  setSpecs(buildCanonicalPair(c, useCipherMode()(), usePaddingScheme()()));
};

/**
 * Switch the block-cipher mode of operation. Both slots rebuild from
 * canonical so encrypt/decrypt stay coherent (the multi-block factory
 * builds the matching pair).
 */
export const setCipherMode = (m: CipherMode): void => {
  setCipherModeSignal(m);
  setSpecs(buildCanonicalPair(useCipher()(), m, usePaddingScheme()()));
};

/**
 * Switch the padding scheme. Re-applies the overlay to BOTH slots — the
 * encrypt slot gets pad+load-block prepended, the decrypt slot gets
 * store-block+unpad appended. `applyPaddingScheme` is idempotent (strips
 * existing overlay before re-applying) so user edits to round leaves
 * survive.
 */
export const setPadding = (scheme: PaddingScheme): void => {
  setPaddingScheme(scheme);
  updateBoth((s, m) => applyPaddingScheme(s, m, scheme));
};

/**
 * Edit one specific step's params. Writes to the ACTIVE mode's slot
 * only — edits don't leak across modes. Two-spec semantics: encrypt's
 * S-box change does not propagate to decrypt's S-box, by design.
 */
export const editStepParams = (stepId: string, params: Json): void => {
  updateActive((s) => updateStepParams(s, stepId, params));
};

/**
 * Apply an update to every step of a given type IN THE ACTIVE SPEC.
 * Used for "swap the S-box across all 10 round SubBytes steps in one
 * click." The decrypt slot's S-boxes are not touched (in fact, decrypt
 * uses the INVERSE S-box — propagating verbatim would be wrong).
 */
export const editAllStepsByType = (stepType: string, update: (params: Json) => Json): void => {
  updateActive((s) => updateAllStepsByType(s, stepType, update));
};

/**
 * Insert a brand-new step leaf into the live spec (Slice 8 of the 2D
 * editor plan). The palette + GraphView drop handler call this with a
 * `stepType` registered in the registry and an anchor that says WHERE
 * relative to the existing tree the new leaf should land.
 *
 * Four anchor flavors:
 *   • `{ kind: "after", stepId }` — uses `insertStepAfter` to place the
 *     new leaf immediately after that node, into its parent. The anchor
 *     can be a leaf id OR a container id (group/iterate) — `findStepAndParent`
 *     handles both since Slice 4.
 *   • `{ kind: "before", stepId }` — mirror of `after`. Routes through
 *     `insertStepBefore`. The drop-gutter UI surface (Slice 5 of the
 *     graph-narrative-and-zoom plan) uses this for "drop between two
 *     siblings" (gutter anchored at the slot's next sibling).
 *   • `{ kind: "into-start", containerId }` — inserts as the FIRST
 *     child of the named container's body. Used by the post-rescope
 *     header-drop semantic (2026-05-15 follow-up to Slice 5): dropping
 *     on a container's header band means "enter this container's body
 *     and land at position 0," NOT the original Slice 8 "insert after
 *     the container in its parent" — user feedback showed the after-in-
 *     parent semantic was actively confusing because the chip obscures
 *     the header and users couldn't tell their cursor was on the
 *     header. Falls back to root-append when the container has no
 *     children. Walks the spec tree to find the first child; works for
 *     groups and iterates uniformly.
 *   • `{ kind: "root-append" }` — appends to `spec.steps`. Used when the
 *     drop lands on the SVG canvas with no specific node target (today's
 *     ciphers always have at least one root node, so this is the empty-
 *     canvas / fallback path).
 *
 * The new leaf carries `params: {}` — the runtime will almost certainly
 * throw on first execution because most step types require parameters
 * (S-box, block size, …). That's deliberate per the Slice 8 plan: the
 * inserted leaf is a placeholder the user opens in the ParamEditor to
 * configure. The Run error surfaces in the existing error banner, telling
 * the user which step is missing what.
 *
 * Id generation: `<last-stepType-segment-without-@N>-<n>`. Example:
 * `generic.byte-substitution@1` → `byte-substitution-1`. n auto-increments
 * to dodge collisions with existing leaves of the same stepType.
 *
 * Returns the generated id so the caller (GraphView's drop handler) can
 * route the trace scrubber to the new step's frame once the auto-rerun
 * lands — even though that frame is likely an ERROR frame for a leaf with
 * empty params.
 */
/**
 * Remove a leaf, group, or iterate (and all its descendants) from the
 * live spec. Three UI affordances drive this:
 *   - the × button rendered on hover at the corner of each graph node;
 *   - the "Delete this step" button in the ParamEditor;
 *   - the Delete/Backspace keyboard shortcut while a graph node is
 *     focused.
 *
 * No-op + warn if the id doesn't resolve. Throwing on a stale id would
 * be hostile — the user clicks delete on a node, the spec re-runs
 * meanwhile and the leaf was already removed; we don't want a crash.
 * `removeStep` (core) throws on stale ids by design; we catch here to
 * make the boundary lenient.
 */
export const removeStepFromSpec = (stepId: string): void => {
  try {
    updateActive((s) => removeStep(s, stepId));
  } catch (err) {
    // Stale id or other failure — surface to the console for debugging
    // but don't crash the UI. Real users won't see this; the path lights
    // up only when delete races with another spec mutation.
    console.warn(`removeStepFromSpec(${stepId}) failed:`, err);
  }
};

export const insertStepIntoSpec = (
  stepType: string,
  anchor:
    | { kind: "after"; stepId: string }
    | { kind: "before"; stepId: string }
    | { kind: "into-start"; containerId: string }
    | { kind: "root-append" },
): string => {
  const currentSpec = activeSpec();
  const newId = generateUniqueStepId(currentSpec, stepType);
  const newLeaf: StepLeaf = {
    kind: "step",
    id: newId,
    type: stepType,
    params: {},
  };
  if (anchor.kind === "after") {
    updateActive((s) => insertStepAfter(s, anchor.stepId, newLeaf));
  } else if (anchor.kind === "before") {
    updateActive((s) => insertStepBefore(s, anchor.stepId, newLeaf));
  } else if (anchor.kind === "into-start") {
    // Resolve "first child of container" by walking the spec. The
    // graph's `ContainerNode.childIds` would also work but reflects
    // post-collapse state — and collapsing shouldn't change the
    // insertion semantic. The spec tree is authoritative.
    const loc = findStepAndParent(currentSpec, anchor.containerId);
    const firstChild =
      loc && loc.node.kind !== "step" && loc.node.children.length > 0 && loc.node.children[0];
    if (firstChild) {
      updateActive((s) => insertStepBefore(s, firstChild.id, newLeaf));
    } else {
      // Container has no children, or the id didn't resolve to a
      // container at all. Falling through to root-append is the safest
      // recovery — the dropped step still lands somewhere visible
      // instead of vanishing.
      updateActive((s) => ({ ...s, steps: [...s.steps, newLeaf] }));
    }
  } else {
    // root-append: rebuild the top-level array with the new leaf at the
    // end. `insertStepAfter` would also work if there's a last element,
    // but a direct append covers the empty-spec edge case uniformly.
    updateActive((s) => ({ ...s, steps: [...s.steps, newLeaf] }));
  }
  return newId;
};

/**
 * Duplicate-round entry point for the graph-view toolbar (Phase 4 of
 * docs/plans/duplicate-round.md). Invariants:
 *
 *   - The CURRENT mode's spec is mutated via `duplicateRoundGroup` with
 *     the appropriate direction (forward for encrypt, reverse for
 *     decrypt).
 *   - The COUNTERPART mode's spec is also mutated, with the opposite
 *     direction and the source id translated by key index
 *     (round.N ↔ inv-round.N).
 *   - Both slots are written in one signal update.
 *   - Layout pins are migrated for BOTH spec.id's via
 *     `renameSpecLayoutIds`. Pins on un-renamed nodes stay.
 *   - Stacking duplicates: the second call applies the mutator to the
 *     LIVE (already-modified) counterpart slot, not to canonical. So
 *     two duplicates on encrypt produce a decrypt with two mirrored
 *     duplicates.
 *
 * Failure modes:
 *   - Active-side mutator throws → the entire call throws; nothing
 *     changes. (Bad source id, source isn't a group, etc.)
 *   - Counterpart mutator throws → active-side change still lands but
 *     counterpart is left unchanged. The user sees a console warning;
 *     they can manually adjust decrypt. This path is reachable if the
 *     counterpart spec has been customized in a way that lost the
 *     matching inv-round.N (e.g. user deleted it manually).
 *
 * The source id is restricted to non-final rounds by the UI layer
 * (Phase 5) — round.{rounds} / inv-round.0 have no clean auto-mirror
 * because the canonical decrypt has no inv-round.{rounds}.
 */
export const duplicateRoundInSpec = (sourceId: string): void => {
  const currentMode = mode();
  const current = specs();
  const activeDirection: "forward" | "reverse" = currentMode === "encrypt" ? "forward" : "reverse";

  // Active-side: throws propagate to the caller (UI surfaces in the
  // existing error banner). Without this, a typo'd id would silently
  // no-op which would be a debugging puzzle.
  const { spec: newActive, renames: activeRenames } = duplicateRoundGroup(
    current[currentMode],
    sourceId,
    activeDirection,
  );

  // Counterpart-side: best-effort. The counterpart's source id swaps
  // by key index — round.N ↔ inv-round.N — preserving the "same key
  // index, mirrored direction" semantic.
  const counterpartMode: Mode = currentMode === "encrypt" ? "decrypt" : "encrypt";
  const counterpartDirection: "forward" | "reverse" =
    counterpartMode === "encrypt" ? "forward" : "reverse";
  const counterpartSourceId =
    activeDirection === "forward"
      ? sourceId.replace(/^round\./, "inv-round.")
      : sourceId.replace(/^inv-round\./, "round.");

  let newCounterpart: CipherSpec = current[counterpartMode];
  let counterpartRenames: ReadonlyMap<string, string> = new Map();
  try {
    const result = duplicateRoundGroup(
      current[counterpartMode],
      counterpartSourceId,
      counterpartDirection,
    );
    newCounterpart = result.spec;
    counterpartRenames = result.renames;
  } catch (err) {
    // Don't roll back active-side: the user explicitly clicked
    // duplicate, and partial success > total failure when the
    // counterpart is the only failed side.
    console.warn(
      `duplicateRoundInSpec: counterpart mirror failed for ${counterpartSourceId}:`,
      err,
    );
  }

  // Single signal update: both slots land atomically. Subscribers see
  // one consistent (encrypt, decrypt) pair.
  setSpecs({
    [currentMode]: newActive,
    [counterpartMode]: newCounterpart,
  } as SpecsByMode);

  // Layout migration. Both specs have their own layout entry keyed by
  // spec.id; each gets the matching rename map applied.
  renameSpecLayoutIds(newActive.id, activeRenames);
  renameSpecLayoutIds(newCounterpart.id, counterpartRenames);
};

/**
 * UI gate for the graph-view duplicate button. Returns true iff the
 * container at `containerId` is a round group whose auto-mirror has a
 * clean landing site on the counterpart side.
 *
 *   - `round.N`: needs a sibling `round.{N+1}` to exist. The final
 *     round (e.g. `round.{rounds}` in canonical AES) has no
 *     `round.{N+1}` sibling, so it would auto-mirror to a non-existent
 *     `inv-round.{rounds}` on the decrypt side. Suppress the button
 *     to avoid a half-mirrored state.
 *   - `inv-round.N`: needs `N > 0`. `inv-round.0` is the final inverse
 *     round; mirroring to encrypt's `round.0` (which doesn't exist —
 *     encrypt's `initial.add-round-key` is a LEAF, not a group) would
 *     fail.
 *   - Anything else (leaves, iterate body, non-round groups): false.
 *
 * Pure read of the active spec. Tracking is implicit (reads `specs()`
 * and `mode()` via `activeSpec()`), so consumers using this inside
 * `createMemo` automatically re-evaluate when the spec changes.
 */
export const isRoundDuplicatable = (containerId: string): boolean => {
  const m = containerId.match(/^(round|inv-round)\.(\d+)$/);
  if (!m || !m[1] || !m[2]) return false;
  const prefix = m[1];
  const n = Number.parseInt(m[2], 10);
  if (prefix === "inv-round") return n > 0;
  // prefix === "round": confirm a higher-numbered sibling exists.
  const loc = findStepAndParent(activeSpec(), containerId);
  if (!loc || loc.node.kind !== "group") return false;
  const siblings = loc.parent ? loc.parent.children : activeSpec().steps;
  return siblings.some((s) => s.kind === "group" && s.id === `round.${n + 1}`);
};

/**
 * Walk the spec collecting every existing step / group / iterate id, then
 * produce the smallest positive integer `n` for which
 * `<lastSegment>-<n>` is unused. The base segment is the last dot-separated
 * part of `stepType` with any trailing `@version` chopped off, so
 * `generic.byte-substitution@1` → base `byte-substitution`. Pure helper,
 * doesn't read or write the spec store — it just receives the live spec
 * as an argument.
 */
const generateUniqueStepId = (spec: CipherSpec, stepType: string): string => {
  const lastDot = stepType.lastIndexOf(".");
  const lastSegment = lastDot >= 0 ? stepType.slice(lastDot + 1) : stepType;
  const atIdx = lastSegment.indexOf("@");
  const base = atIdx >= 0 ? lastSegment.slice(0, atIdx) : lastSegment;
  // Collect every id in the spec — leaves AND groups AND iterates, because
  // ids share one namespace and a collision with a group id would be just
  // as bad as one with a leaf id. Cheap to walk on every insert; specs
  // top out at a few hundred nodes.
  const usedIds = new Set<string>();
  const visit = (nodes: readonly StepNode[]): void => {
    for (const node of nodes) {
      usedIds.add(node.id);
      if (node.kind !== "step") visit(node.children);
    }
  };
  visit(spec.steps);
  // Find the first free `<base>-<n>` starting at n=1. Linear scan is fine
  // because the worst case is hundreds of inserts of the same type in one
  // session — well below the threshold where a smarter algorithm pays off.
  let n = 1;
  while (usedIds.has(`${base}-${n}`)) n++;
  return `${base}-${n}`;
};

/**
 * Apply a loaded `CipherDocument` to the live stores (Slice 5 of the 2D
 * editor plan). This is the boundary that the Save/Load UI calls after
 * `parseDocument` succeeds — it routes around the public selector setters
 * (each of which would trigger its own spec rebuild) and lands the
 * document's literal `spec` value as the authoritative final state.
 *
 * Hydration order matters:
 *   1. byteFormat first — so a later App-level format of restored input/
 *      key bytes uses the freshly-applied format, not the previous one.
 *   2. cipher, cipherMode, padding — raw signal setters (from cipher.ts /
 *      cipher-mode.ts / padding.ts) that update the signal + localStorage
 *      WITHOUT rebuilding the spec. We bypass this module's own setCipher
 *      etc. on purpose: those would each rebuild spec from the canonical
 *      defaults table, then the next setter would overwrite it again, and
 *      the literal `doc.spec` would never land.
 *   3. mode — same idea via the local setModeSignal.
 *   4. spec — finally, set the document's spec verbatim. The
 *      createEffect(on(spec, ...)) in App.tsx picks this up; the Load
 *      handler also calls run() synchronously so the trace lands before
 *      the debounce.
 *
 * Cross-store consistency (e.g. a document with cipher=aes-192 +
 * cipherMode=ecb when AES-192-ECB doesn't ship yet) is NOT corrected —
 * the document's spec is what runs, regardless. If it's inconsistent with
 * the supported-modes matrix, the dropdown will show the unsupported
 * combo grayed out, but the loaded trace still works because we use the
 * literal spec rather than re-resolving the defaults table.
 *
 * Input + key bytes are NOT applied here — App.tsx owns those signals and
 * reads `doc.session.inputBytes` / `keyBytes` directly after this call.
 */
export const setSpecFromDocument = (doc: CipherDocument): void => {
  if (doc.session) {
    setByteFormat(doc.session.byteFormat);
    setCipherSignal(doc.session.cipher);
    setCipherModeSignal(doc.session.cipherMode);
    setPaddingScheme(doc.session.padding);
    setModeSignal(doc.session.mode);
    // IV bytes — restored when the saved session carried them (CBC and
    // future feedback modes). The schema validates length=16 already, so
    // the cast to Uint8Array can't fail.
    if (doc.session.ivBytes !== undefined) {
      setIvBytes(new Uint8Array(doc.session.ivBytes));
    }
  }
  // Document carries one spec (for the document's mode). Land it in the
  // matching slot; rebuild the OTHER slot from canonical so the
  // unactive mode is consistent with the current selectors. A saved
  // document doesn't carry the counterpart, so this is the best we can
  // do without a richer document schema.
  const docMode: Mode = doc.session?.mode ?? mode();
  const otherMode: Mode = docMode === "encrypt" ? "decrypt" : "encrypt";
  const otherCanonical = applyPaddingScheme(
    resolveDefault(useCipher()(), useCipherMode()(), otherMode),
    otherMode,
    usePaddingScheme()(),
  );
  setSpecs({
    [docMode]: doc.spec,
    [otherMode]: otherCanonical,
  } as SpecsByMode);
};

/**
 * Restore the default spec for the current (cipher, cipherMode, mode).
 * Affects the ACTIVE slot only — the counterpart slot keeps whatever
 * the user has there. Matches the existing single-spec semantic of
 * "reset the thing I'm looking at."
 */
export const resetSpec = (): void => {
  const canonical = applyPaddingScheme(
    resolveDefault(useCipher()(), useCipherMode()(), mode()),
    mode(),
    usePaddingScheme()(),
  );
  updateActive(() => canonical);
};

/**
 * Structural deep equality for `Json`-typed values. Used by `isCustomSpec`
 * to compare the live spec to the canonical default without depending on
 * insertion-order stability — `JSON.stringify` would be order-sensitive, and
 * while today's spread-based mutations preserve key order, a future param
 * editor could round-trip a step's params through a differently-shaped
 * object and reorder keys. Recursive walk, ~15 lines, no allocation hot
 * path because it short-circuits on the first mismatch.
 */
const deepEqualJson = (a: unknown, b: unknown): boolean => {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqualJson(a[i], b[i])) return false;
    }
    return true;
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const ak = Object.keys(ao);
  const bk = Object.keys(bo);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    if (!Object.prototype.hasOwnProperty.call(bo, k)) return false;
    if (!deepEqualJson(ao[k], bo[k])) return false;
  }
  return true;
};

/**
 * True when the live spec differs from the canonical default that the
 * current selectors (cipher, cipherMode, mode, padding) would produce.
 *
 * Used by the UI to render a "Custom (was AES-128)" indicator + a
 * "reset to canonical" affordance so the user can see when they've
 * diverged from the textbook spec and snap back to it in one click.
 *
 * Why selector flips don't trigger this: `setCipher` / `setCipherMode` /
 * `setMode` all replace the spec with the new canonical default, and
 * `setPadding` rebuilds via `applyPaddingScheme` from the live spec —
 * which, when the live spec was already canonical, produces the same
 * tree as a fresh canonical-then-padding build (verified by the padding
 * round-trip test below).
 *
 * Implementation reads every signal it needs so Solid's tracking sees
 * each dependency; the App-side caller can wrap this in `createMemo` for
 * caching when it's read multiple times per render.
 */
export const isCustomSpec = (): boolean => {
  const canonical = applyPaddingScheme(
    resolveDefault(useCipher()(), useCipherMode()(), mode()),
    mode(),
    usePaddingScheme()(),
  );
  return !deepEqualJson(activeSpec(), canonical);
};

/** Test-only reset; production code uses the setters above. */
export const __resetSpecForTests = (): void => {
  setModeSignal("encrypt");
  const scheme = usePaddingScheme()();
  setSpecs({
    encrypt: applyPaddingScheme(aes128Spec, "encrypt", scheme),
    decrypt: applyPaddingScheme(aes128DecryptSpec, "decrypt", scheme),
  });
};
