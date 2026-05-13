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
  insertStepAfter,
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

const [mode, setModeSignal] = createSignal<Mode>("encrypt");
// Seed initial spec with the persisted (cipher, cipherMode, padding).
const [spec, setSpec] = createSignal<CipherSpec>(
  applyPaddingScheme(
    resolveDefault(useCipher()(), useCipherMode()(), "encrypt"),
    "encrypt",
    usePaddingScheme()(),
  ),
);

export const useMode = () => mode;
export const useSpec = () => spec;

// ─── Mutators ────────────────────────────────────────────────────────────

/**
 * Switch between encrypt and decrypt. RESETS the spec to the default for
 * the new (cipher, cipherMode, mode) — any in-progress experiments are
 * discarded. The active padding scheme is re-applied to the freshly-
 * loaded canonical spec so the user's choice persists across the flip.
 */
export const setMode = (m: Mode): void => {
  setModeSignal(m);
  setSpec(
    applyPaddingScheme(
      resolveDefault(useCipher()(), useCipherMode()(), m),
      m,
      usePaddingScheme()(),
    ),
  );
};

/**
 * Switch the active cipher. Replaces the spec with the new cipher's
 * canonical default for the current (cipherMode, mode), then re-applies
 * the active padding overlay. If the new cipher doesn't support the
 * current cipherMode, the cipherMode signal is RESET to "single-block"
 * before the spec is rebuilt. Without this reset, `resolveDefault` would
 * silently fall back to single-block but the dropdown would still show
 * the unsupported mode — `paddingLimits` would then return the
 * multi-block range, the spec would run as single-block with the
 * padding overlay, and the user would see a deep "load-block: expected
 * 16, got 32" error instead of any UI signal.
 */
export const setCipher = (c: Cipher): void => {
  setCipherSignal(c);
  if (!isCipherModeSupported(c, useCipherMode()())) {
    setCipherModeSignal("single-block");
  }
  setSpec(
    applyPaddingScheme(resolveDefault(c, useCipherMode()(), mode()), mode(), usePaddingScheme()()),
  );
};

/**
 * Switch the block-cipher mode of operation (single-block / ecb / cbc /
 * ctr). Replaces the spec with the multi-block factory's output for the
 * current cipher + mode, then re-applies the padding overlay. If the
 * requested cipherMode isn't registered for the current cipher, falls
 * back to single-block.
 */
export const setCipherMode = (m: CipherMode): void => {
  setCipherModeSignal(m);
  setSpec(
    applyPaddingScheme(resolveDefault(useCipher()(), m, mode()), mode(), usePaddingScheme()()),
  );
};

/**
 * Switch the padding scheme. Persists the choice and rebuilds the current
 * spec with the new overlay. User edits to canonical AES leaves survive
 * because `applyPaddingScheme` only touches the overlay step types; it
 * walks the existing spec to strip+rebuild the padding chain without
 * disturbing the AES rounds.
 */
export const setPadding = (scheme: PaddingScheme): void => {
  setPaddingScheme(scheme);
  setSpec((s) => applyPaddingScheme(s, mode(), scheme));
};

/**
 * Edit one specific step's params. The UI uses this when the user changes
 * a value in the ParamEditor and wants the change scoped to a single step.
 */
export const editStepParams = (stepId: string, params: Json): void => {
  setSpec((s) => updateStepParams(s, stepId, params));
};

/**
 * Apply an update to every step of a given type. Used for "swap the S-box
 * across all 10 round SubBytes steps in one click" — the more dramatic
 * modularity demo, since AES the cipher conceptually has ONE S-box.
 */
export const editAllStepsByType = (stepType: string, update: (params: Json) => Json): void => {
  setSpec((s) => updateAllStepsByType(s, stepType, update));
};

/**
 * Insert a brand-new step leaf into the live spec (Slice 8 of the 2D
 * editor plan). The palette + GraphView drop handler call this with a
 * `stepType` registered in the registry and an anchor that says WHERE
 * relative to the existing tree the new leaf should land.
 *
 * Two anchor flavors:
 *   • `{ kind: "after", stepId }` — uses `insertStepAfter` to place the
 *     new leaf immediately after that node, into its parent. The anchor
 *     can be a leaf id OR a container id (group/iterate) — `findStepAndParent`
 *     handles both since Slice 4.
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
export const insertStepIntoSpec = (
  stepType: string,
  anchor: { kind: "after"; stepId: string } | { kind: "root-append" },
): string => {
  const currentSpec = spec();
  const newId = generateUniqueStepId(currentSpec, stepType);
  const newLeaf: StepLeaf = {
    kind: "step",
    id: newId,
    type: stepType,
    params: {},
  };
  if (anchor.kind === "after") {
    setSpec(insertStepAfter(currentSpec, anchor.stepId, newLeaf));
  } else {
    // root-append: rebuild the top-level array with the new leaf at the
    // end. `insertStepAfter` would also work if there's a last element,
    // but a direct append covers the empty-spec edge case uniformly.
    setSpec({ ...currentSpec, steps: [...currentSpec.steps, newLeaf] });
  }
  return newId;
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
  }
  // Set the document's spec literally — no padding overlay re-application,
  // no canonical-default fallback. The document author already baked the
  // overlay into the serialized spec (round-trip property locked in by
  // tests/document-roundtrip.test.ts).
  setSpec(doc.spec);
};

/**
 * Restore the default spec for the current (cipher, cipherMode, mode).
 * Preserves the padding scheme + cipher + cipherMode.
 */
export const resetSpec = (): void => {
  setSpec(
    applyPaddingScheme(
      resolveDefault(useCipher()(), useCipherMode()(), mode()),
      mode(),
      usePaddingScheme()(),
    ),
  );
};

/** Test-only reset; production code uses the setters above. */
export const __resetSpecForTests = (): void => {
  setModeSignal("encrypt");
  setSpec(applyPaddingScheme(aes128Spec, "encrypt", usePaddingScheme()()));
};
