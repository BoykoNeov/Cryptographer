/**
 * Step palette — the left sidebar of the graph view (Slice 8 of the 2D
 * editor plan). Lists every step type the registry knows about, grouped
 * by namespace (the dot-prefix), with each entry draggable into the
 * GraphView canvas via HTML5 DnD.
 *
 * Why HTML5 DnD over pointer events: cross-component drag (palette → SVG)
 * is exactly what `dataTransfer` was designed for. The drop target reads
 * the dragged step type out of `dataTransfer.getData(MIME)` without us
 * having to maintain a "currently-dragging" signal in a shared store.
 * Pointer events would require manual ghost rendering AND a separate
 * dispatch channel between two unrelated component trees; the DnD API
 * does both for free.
 *
 * MIME type: a project-private string. Browsers don't enforce the value;
 * we just need uniqueness so a stray text drag from the OS doesn't
 * accidentally trip the drop handler.
 *
 * Excluded types: `PADDING_STEP_TYPES` from `core/spec-mutations.ts`. The
 * padding selector owns those — palette-dropping one would create a
 * top-level leaf that the next padding toggle silently strips (see
 * `stripPaddingLeaves` in spec-mutations.ts). Surfacing that footgun would
 * confuse users worse than the missing palette entry; the selector is
 * already the obvious surface for those step types.
 */

import { PADDING_STEP_TYPES } from "@/core/spec-mutations";
import type { StateShape } from "@/core/types";
import { For, createMemo, createSignal } from "solid-js";
import { registry } from "../stores/registry";

/**
 * MIME-style key used on `dataTransfer` to carry the step type from a
 * palette entry to the drop handler. Browsers normalize the case of MIME
 * keys when reading/writing across getData/setData, so use lowercase.
 */
export const STEP_TYPE_DRAG_MIME = "application/x-cryptographer-step-type";

/**
 * Module-level signal of the step type currently being dragged from the
 * palette (or `null` when no palette drag is in flight). Exported so the
 * GraphView can react to `dragstart` BEFORE `drop` — the drop-anchor
 * greying needs to know which step is dragging the moment the gesture
 * begins, and `dataTransfer.getData()` deliberately returns the empty
 * string outside the drop event (browser security around cross-origin
 * drags).
 *
 * Lifecycle: set on `dragstart` of a palette entry, cleared on `dragend`
 * of the same entry (fires regardless of drop success). Browsers
 * guarantee `dragend` after every `dragstart`, so the signal never
 * "leaks" a stale step type past one gesture.
 */
const [activeDragStepType, setActiveDragStepType] = createSignal<string | null>(null);

/** Read-only accessor for the active palette drag's step type (or null). */
export const useActiveDragStepType = (): (() => string | null) => activeDragStepType;

/**
 * Display labels for each StateShape variant + the "any" sentinel. Used
 * by both the palette chip and the tooltip. Kept tight so the chip
 * doesn't crowd the palette entry's name/id column.
 */
export const SHAPE_LABELS: Record<StateShape | "any", string> = {
  bytes: "bytes",
  "matrix4x4-bytes": "4×4 matrix",
  bitvec: "bitvec",
  bigint: "bigint",
  any: "any",
};

/**
 * One row of palette state: the raw step type id (e.g.
 * `generic.byte-substitution@1`), the namespace prefix (everything before
 * the first dot, default `other`), and a human-friendly name +
 * summary pulled from the registered `StepDocumentation` (with a fallback
 * to the type id when docs are missing — the registry allows doc-less
 * registrations).
 */
type PaletteEntry = {
  readonly stepType: string;
  readonly namespace: string;
  readonly name: string;
  readonly summary: string;
  /**
   * Declared input state shape from the step's `shapeContract`. Undefined
   * when the step type registered no contract (the field is optional, see
   * `core/types.ts`'s `StepDocumentation`).
   */
  readonly inputShape?: StateShape | "any";
};

/**
 * Build the grouped entries the palette renders. Pure derivation off the
 * UI's singleton registry — the registry never mutates after module load,
 * so a `createMemo` here is for ergonomics (avoids re-walking on unrelated
 * signal ticks), not correctness.
 *
 * Sort within a group: alphabetical by display name so neighbors in the
 * panel are similar (the `aes.*` group lists `Add Round Key`, `Byte
 * Substitution`, `Key Expansion`, … in order). Groups themselves are
 * surfaced in a deterministic order from `GROUP_ORDER` below; namespaces
 * not in that list trail behind in alphabetical order.
 */
const collectEntries = (): readonly PaletteEntry[] => {
  const types = registry.types();
  const entries: PaletteEntry[] = [];
  for (const stepType of types) {
    if (PADDING_STEP_TYPES.has(stepType)) continue;
    const dotIdx = stepType.indexOf(".");
    const namespace = dotIdx >= 0 ? stepType.slice(0, dotIdx) : "other";
    const doc = registry.getDoc(stepType);
    entries.push({
      stepType,
      namespace,
      name: doc?.name ?? stepType,
      summary: doc?.summary ?? "",
      // Carry the contract's input shape onto the entry so the chip + the
      // dragstart handler (which sets the module-level drag signal) both
      // see the same value. Undefined when the step has no contract — the
      // chip is then suppressed and dragging it greys no anchors.
      ...(doc?.shapeContract ? { inputShape: doc.shapeContract.input } : {}),
    });
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  return entries;
};

/**
 * Fixed ordering for the four namespaces shipped today. Namespaces NOT in
 * this list fall through to alphabetical order at the end — protects the
 * panel from blowing up when a future cipher family lands without us
 * touching this file.
 */
const GROUP_ORDER: readonly string[] = ["aes", "generic", "speck", "serpent"];

/**
 * Group entries by namespace and return them in the canonical group order.
 * Unknown namespaces tail-append alphabetically. Within a group entries
 * stay in the alphabetical order `collectEntries` produced.
 */
const groupEntries = (entries: readonly PaletteEntry[]): readonly [string, PaletteEntry[]][] => {
  const byNs = new Map<string, PaletteEntry[]>();
  for (const e of entries) {
    const bucket = byNs.get(e.namespace) ?? [];
    bucket.push(e);
    byNs.set(e.namespace, bucket);
  }
  const seenNs = new Set<string>(GROUP_ORDER);
  const out: [string, PaletteEntry[]][] = [];
  for (const ns of GROUP_ORDER) {
    const bucket = byNs.get(ns);
    if (bucket && bucket.length > 0) out.push([ns, bucket]);
  }
  // Unknown namespaces — order alphabetically so two future ciphers
  // landing in the same release produce a stable panel.
  const extras: string[] = [];
  for (const ns of byNs.keys()) {
    if (!seenNs.has(ns)) extras.push(ns);
  }
  extras.sort();
  for (const ns of extras) {
    const bucket = byNs.get(ns);
    if (bucket && bucket.length > 0) out.push([ns, bucket]);
  }
  return out;
};

export const StepPalette = () => {
  const grouped = createMemo(() => groupEntries(collectEntries()));

  /**
   * HTML5 dragstart handler. Writes the step type onto `dataTransfer` so
   * the drop handler (GraphView's onDrop) can read it back. We also set
   * `effectAllowed` to "copy" because the operation is logically a copy
   * (the palette entry isn't consumed — many drops of the same type are
   * fine), which is the semantic the browser's drag-cursor reflects.
   *
   * We don't customize the drag image; the browser's default ghost of the
   * source element is fine and matches the user's expectation for a
   * sidebar-style palette.
   */
  const onDragStart = (e: DragEvent, stepType: string): void => {
    // Publish the drag's step type on the module-level signal so the
    // GraphView can read it during dragover (where `dataTransfer.getData`
    // returns "" for security reasons). Cleared by onDragEnd below.
    setActiveDragStepType(stepType);
    if (!e.dataTransfer) return;
    e.dataTransfer.setData(STEP_TYPE_DRAG_MIME, stepType);
    // Fallback for cross-browser safety: some older browsers won't expose
    // custom MIME on dataTransfer in DnD events, falling back to text/plain.
    // The drop handler tries the custom MIME first, then text/plain.
    e.dataTransfer.setData("text/plain", stepType);
    e.dataTransfer.effectAllowed = "copy";
  };

  /**
   * Always fires after `dragstart`, regardless of drop success. Resets the
   * module-level signal so the next drag starts clean. The browser
   * guarantees `dragend` even when the user drops outside any handler or
   * presses Escape mid-drag.
   */
  const onDragEnd = (): void => {
    setActiveDragStepType(null);
  };

  return (
    <aside
      class="step-palette"
      aria-label="Step palette — drag a step type into the graph"
      data-testid="step-palette"
    >
      <h3 class="step-palette-title">palette</h3>
      <p class="step-palette-hint">drag a step into the graph</p>
      <For each={grouped()}>
        {([namespace, entries]) => (
          <section class="step-palette-group" data-testid={`step-palette-group-${namespace}`}>
            <h4 class="step-palette-group-label">{namespace}</h4>
            <ul class="step-palette-list">
              <For each={entries}>
                {(entry) => {
                  // Compose a hover tooltip that combines the summary (or
                  // stepType fallback) with the shape contract — so users
                  // who scan via native browser tooltips see both pieces of
                  // metadata at once, without having to drag to find out.
                  const baseTitle = entry.summary || entry.stepType;
                  const shapeTitle =
                    entry.inputShape !== undefined
                      ? `\nExpects: ${SHAPE_LABELS[entry.inputShape]} state`
                      : "";
                  return (
                    <li
                      class="step-palette-entry"
                      draggable={true}
                      data-step-type={entry.stepType}
                      data-testid={`step-palette-entry-${entry.stepType}`}
                      title={baseTitle + shapeTitle}
                      onDragStart={(e) => onDragStart(e, entry.stepType)}
                      onDragEnd={onDragEnd}
                    >
                      <span class="step-palette-entry-name">{entry.name}</span>
                      <span class="step-palette-entry-type">{entry.stepType}</span>
                      {entry.inputShape !== undefined ? (
                        <span
                          class="step-palette-entry-shape"
                          data-shape={entry.inputShape}
                          data-testid={`step-palette-entry-shape-${entry.stepType}`}
                        >
                          {SHAPE_LABELS[entry.inputShape]}
                        </span>
                      ) : null}
                    </li>
                  );
                }}
              </For>
            </ul>
          </section>
        )}
      </For>
    </aside>
  );
};
