/**
 * Spec-author-declared layout defaults — today, just default-collapse
 * for graph view (universal-port plan Phase 2 Slice 2.6d follow-up,
 * 2026-05-25). SHA-256's 64 compression rounds were the forcing case:
 * uncollapsed they put 1792+ chips on the canvas on first render, which
 * is the chip-wall failure mode Slice 2.6c plan F.1 flagged.
 *
 * Why "spec-author" instead of a UI-store switch on `spec.id`: this
 * judgment is the cipher author's, not the renderer's. A custom palette-
 * built or shared SHA-256-shaped spec inherits the affordance without
 * the rendering layer needing to know which ids are "the round groups."
 * See the user's Option 1 vs. Option 5 decision in the 2026-05-25
 * session: declarative-per-container won.
 *
 * Pure module — walks `CipherSpec` data, returns sets/arrays. The UI
 * layer (`stores/layout.ts::toggleCollapse`, `GraphView.tsx`'s
 * `collapsedSet` memo) consumes the result.
 *
 * Effective-set algebra (canonical, mirrored at every reader):
 *
 *   effective = (spec defaults  ∪  layout.collapsedGroups)
 *             −  layout.expandedGroups
 *
 * The two layout sets are mutually exclusive by `toggleCollapse`'s
 * invariant: a container id never appears in BOTH at once. That
 * invariant means the algebra simplifies — set subtraction can only
 * remove items the user explicitly expanded, never items they
 * explicitly collapsed.
 */

import type { LayoutSpec } from "./document";
import type { CipherSpec, StepNode } from "./types";

/**
 * Walk a `CipherSpec`'s tree and return the set of container ids whose
 * node declares `defaultCollapsed: true`. Leaves and containers without
 * the flag are skipped. Pure — never throws, returns an empty set for a
 * spec with no default-collapse declarations.
 *
 * Container kinds inspected: `group`, `iterate`, `feistel-round`,
 * `for-each-subgraph`, `for-each-subgraph-with-history`. The traversal
 * follows whichever children-bearing field each kind exposes (top-level
 * `children` for most; `tracks[].children` for feistel-round).
 */
export const getDefaultCollapsedContainers = (spec: CipherSpec): ReadonlySet<string> => {
  const ids = new Set<string>();
  const walk = (node: StepNode): void => {
    switch (node.kind) {
      case "step":
        // Leaves have no `defaultCollapsed` and no children — nothing
        // to do.
        return;
      case "group":
      case "iterate":
      case "for-each-subgraph":
      case "for-each-subgraph-with-history": {
        if (node.defaultCollapsed === true) ids.add(node.id);
        for (const child of node.children) walk(child);
        return;
      }
    }
  };
  for (const node of spec.steps) walk(node);
  return ids;
};

/**
 * Walk a `CipherSpec`'s tree and return every container id, in document
 * order. Leaves are skipped; every `group`/`iterate`/`for-each-subgraph`/
 * `for-each-subgraph-with-history` node contributes its id (including nested
 * ones). Pure — never throws, returns an empty array for a container-less
 * spec.
 *
 * Used by the graph-view "collapse all" / "expand all" toolbar buttons to
 * drive `collapseAllContainers` / `expandAllContainers` (`stores/layout.ts`),
 * which are spec-agnostic and so need the id list threaded in — mirroring how
 * `toggleCollapse` receives `inDefaults` from the caller.
 */
export const getAllContainerIds = (spec: CipherSpec): readonly string[] => {
  const ids: string[] = [];
  const walk = (node: StepNode): void => {
    switch (node.kind) {
      case "step":
        return;
      case "group":
      case "iterate":
      case "for-each-subgraph":
      case "for-each-subgraph-with-history": {
        ids.push(node.id);
        for (const child of node.children) walk(child);
        return;
      }
    }
  };
  for (const node of spec.steps) walk(node);
  return ids;
};

/**
 * Compute the effective collapsed set for a (spec, layout) pair.
 * Effective = (spec defaults ∪ layout.collapsedGroups) − layout.expandedGroups.
 *
 * `layout === null` means no persisted layout yet — only the spec
 * defaults apply (the SHA-256-on-first-render case).
 *
 * Returns a fresh `Set` so callers may mutate it without aliasing the
 * spec-defaults set (which is shared across renders).
 */
export const getEffectiveCollapsedSet = (
  spec: CipherSpec,
  layout: LayoutSpec | null,
): ReadonlySet<string> => {
  const defaults = getDefaultCollapsedContainers(spec);
  if (layout === null) return new Set(defaults);
  const effective = new Set<string>(defaults);
  for (const id of layout.collapsedGroups) effective.add(id);
  if (layout.expandedGroups !== undefined) {
    for (const id of layout.expandedGroups) effective.delete(id);
  }
  return effective;
};

/**
 * True iff `containerId` is in the spec's default-collapsed set. Used
 * by `toggleCollapse` to decide whether a flip should route to
 * `collapsedGroups` (explicit user-add when NOT a default) or
 * `expandedGroups` (explicit user-override when IS a default), and so
 * that an explicit toggle that lands on the default doesn't persist
 * redundant bytes.
 *
 * Pure convenience over `getDefaultCollapsedContainers(spec).has(...)`;
 * exposed as a named helper so callers don't accidentally re-walk the
 * tree per click (the layout store materializes the full set once per
 * toggle).
 */
export const isDefaultCollapsed = (spec: CipherSpec, containerId: string): boolean => {
  return getDefaultCollapsedContainers(spec).has(containerId);
};
