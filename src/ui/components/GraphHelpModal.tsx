/**
 * In-app help modal for the graph view (Slice 11 of the 2D editor plan).
 *
 * Wraps `docs/help/graph-view.md` in a `<dialog>` so users have a
 * one-click reference for what the edges mean, how the drag/drop
 * affordances work, and how the toolbar toggles affect the layout.
 *
 * Why a separate component (instead of inlining into `GraphView`):
 *   - Keeps `GraphView.tsx` (~1700 lines) focused on rendering the SVG.
 *   - The host (`GraphView`) only owns one signal — `isOpen` — and a
 *     `<GraphHelpModal>` mount; the markdown source + dialog plumbing
 *     all live here.
 *   - Mirrors the pattern set by `RunExplorerModal.tsx`.
 *
 * Why `?raw` import of the .md file rather than an inlined TS string:
 *   - `docs/help/graph-view.md` is the single source of truth — the same
 *     file is what readers find on GitHub when they browse `docs/help/`.
 *   - Vite's `?raw` query bundles the file content as a string at build
 *     time — no network fetch, no asset hashing, no Markdown loaded
 *     dynamically. Type comes from `vite/client`'s ambient declaration.
 *
 * The Markdown component supports the same lightweight subset used by
 * step doc detail strings (paragraphs, headings, lists, bold, code,
 * fences); the help doc is written to that subset deliberately.
 */

import { Show, createEffect } from "solid-js";
// Vite's `?raw` query loads the file content as a string at build time.
// Path is relative because `docs/` lives outside `src/` (the `@/` alias
// only maps inside src). Vitest's vite-plugin-solid pipeline handles
// `?raw` the same way as the dev/build pipelines.
import helpMarkdown from "../../../docs/help/graph-view.md?raw";
import { Markdown } from "./Markdown";

type Props = {
  readonly isOpen: () => boolean;
  readonly onClose: () => void;
};

export const GraphHelpModal = (props: Props) => {
  // Native `<dialog>` element: built-in escape-to-close, focus trap, and
  // ::backdrop styling. We drive showModal/close from the isOpen signal
  // via an effect so the host (GraphView) just flips the boolean.
  //
  // jsdom note: `HTMLDialogElement.showModal` is undefined in jsdom 22+;
  // the wrapper guards against that so test imports of components that
  // mount this modal don't throw on first render. Production behavior is
  // unaffected — every browser we ship to has the API since 2022.
  let dialogRef: HTMLDialogElement | undefined;
  createEffect(() => {
    const open = props.isOpen();
    const el = dialogRef;
    if (!el) return;
    const showModal = el.showModal?.bind(el);
    const close = el.close?.bind(el);
    if (open && !el.open && showModal) showModal();
    if (!open && el.open && close) close();
  });

  return (
    <dialog
      ref={dialogRef}
      class="modal graph-help-modal"
      aria-label="Graph view help"
      onClose={() => props.onClose()}
      onKeyDown={() => {}}
      onClick={(e) => {
        // Click on the dialog element itself (not a child) hits the
        // pseudo-element backdrop, which bubbles up through the dialog.
        // currentTarget vs target is the canonical disambiguation.
        if (e.target === e.currentTarget) props.onClose();
      }}
    >
      <div class="modal-inner">
        <div class="modal-header">
          <h2>Graph view</h2>
          <button
            type="button"
            class="modal-close"
            onClick={() => props.onClose()}
            aria-label="Close"
          >
            ×
          </button>
        </div>
        <div class="modal-body graph-help-body">
          <Show when={props.isOpen()}>
            <Markdown source={helpMarkdown} />
          </Show>
        </div>
      </div>
    </dialog>
  );
};
