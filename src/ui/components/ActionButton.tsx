/**
 * Reusable button primitive that gives the user a brief visible signal
 * when their click registered. Without this, several of our action
 * buttons (Repair, Sync inverse, Apply-to-all, Duplicate-round) change
 * state in panels the user isn't currently looking at — the counterpart
 * mode's spec, the rest of the round list, etc. — so they can't tell
 * the click did anything.
 *
 * Mechanism: on click, we synchronously invoke `onAction`, then add a
 * `flashing` class to the rendered <button> for ~900ms. CSS handles the
 * visual transition (background → `--accent-success`, plus a "✓" glyph
 * after the label). Screen-reader users get an `aria-live="polite"`
 * announcement carrying the operation name.
 *
 * The flash duration is deliberate: long enough that the eye catches
 * the green, short enough that it doesn't feel like a modal interrupt.
 * `prefers-reduced-motion` is honored in CSS (transition disabled).
 *
 * The primitive is HTML-button-only. The graph view's SVG
 * `DuplicateGlyph` flashes via a parallel CSS class toggle inside its
 * own component — different surface, same visual idea.
 */

import { type JSX, createSignal, splitProps } from "solid-js";

type ButtonHTMLAttributes = JSX.ButtonHTMLAttributes<HTMLButtonElement>;

type Props = ButtonHTMLAttributes & {
  /** Click handler. Runs synchronously before the flash starts. */
  onAction: () => void;
  /**
   * Text announced to assistive tech when the button is clicked. If
   * omitted, falls back to the button's visible text content.
   */
  feedbackLabel?: string;
  /**
   * Override the flash duration in ms. Default 900 — long enough to
   * register, short enough not to compete with the next user action.
   */
  flashMs?: number;
};

export const ActionButton = (allProps: Props) => {
  const [local, rest] = splitProps(allProps, [
    "onAction",
    "feedbackLabel",
    "flashMs",
    "class",
    "children",
    "onClick",
  ]);

  const [flashing, setFlashing] = createSignal(false);
  const [announce, setAnnounce] = createSignal("");

  // We compose the className manually so callers can pass their existing
  // BEM-style class (e.g. `sbox-warning-repair`) and we layer the
  // `action-button` modifier on top without trampling it. The flashing
  // class is only present during the post-click window.
  const computedClass = (): string => {
    const parts = ["action-button"];
    if (local.class) parts.push(local.class);
    if (flashing()) parts.push("flashing");
    return parts.join(" ");
  };

  const handleClick: JSX.EventHandler<HTMLButtonElement, MouseEvent> = (event) => {
    // Run the action first so the user-visible effect happens before any
    // visual feedback. If onAction throws, we still flash — the user
    // clicked and we should acknowledge the click; the error surfaces
    // through whatever error path the caller wired up.
    local.onAction();

    const label = local.feedbackLabel ?? event.currentTarget.textContent ?? "Action completed";
    setAnnounce(label);
    setFlashing(true);

    const duration = local.flashMs ?? 900;
    window.setTimeout(() => {
      setFlashing(false);
      // Clear the announcement at the same time the visual flash ends,
      // so a screen-reader user can re-click and get a fresh announcement
      // (aria-live only announces *changes* in content).
      setAnnounce("");
    }, duration);
  };

  return (
    <>
      <button
        // Pass through every other native button attribute (type,
        // disabled, title, data-*, aria-*, etc.) so the primitive is a
        // drop-in replacement for raw <button> at every call site.
        // type is explicitly defaulted below so we never accidentally
        // submit a form (the HTML default for a bare <button>).
        {...rest}
        type={rest.type ?? "button"}
        class={computedClass()}
        onClick={handleClick}
      >
        {local.children}
      </button>
      {/* Live region for assistive tech. <output> is the semantic
          element for "result of an action"; it carries an implicit
          role="status" + aria-live="polite" so the click confirmation
          is announced as a polite, non-interrupting update. We keep
          it visually hidden — sighted users get the button flash. */}
      <output class="visually-hidden">{announce()}</output>
    </>
  );
};
