import { Show } from "solid-js";

/**
 * Tiny "Block i of N" chip rendered above the per-frame state view when
 * the current frame belongs to a multi-block iterate loop. Pure visual —
 * no behavior, no scrubber surgery — driven entirely by the optional
 * `blockIndex` field that the runtime stamps onto frames emitted inside
 * an `iterate` node (see `src/core/runtime.ts`).
 *
 * Suppressed for single-block frames (where `blockIndex` is undefined).
 */

type Props = {
  /** 0-based block index from `TraceFrame.blockIndex`. Pass `undefined` to suppress. */
  blockIndex: number | undefined;
  /** Total iteration count for the current run (= max blockIndex + 1). */
  blockCount: number;
};

export const BlockBadge = (props: Props) => {
  return (
    <Show when={props.blockIndex !== undefined && props.blockCount > 1}>
      <div class="block-badge">
        Block <strong>{(props.blockIndex ?? 0) + 1}</strong> of {props.blockCount}
      </div>
    </Show>
  );
};
