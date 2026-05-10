import { Show } from "solid-js";
import { getTrace, setFrame, useFrameIndex, useTraceVersion } from "../stores/trace";

export const TraceTimeline = () => {
  const frameIndex = useFrameIndex();
  const version = useTraceVersion();

  const trace = () => {
    void version();
    return getTrace();
  };

  const max = () => Math.max(0, (trace()?.frames.length ?? 1) - 1);

  return (
    <div class="trace-timeline">
      <Show when={trace()} fallback={<span class="muted">no trace yet — run the cipher</span>}>
        {(t) => (
          <>
            <button onClick={() => setFrame(frameIndex() - 1)} disabled={frameIndex() === 0}>
              ◀
            </button>
            <input
              type="range"
              min="0"
              max={max()}
              value={frameIndex()}
              onInput={(e) => setFrame(Number(e.currentTarget.value))}
            />
            <button
              onClick={() => setFrame(frameIndex() + 1)}
              disabled={frameIndex() >= max()}
            >
              ▶
            </button>
            <span class="frame-counter">
              frame {frameIndex() + 1} / {t().frames.length}
            </span>
          </>
        )}
      </Show>
    </div>
  );
};
