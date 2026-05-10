import { For, Show } from "solid-js";
import { getTrace, setFrame, useFrameIndex, useTraceVersion } from "../stores/trace";

export const StepList = () => {
  const frameIndex = useFrameIndex();
  const version = useTraceVersion();

  const frames = () => {
    void version();
    return getTrace()?.frames ?? [];
  };

  return (
    <div class="step-list">
      <Show when={frames().length > 0} fallback={<span class="muted">no trace</span>}>
        <For each={frames()}>
          {(frame) => (
            <button
              type="button"
              class="step-item"
              classList={{ active: frame.index === frameIndex() }}
              onClick={() => setFrame(frame.index)}
            >
              <span class="step-index">{frame.index}</span>
              <span class="step-path">
                {frame.path.length > 0 ? `${frame.path.join(" › ")} › ` : ""}
                {frame.stepId}
              </span>
              <span class="step-type">{frame.stepType}</span>
            </button>
          )}
        </For>
      </Show>
    </div>
  );
};
