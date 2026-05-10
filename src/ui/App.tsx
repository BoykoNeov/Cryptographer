import { Show, createMemo, createSignal } from "solid-js";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, MatrixState } from "@/core/types";
import { MatrixView } from "./components/MatrixView";
import { StepList } from "./components/StepList";
import { TraceTimeline } from "./components/TraceTimeline";
import { useSpec } from "./stores/spec";
import { getTrace, setTrace, useFrameIndex, useTraceVersion } from "./stores/trace";
import "./app.css";

const DEFAULT_PT = "00112233445566778899aabbccddeeff";
const DEFAULT_KEY = "000102030405060708090a0b0c0d0e0f";

export const App = () => {
  const spec = useSpec();
  const [plaintext, setPlaintext] = createSignal(DEFAULT_PT);
  const [key, setKey] = createSignal(DEFAULT_KEY);
  const [error, setError] = createSignal<string | null>(null);

  const registry = buildDefaultRegistry();

  const run = () => {
    try {
      setError(null);
      const ptBytes = bytesFromHex(plaintext());
      if (ptBytes.length !== 16) throw new Error("plaintext must be 16 bytes (32 hex chars)");
      const keyBytes = bytesFromHex(key());
      if (keyBytes.length !== 16) throw new Error("key must be 16 bytes (32 hex chars)");
      const initialAux = new Map<string, AuxValue>([["key", keyBytes]]);
      const trace = runSpec(spec(), registry, {
        initialState: matrixFromBytes(ptBytes),
        initialAux,
      });
      setTrace(trace);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const frameIndex = useFrameIndex();
  const version = useTraceVersion();

  const currentFrame = createMemo(() => {
    void version();
    return getTrace()?.frames[frameIndex()] ?? null;
  });

  const ciphertext = createMemo(() => {
    void version();
    const t = getTrace();
    if (!t || t.finalState.shape !== "matrix4x4-bytes") return null;
    return hexFromBytes(t.finalState.bytes);
  });

  return (
    <div class="app">
      <header>
        <h1>Cryptographer</h1>
        <span class="cipher-name">{spec().name}</span>
      </header>

      <section class="inputs">
        <label>
          plaintext (hex)
          <input
            value={plaintext()}
            onInput={(e) => setPlaintext(e.currentTarget.value)}
            spellcheck={false}
          />
        </label>
        <label>
          key (hex)
          <input
            value={key()}
            onInput={(e) => setKey(e.currentTarget.value)}
            spellcheck={false}
          />
        </label>
        <button type="button" onClick={run}>
          encrypt
        </button>
      </section>

      <Show when={error()}>
        <div class="error">{error()}</div>
      </Show>

      <Show when={ciphertext()}>
        <div class="result">
          ciphertext: <code>{ciphertext()}</code>
        </div>
      </Show>

      <TraceTimeline />

      <section class="trace-view">
        <Show
          when={currentFrame()}
          fallback={<div class="muted">run the cipher to see step-by-step state</div>}
        >
          {(frame) => (
            <>
              <div class="frame-header">
                <span class="frame-step">
                  {frame().path.length > 0 ? `${frame().path.join(" › ")} › ` : ""}
                  {frame().stepId}
                </span>
                <span class="frame-type">{frame().stepType}</span>
              </div>
              <Show
                when={
                  frame().stateBefore.shape === "matrix4x4-bytes" &&
                  frame().stateAfter.shape === "matrix4x4-bytes"
                }
                fallback={<div class="muted">non-matrix state — view not yet implemented</div>}
              >
                <MatrixView
                  before={frame().stateBefore as MatrixState}
                  after={frame().stateAfter as MatrixState}
                />
              </Show>
            </>
          )}
        </Show>
      </section>

      <aside class="step-list-pane">
        <h2>steps</h2>
        <StepList />
      </aside>
    </div>
  );
};
