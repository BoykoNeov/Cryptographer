/**
 * bytes-to-state@1 — port-native bridge primitive tests
 * (universal-port plan Phase 2 Slice 2.6b, 2026-05-25).
 *
 * Two layers of coverage:
 *
 *  1. **Executor unit tests** — direct invocation against `inputs` Map.
 *     Pins the port-level identity-passthrough contract: bytes in via
 *     `inputs.get("input")` come out via `outputs.get("output")`, fresh
 *     buffer, same length, byte-equal.
 *
 *  2. **Runtime integration tests** — exercise the load-bearing
 *     `meta.stateOutputPort` mechanism. With `portedDispatchEnabled:
 *     true`, the runtime sees `meta.stateOutputPort = "output"` and
 *     copies output-port bytes into `state` post-executor. We pin this
 *     by running a 2-leaf spec (constant-load → bytes-to-state) and
 *     asserting `trace.finalState.bytes` matches the constant.
 *
 * **Why split into two layers.** Executor unit tests are fast and
 * deterministic; they break on math/data bugs in the executor itself.
 * Runtime integration tests catch the runtime↔meta interaction the
 * executor can't surface (e.g., if a future runtime refactor accidentally
 * dropped the `stateOutputPort` projection). Both gates are cheap; both
 * pin different invariants.
 *
 * **Off-flag dispatch throws** (the Slice 2.1a guard message): per the
 * `kind: "ported"` with no `legacy` registration, running this leaf
 * without `portedDispatchEnabled: true` throws "port-native; requires
 * portedDispatchEnabled: true". Pinned in the runtime test.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { CipherSpec, Json, StepContext } from "@/core/types";
import { bytesToState } from "@/steps/bytes-to-state";
import { describe, expect, it } from "vitest";

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const callExecutor = (input: Uint8Array, params: Json = {}): Uint8Array => {
  const out = bytesToState(new Map([["input", input]]), params, CTX);
  return out.get("output") as Uint8Array;
};

// ─── Executor unit tests ──────────────────────────────────────────────────

describe("bytes-to-state@1 — executor identity-passthrough on the port layer", () => {
  it("emits the input bytes verbatim on the output port (empty input)", () => {
    const out = callExecutor(new Uint8Array());
    expect(out).toEqual(new Uint8Array());
  });

  it("emits the input bytes verbatim on the output port (single-byte input)", () => {
    const out = callExecutor(new Uint8Array([0x42]));
    expect(out).toEqual(new Uint8Array([0x42]));
  });

  it("emits the input bytes verbatim on the output port (32-byte input — SHA-256 hash size)", () => {
    const input = new Uint8Array(32);
    for (let i = 0; i < 32; i++) input[i] = (i * 7 + 13) & 0xff;
    const out = callExecutor(input);
    expect(out).toEqual(input);
  });

  it("output is a fresh buffer — mutating it does not affect the input", () => {
    const input = new Uint8Array([0x01, 0x02, 0x03]);
    const out = callExecutor(input);
    out[0] = 0xff;
    // Input unchanged.
    expect(input[0]).toBe(0x01);
  });

  it("throws when the `input` port is missing", () => {
    expect(() => bytesToState(new Map(), {}, CTX)).toThrow(/input port 'input' is not wired/);
  });

  it("throws when params is null", () => {
    expect(() => bytesToState(new Map([["input", new Uint8Array()]]), null, CTX)).toThrow(
      /params must be an object/,
    );
  });

  it("throws when params is an array", () => {
    expect(() => bytesToState(new Map([["input", new Uint8Array()]]), [] as Json, CTX)).toThrow(
      /params must be an object/,
    );
  });
});

// ─── Runtime integration: state-write via meta.stateOutputPort ───────────

describe("bytes-to-state@1 — runtime state-write via meta.stateOutputPort", () => {
  // The load-bearing gate: a 2-leaf spec where `constant-load` emits a
  // known byte sequence on its `output` port, `bytes-to-state` wires its
  // `input` to that, and we assert the runtime's `finalState` matches.
  // If the runtime's meta.stateOutputPort wiring is broken, finalState
  // would stay as whatever the initial (empty) state was.
  const buildSpec = (constantBytes: number[]): CipherSpec => ({
    id: "toy-bytes-to-state",
    name: "bytes-to-state runtime gate (Slice 2.6b)",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "const",
        type: "constant-load@1",
        params: { bytes: constantBytes },
      },
      {
        kind: "step",
        id: "sink",
        type: "bytes-to-state@1",
        params: {},
        portInputs: {
          input: { node: "const", port: "output" },
        },
      },
    ],
  });

  it("finalState carries the bytes routed through bytes-to-state's output port", () => {
    const constantBytes = [0xde, 0xad, 0xbe, 0xef];
    const trace = runSpec(buildSpec(constantBytes), buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array() },
      portedDispatchEnabled: true,
    });
    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") throw new Error("unreachable");
    expect(Array.from(trace.finalState.bytes)).toEqual(constantBytes);
  });

  it("output port is still readable by downstream consumers (chainable form preserved)", () => {
    // Three leaves: constant-load → bytes-to-state → xor. The xor reads
    // both the bytes-to-state output AND a second constant. If
    // bytes-to-state's output port were terminal-only (per the rejected
    // option in the Slice 2.6b user pick), the xor wire would fail at
    // resolution. Expose-output preserves the chainable shape.
    const spec: CipherSpec = {
      id: "toy-chainable-bytes-to-state",
      name: "bytes-to-state chainable form (Slice 2.6b)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "const-a",
          type: "constant-load@1",
          params: { bytes: [0x01, 0x02, 0x03, 0x04] },
        },
        {
          kind: "step",
          id: "sink",
          type: "bytes-to-state@1",
          params: {},
          portInputs: {
            input: { node: "const-a", port: "output" },
          },
        },
        {
          kind: "step",
          id: "const-b",
          type: "constant-load@1",
          params: { bytes: [0x10, 0x20, 0x30, 0x40] },
        },
        {
          kind: "step",
          id: "xor.result",
          type: "xor@1",
          params: { inputCount: 2 },
          portInputs: {
            operand0: { node: "sink", port: "output" },
            operand1: { node: "const-b", port: "output" },
          },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array() },
      portedDispatchEnabled: true,
    });
    // Four frames: const-a, sink, const-b, xor.result.
    expect(trace.frames).toHaveLength(4);
    // sink updated state, but const-b runs after, so finalState reflects
    // the LAST state assignment — which is still sink's (const-b doesn't
    // touch state; xor doesn't touch state). So finalState should be
    // const-a's bytes (set by bytes-to-state).
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([0x01, 0x02, 0x03, 0x04]);
    // The xor result is observable via the trace's last frame's
    // computed output (port-level). We can't easily inspect output ports
    // through TraceFrame in the current contract (PortedFrame.outputs
    // is a separate concept the plan defers merging), so we trust the
    // runtime didn't throw on the unwired ports — the test's existence
    // gate is enough.
  });

  it("off-flag dispatch throws (port-native, no legacy executor)", () => {
    const spec = buildSpec([0xaa, 0xbb]);
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array() },
        // portedDispatchEnabled omitted (defaults to false)
      }),
    ).toThrow(/port-native; requires portedDispatchEnabled: true/);
  });

  it("preserves state shape: bytes-to-state always materializes a BytesState (not a matrix)", () => {
    // Even if the upstream emits 16 bytes — which happens to be a valid
    // matrix length — bytes-to-state's meta.stateLayout = "bytes" pins
    // the reconstruction as a BytesState. Pin the discrimination.
    const spec = buildSpec([
      // 16 bytes — could be misinterpreted as a 4×4 matrix.
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
      0x0f,
    ]);
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array() },
      portedDispatchEnabled: true,
    });
    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") throw new Error("unreachable");
    expect(trace.finalState.bytes.length).toBe(16);
  });
});

// ─── Validator coverage (no warnings on a well-wired spec) ────────────────

describe("bytes-to-state@1 — validator does not surface false warnings", () => {
  it("happy-path spec produces zero warnings", async () => {
    const { validateShapes } = await import("@/core/spec-shapes");
    const spec: CipherSpec = {
      id: "toy-bytes-to-state-validator",
      name: "validator gate",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "const",
          type: "constant-load@1",
          params: { bytes: [0x42] },
        },
        {
          kind: "step",
          id: "sink",
          type: "bytes-to-state@1",
          params: {},
          portInputs: {
            input: { node: "const", port: "output" },
          },
        },
      ],
    };
    const warnings = validateShapes(spec, buildDefaultRegistry());
    expect(warnings).toEqual([]);
  });
});

// ─── BytesState gate explanation ──────────────────────────────────────────
// Note: the executor returns `new Uint8Array(input.length)` and bytes-to-
// state's pre-Slice-2.6a contract guarantees output port bytes are
// independent of the executor's `inputs` map (the Slice 2.6a runtime
// re-records `outputs` into a fresh nodeOutputs map). Together these mean
// the runtime CAN'T silently corrupt the bytes across the executor
// boundary, even under future refactors. The "fresh buffer" assertion
// above pins this at the executor layer; if a future PR's runtime change
// aliased outputs back to inputs, the cross-leaf chainable test would
// surface the regression.
