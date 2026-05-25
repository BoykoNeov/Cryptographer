/**
 * state-to-bytes@1 — port-native bridge primitive tests
 * (universal-port plan Phase 2 Slice 2.6b, 2026-05-25).
 *
 * Symmetric counterpart to `bytes-to-state.test.ts`. Two layers:
 *
 *  1. **Executor unit tests** — direct invocation against `inputs` Map.
 *     The executor receives state bytes via `inputs.get("state")` (which
 *     the runtime auto-projects from parent state via meta.stateInputPort)
 *     and emits them verbatim on `output`. Identity passthrough.
 *
 *  2. **Runtime integration tests** — the load-bearing
 *     `meta.stateInputPort` mechanism. With `portedDispatchEnabled: true`,
 *     the runtime sees `meta.stateInputPort = "state"` and projects
 *     parent state into the `state` input port BEFORE the executor runs.
 *     We pin this by running a 2-leaf spec (state-to-bytes → bytes-to-state)
 *     and asserting the bytes round-trip through state correctly.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { CipherSpec, Json, StepContext } from "@/core/types";
import { stateToBytes } from "@/steps/state-to-bytes";
import { describe, expect, it } from "vitest";

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const callExecutor = (state: Uint8Array, params: Json = {}): Uint8Array => {
  const out = stateToBytes(new Map([["state", state]]), params, CTX);
  return out.get("output") as Uint8Array;
};

// ─── Executor unit tests ──────────────────────────────────────────────────

describe("state-to-bytes@1 — executor identity-passthrough on the port layer", () => {
  it("emits the state bytes verbatim on the output port", () => {
    const state = new Uint8Array([0x61, 0x62, 0x63]); // "abc"
    const out = callExecutor(state);
    expect(out).toEqual(state);
  });

  it("output is a fresh buffer — mutating it does not affect the input", () => {
    const state = new Uint8Array([0x01, 0x02, 0x03]);
    const out = callExecutor(state);
    out[0] = 0xff;
    expect(state[0]).toBe(0x01);
  });

  it("handles empty state", () => {
    const out = callExecutor(new Uint8Array());
    expect(out).toEqual(new Uint8Array());
  });

  it("throws when the `state` port is missing", () => {
    expect(() => stateToBytes(new Map(), {}, CTX)).toThrow(/input port 'state' is not wired/);
  });

  it("throws when params is null", () => {
    expect(() => stateToBytes(new Map([["state", new Uint8Array()]]), null, CTX)).toThrow(
      /params must be an object/,
    );
  });
});

// ─── Runtime integration: state projection via meta.stateInputPort ────────

describe("state-to-bytes@1 — runtime state-read via meta.stateInputPort", () => {
  // Round-trip gate: state → state-to-bytes → bytes-to-state → state.
  // The plaintext (initialState) flows through both bridges and lands
  // back in finalState byte-identical. If meta.stateInputPort is broken,
  // state-to-bytes' executor would throw "not wired"; if the round-trip
  // is broken anywhere, finalState diverges from initialState.
  it("round-trips initial plaintext through state-to-bytes → bytes-to-state → state", () => {
    const plaintext = new Uint8Array([0x61, 0x62, 0x63]); // "abc"
    const spec: CipherSpec = {
      id: "toy-state-to-bytes-roundtrip",
      name: "state-to-bytes round-trip (Slice 2.6b)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "src",
          type: "state-to-bytes@1",
          params: {},
        },
        {
          kind: "step",
          id: "sink",
          type: "bytes-to-state@1",
          params: {},
          portInputs: {
            input: { node: "src", port: "output" },
          },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: plaintext },
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual(Array.from(plaintext));
  });

  it("state-to-bytes output is consumable by downstream port-native primitives", () => {
    // Wire state-to-bytes' output into an xor along with a constant, then
    // bytes-to-state back. Result should be plaintext ⊕ constant.
    const plaintext = new Uint8Array([0x10, 0x20, 0x30, 0x40]);
    const constant = [0x01, 0x02, 0x03, 0x04];
    const spec: CipherSpec = {
      id: "toy-state-to-bytes-xor",
      name: "state-to-bytes + xor + bytes-to-state (Slice 2.6b)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "src",
          type: "state-to-bytes@1",
          params: {},
        },
        {
          kind: "step",
          id: "mask",
          type: "constant-load@1",
          params: { bytes: constant },
        },
        {
          kind: "step",
          id: "x",
          type: "xor@1",
          params: { inputCount: 2 },
          portInputs: {
            operand0: { node: "src", port: "output" },
            operand1: { node: "mask", port: "output" },
          },
        },
        {
          kind: "step",
          id: "sink",
          type: "bytes-to-state@1",
          params: {},
          portInputs: {
            input: { node: "x", port: "output" },
          },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: plaintext },
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    // plaintext ⊕ constant per byte
    expect(Array.from(trace.finalState.bytes)).toEqual([
      0x10 ^ 0x01,
      0x20 ^ 0x02,
      0x30 ^ 0x03,
      0x40 ^ 0x04,
    ]);
  });

  it("off-flag dispatch throws (port-native, no legacy executor)", () => {
    const spec: CipherSpec = {
      id: "toy-state-to-bytes-offflag",
      name: "off-flag throw",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "src",
          type: "state-to-bytes@1",
          params: {},
        },
      ],
    };
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array([0x01]) },
      }),
    ).toThrow(/port-native; requires portedDispatchEnabled: true/);
  });
});
