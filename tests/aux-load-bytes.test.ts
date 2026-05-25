/**
 * aux-load-bytes@1 — port-native aux→port bridge primitive tests
 * (universal-port plan Phase 2 Slice 2.6d, 2026-05-25).
 *
 * Two layers, mirroring `state-to-bytes.test.ts`:
 *
 *  1. **Executor unit tests** — direct invocation against `inputs` Map.
 *     The executor receives aux bytes via `inputs.get("input")` (which
 *     the runtime auto-projects from `aux[params.auxName]` via
 *     meta.auxReadPorts) and emits them verbatim on `output`.
 *
 *  2. **Runtime integration tests** — the load-bearing
 *     `meta.auxReadPorts` mechanism. Wire a spec that loads bytes into
 *     aux (`generic.aux-load@1`) and reads them back via
 *     `aux-load-bytes@1`. Assert the bytes round-trip end-to-end.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { CipherSpec, Json, StepContext } from "@/core/types";
import { auxLoadBytes } from "@/steps/aux-load-bytes";
import { describe, expect, it } from "vitest";

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const callExecutor = (input: Uint8Array, params: Json): Uint8Array => {
  const out = auxLoadBytes(new Map([["input", input]]), params, CTX);
  return out.get("output") as Uint8Array;
};

// ─── Executor unit tests ──────────────────────────────────────────────────

describe("aux-load-bytes@1 — executor identity-passthrough on the port layer", () => {
  it("emits the input bytes verbatim on the output port", () => {
    const bytes = new Uint8Array([0x6a, 0x09, 0xe6, 0x67]); // SHA-256 H_0
    const out = callExecutor(bytes, { auxName: "H", byteLength: 4 });
    expect(out).toEqual(bytes);
  });

  it("output is a fresh buffer — mutating it does not affect the input", () => {
    const bytes = new Uint8Array([0x01, 0x02, 0x03]);
    const out = callExecutor(bytes, { auxName: "K", byteLength: 3 });
    out[0] = 0xff;
    expect(bytes[0]).toBe(0x01);
  });

  it("handles a 256-byte input (SHA-256 K-table size)", () => {
    const big = new Uint8Array(256);
    for (let i = 0; i < 256; i++) big[i] = i;
    const out = callExecutor(big, { auxName: "K", byteLength: 256 });
    expect(out).toEqual(big);
  });

  it("throws when the `input` port is missing", () => {
    expect(() => auxLoadBytes(new Map(), { auxName: "K", byteLength: 4 }, CTX)).toThrow(
      /input port 'input' is not wired/,
    );
  });

  it("throws when params is null", () => {
    expect(() => auxLoadBytes(new Map([["input", new Uint8Array(4)]]), null, CTX)).toThrow(
      /params must be an object/,
    );
  });

  it("throws when params.auxName is missing", () => {
    expect(() =>
      auxLoadBytes(new Map([["input", new Uint8Array(4)]]), { byteLength: 4 }, CTX),
    ).toThrow(/params.auxName must be a string/);
  });

  it("throws when params.auxName is not a string", () => {
    expect(() =>
      auxLoadBytes(new Map([["input", new Uint8Array(4)]]), { auxName: 42, byteLength: 4 }, CTX),
    ).toThrow(/params.auxName must be a string/);
  });

  it("throws when params.byteLength is missing", () => {
    expect(() =>
      auxLoadBytes(new Map([["input", new Uint8Array(4)]]), { auxName: "K" }, CTX),
    ).toThrow(/params.byteLength must be a positive integer/);
  });

  it("throws when params.byteLength is zero", () => {
    expect(() =>
      auxLoadBytes(new Map([["input", new Uint8Array(4)]]), { auxName: "K", byteLength: 0 }, CTX),
    ).toThrow(/params.byteLength must be a positive integer/);
  });

  it("throws when params.byteLength is negative", () => {
    expect(() =>
      auxLoadBytes(new Map([["input", new Uint8Array(4)]]), { auxName: "K", byteLength: -1 }, CTX),
    ).toThrow(/params.byteLength must be a positive integer/);
  });

  it("throws when params.byteLength is not an integer", () => {
    expect(() =>
      auxLoadBytes(new Map([["input", new Uint8Array(4)]]), { auxName: "K", byteLength: 1.5 }, CTX),
    ).toThrow(/params.byteLength must be a positive integer/);
  });

  it("allows empty string auxName (authoring-state default)", () => {
    // Empty auxName is allowed at the executor level; the meta still emits
    // a binding so the runtime records auxReadMissing. The executor itself
    // never sees the empty auxName impact — by the time it runs, inputs
    // is either populated (somehow) or it threw on the missing port.
    const bytes = new Uint8Array([0x42]);
    const out = callExecutor(bytes, { auxName: "", byteLength: 1 });
    expect(out).toEqual(bytes);
  });
});

// ─── Runtime integration: aux projection via meta.auxReadPorts ────────────

describe("aux-load-bytes@1 — runtime aux-read via meta.auxReadPorts", () => {
  /**
   * End-to-end: load 4 bytes into aux["src"] via `generic.aux-load@1`,
   * then read them back via `aux-load-bytes@1` and pipe through
   * `bytes-to-state@1` so finalState carries the round-tripped bytes.
   * If meta.auxReadPorts is wired right, finalState matches the aux-loaded
   * bytes; if it's broken, the executor throws "input port 'input' not
   * wired" because the runtime never projected aux into the port.
   */
  it("round-trips bytes through aux: aux-load → aux-load-bytes → state", () => {
    const auxBytes = [0x6a, 0x09, 0xe6, 0x67]; // SHA-256 H_0
    const spec: CipherSpec = {
      id: "toy-aux-load-bytes-roundtrip",
      name: "aux-load-bytes round-trip (Slice 2.6d)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        // 1. Publish 4 bytes into aux["src"] via the lifted-legacy
        //    `generic.aux-load@1` (it takes a literal value param).
        {
          kind: "step",
          id: "publish",
          type: "generic.aux-load@1",
          params: { auxName: "src", value: auxBytes },
        },
        // 2. Read aux["src"] via the new port-native primitive.
        {
          kind: "step",
          id: "fetch",
          type: "aux-load-bytes@1",
          params: { auxName: "src", byteLength: 4 },
        },
        // 3. Pipe the output into state via bytes-to-state.
        {
          kind: "step",
          id: "sink",
          type: "bytes-to-state@1",
          params: {},
          portInputs: {
            input: { node: "fetch", port: "output" },
          },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual(auxBytes);
  });

  /**
   * Multiple consumers of the same aux key. Two separate `aux-load-bytes@1`
   * leaves read aux["K"] independently; the outputs feed into an xor.
   * Verifies aux read is idempotent and re-readable.
   */
  it("two leaves can read the same aux key independently", () => {
    const auxBytes = [0xff, 0xff, 0xff, 0xff];
    const spec: CipherSpec = {
      id: "toy-aux-load-bytes-fanout",
      name: "aux fanout (Slice 2.6d)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "publish",
          type: "generic.aux-load@1",
          params: { auxName: "K", value: auxBytes },
        },
        {
          kind: "step",
          id: "fetch-a",
          type: "aux-load-bytes@1",
          params: { auxName: "K", byteLength: 4 },
        },
        {
          kind: "step",
          id: "fetch-b",
          type: "aux-load-bytes@1",
          params: { auxName: "K", byteLength: 4 },
        },
        // XOR them — A ⊕ A = 0 — to prove both reads delivered the same bytes.
        {
          kind: "step",
          id: "x",
          type: "xor@1",
          params: { inputCount: 2 },
          portInputs: {
            operand0: { node: "fetch-a", port: "output" },
            operand1: { node: "fetch-b", port: "output" },
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
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual([0, 0, 0, 0]);
  });

  /**
   * Off-flag dispatch should throw the "requires portedDispatchEnabled:
   * true" guard — `aux-load-bytes@1` is port-native (no `legacy` executor
   * for the off-flag path to fall back to).
   */
  it("off-flag dispatch throws (port-native, no legacy executor)", () => {
    const spec: CipherSpec = {
      id: "toy-aux-load-bytes-offflag",
      name: "off-flag throw",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "publish",
          type: "generic.aux-load@1",
          params: { auxName: "K", value: [0x01] },
        },
        {
          kind: "step",
          id: "fetch",
          type: "aux-load-bytes@1",
          params: { auxName: "K", byteLength: 1 },
        },
      ],
    };
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      }),
    ).toThrow(/port-native; requires portedDispatchEnabled: true/);
  });

  /**
   * Missing aux key — fresh palette drop with auxName="" or wrong name.
   * The runtime should record auxReadMissing on the frame; the executor
   * should throw "input port 'input' is not wired" because the projection
   * found no aux value to fill the port with.
   */
  it("throws at run-time when aux[auxName] is missing", () => {
    const spec: CipherSpec = {
      id: "toy-aux-load-bytes-missing",
      name: "missing-aux throw",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        // No publish step — aux["X"] is unset.
        {
          kind: "step",
          id: "fetch",
          type: "aux-load-bytes@1",
          params: { auxName: "X", byteLength: 4 },
        },
      ],
    };
    expect(() =>
      runSpec(spec, buildDefaultRegistry(), {
        initialState: { shape: "bytes", bytes: new Uint8Array(0) },
        portedDispatchEnabled: true,
      }),
    ).toThrow(/input port 'input' is not wired/);
  });

  /**
   * Length-mismatch coercion — the aux value is 6 bytes but the leaf
   * declares byteLength=4. The runtime's Slice 1.12 port-length coercion
   * should truncate from the right and emit a synthetic __coerce__ frame.
   */
  it("coerces when the aux value's length differs from declared byteLength", () => {
    const auxBytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]; // 6 bytes
    const spec: CipherSpec = {
      id: "toy-aux-load-bytes-coerce",
      name: "length-mismatch coercion",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "publish",
          type: "generic.aux-load@1",
          params: { auxName: "src", value: auxBytes },
        },
        {
          kind: "step",
          id: "fetch",
          type: "aux-load-bytes@1",
          params: { auxName: "src", byteLength: 4 }, // declare 4, actual 6
        },
        {
          kind: "step",
          id: "sink",
          type: "bytes-to-state@1",
          params: {},
          portInputs: {
            input: { node: "fetch", port: "output" },
          },
        },
      ],
    };
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(0) },
      portedDispatchEnabled: true,
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    // Truncate-from-right: keep first 4 bytes.
    expect(Array.from(trace.finalState.bytes)).toEqual([0x01, 0x02, 0x03, 0x04]);
    // Verify a __coerce__ frame was emitted between publish and fetch.
    const coerceFrames = trace.frames.filter((f) => f.stepType === "__coerce__");
    expect(coerceFrames.length).toBeGreaterThan(0);
  });
});
