/**
 * `generic.state-to-aux-bytes@1` — dedicated unit tests
 * (universal-port plan Phase 2 Slice 2.6d follow-up, 2026-05-25).
 *
 * The bytes-shape sibling of `generic.state-to-aux@1` shipped in step 4
 * of Slice 2.6d, bundled into the SHA-256 spec rewrite + parity test.
 * It got coverage **indirectly** via the SHA-256 KAT — a contract drift
 * in `stateToAuxBytesMeta` or `stateToAuxBytesPortContract` would break
 * SHA-256 — but the three other primitives shipped in the same slice
 * (`aux-load-bytes@1`, `byte-slice@1`, `split-bytes@1`) each landed
 * with their own dedicated test file. This closes the coverage
 * asymmetry.
 *
 * Five tests, each pinning one axis the SHA-256 KAT would only catch
 * incidentally:
 *
 *   1. **Executor round-trip** — direct executor call, snapshot bytes
 *      equal state bytes. State input/output are independent of the
 *      runtime's port projection layer.
 *
 *   2. **Length polymorphism** — synthetic specs at 8 / 32 / 256 bytes.
 *      The whole point of the sibling registration (vs widening the
 *      matrix variant) is `byteLength: undefined` on every port.
 *
 *   3. **Empty-auxName** — passthrough; no aux write. Fresh palette-drop
 *      sentinel. The executor early-returns; the meta's
 *      `auxWritePorts(params)` returns an empty Map so the runtime
 *      doesn't try to `aux.set("", ...)`.
 *
 *   4. **State passthrough** — state arrives at the next step unchanged.
 *      This is what `shapeContract: { output: "preserveInput" }` promises.
 *
 *   5. **Synthetic integration: snapshot then read back** — the wiring
 *      SHA-256 actually depends on. Pipe state-to-aux-bytes → aux-load-bytes
 *      → bytes-to-state and assert (a) `finalState.bytes` equals the
 *      initial state, AND (b) `trace.finalAux.get(name)` is a bare
 *      `Uint8Array`, NOT a `BytesState` object. The bare-Uint8Array
 *      assertion is the discriminator vs the matrix sibling (which decodes
 *      to MatrixState) and the load-bearing invariant for `aux-load-bytes@1`
 *      downstream — that step type's port-native executor doesn't reach
 *      into a State wrapper.
 *
 * ## No legacy-vs-ported parity here
 *
 * The matrix sibling's `tests/runtime-ported-dispatch-chaining.test.ts`
 * asserts frame-by-frame parity between flag-on and flag-off. For the
 * bytes sibling, parity would *not* hold by `toEqual`:
 *
 *   - Flag-on (ported path): `auxValueToPortBytes(BytesState) → Uint8Array`,
 *     then runtime decode via `layout: "raw"` → `aux[name] = Uint8Array`.
 *   - Flag-off (legacy path): `aux[name] = BytesState` directly (no
 *     port projection happens at all).
 *
 * The wrappers diverge — `Uint8Array` vs `{ shape: "bytes", bytes: ... }`.
 * No shipped spec observes this asymmetry because the only consumer
 * (`aux-load-bytes@1`) is port-native and throws under flag-off, so
 * SHA-256 only runs flag-on. The advisor (2026-05-25) confirmed: writing
 * a parity test here would either fail honestly or require a custom
 * equality that strips the State wrapper, at which point it tests
 * nothing real. The ported-path-only invariant in test #5 is the
 * substantive load-bearing assertion.
 *
 * If a future cipher needs `state-to-aux-bytes` under flag-off (legacy-
 * only spec), the BytesState-vs-Uint8Array drift will bite — and a
 * dedicated parity test will become meaningful at that point.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import type { BytesState, CipherSpec, StepContext } from "@/core/types";
import { stateToAux } from "@/steps/state-to-aux";
import { describe, expect, it } from "vitest";

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const bytesStateOf = (values: readonly number[]): BytesState =>
  makeBytesState(new Uint8Array(values));

// ─── 1. Executor round-trip ───────────────────────────────────────────────

describe("state-to-aux-bytes@1 — executor unit semantics (shared with matrix sibling)", () => {
  it("snapshot bytes equal state bytes (bytes-shape state)", () => {
    const state = bytesStateOf([0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85]);
    const result = stateToAux(state, { auxName: "snap" }, CTX);
    const written = result.auxWrites?.get("snap") as BytesState;
    expect(written.shape).toBe("bytes");
    expect(Array.from(written.bytes)).toEqual(Array.from(state.bytes));
    // Deep clone — mutating the snapshot must not bleed back into state.
    written.bytes[0] = 0xff;
    expect(state.bytes[0]).toBe(0x6a);
  });

  // ─── 3. Empty-auxName: no aux write ─────────────────────────────────────

  it("empty auxName: passthrough, no aux write", () => {
    const state = bytesStateOf([0x01, 0x02, 0x03]);
    const result = stateToAux(state, { auxName: "" }, CTX);
    expect(result.auxWrites).toBeUndefined();
    // State still passes through as-is — the executor early-returns
    // with `{ state }` before doing any work.
    expect(result.state).toBe(state);
  });
});

// ─── Integration tests (2, 4, 5) ──────────────────────────────────────────

describe("state-to-aux-bytes@1 — runtime integration under flag-on", () => {
  // ─── 2. Length polymorphism ─────────────────────────────────────────────
  //
  // The whole reason a sibling registration exists (vs widening the matrix
  // variant) is `byteLength: undefined` on every port — bytes-shape state
  // can be any length. Walk three sizes that bracket the realistic range:
  // 8 (Speck32 block), 32 (SHA-256 H_state), 256 (SHA-256 W schedule). If
  // the PortContract regresses to a fixed byteLength, all three of these
  // would either throw or coerce.

  for (const byteLength of [8, 32, 256]) {
    it(`accepts a ${byteLength}-byte state and snapshots all bytes`, () => {
      // Build a deterministic test pattern. byte_i = (i * 31) mod 256.
      const initial = new Uint8Array(byteLength);
      for (let i = 0; i < byteLength; i++) initial[i] = (i * 31) % 256;

      const spec: CipherSpec = {
        id: `toy-state-to-aux-bytes-${byteLength}`,
        name: `state-to-aux-bytes length polymorphism @ ${byteLength}`,
        stateShape: "bytes",
        inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
        steps: [
          {
            kind: "step",
            id: "snap",
            type: "generic.state-to-aux-bytes@1",
            params: { auxName: "out" },
          },
        ],
      };

      const trace = runSpec(spec, buildDefaultRegistry(), {
        initialState: makeBytesState(initial),
        portedDispatchEnabled: true,
      });

      const snapshot = trace.finalAux.get("out");
      expect(snapshot).toBeInstanceOf(Uint8Array);
      // Same byte content as the initial state — round-tripping length-
      // dependent layout encode/decode would corrupt at off-by-one.
      expect(Array.from(snapshot as Uint8Array)).toEqual(Array.from(initial));
    });
  }

  // ─── 4. State passthrough ───────────────────────────────────────────────

  it("state passes through unchanged to the next step", () => {
    // Two snapshots back-to-back — if the first mutated state, the second
    // would snapshot something different. Pin the chain.
    const initial = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

    const spec: CipherSpec = {
      id: "toy-state-to-aux-bytes-passthrough",
      name: "state-to-aux-bytes passthrough",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "snap-a",
          type: "generic.state-to-aux-bytes@1",
          params: { auxName: "a" },
        },
        {
          kind: "step",
          id: "snap-b",
          type: "generic.state-to-aux-bytes@1",
          params: { auxName: "b" },
        },
      ],
    };

    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: makeBytesState(initial),
      portedDispatchEnabled: true,
    });

    // Final state is the unmodified input.
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual(Array.from(initial));

    // Both snapshots captured the same bytes — passthrough preserved
    // state across the first snap so the second saw the same input.
    const snapA = trace.finalAux.get("a") as Uint8Array;
    const snapB = trace.finalAux.get("b") as Uint8Array;
    expect(Array.from(snapA)).toEqual(Array.from(initial));
    expect(Array.from(snapB)).toEqual(Array.from(initial));
  });

  // ─── 5. Synthetic integration: snapshot then read back ──────────────────
  //
  // The wiring SHA-256 actually depends on. `state-to-aux-bytes` snapshots
  // state into aux["W"]; `aux-load-bytes` (port-native, no legacy) reads
  // aux["W"] back into a port and pipes to a state sink. Two assertions:
  //
  //   (a) finalState.bytes equals the initial state — full round-trip.
  //   (b) trace.finalAux.get("W") is a BARE Uint8Array, NOT a BytesState
  //       object. This is the discriminator vs the matrix sibling and
  //       the load-bearing invariant for `aux-load-bytes@1` downstream:
  //       its executor reads aux as raw bytes via the runtime's port
  //       projection layer, not by reaching into a State wrapper.

  it("snapshot → aux-load-bytes round-trip; aux value is bare Uint8Array", () => {
    const initial = new Uint8Array([0x6a, 0x09, 0xe6, 0x67]);

    const spec: CipherSpec = {
      id: "toy-state-to-aux-bytes-roundtrip",
      name: "state-to-aux-bytes → aux-load-bytes round-trip",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        // Snapshot state into aux["W"]. State passes through unchanged.
        {
          kind: "step",
          id: "publish",
          type: "generic.state-to-aux-bytes@1",
          params: { auxName: "W" },
        },
        // Read aux["W"] back into a port. Port-native — only works under
        // portedDispatchEnabled: true.
        {
          kind: "step",
          id: "fetch",
          type: "aux-load-bytes@1",
          params: { auxName: "W", byteLength: 4 },
        },
        // Sink the port output back into state, replacing the (still
        // unchanged) initial state. If the wiring is correct, finalState
        // matches initial.
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
      initialState: makeBytesState(initial),
      portedDispatchEnabled: true,
    });

    // (a) Full round-trip — bytes flow state → aux → port → state intact.
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes shape");
    expect(Array.from(trace.finalState.bytes)).toEqual(Array.from(initial));

    // (b) The load-bearing discriminator: aux["W"] is a Uint8Array, not
    // a BytesState. If the bytes-sibling's PortContract regressed to
    // matrix-cm-4x4 layout (or anything other than "raw"), this would
    // fail with an object that has `.shape` / `.bytes` fields.
    const auxW = trace.finalAux.get("W");
    expect(auxW).toBeInstanceOf(Uint8Array);
    // Negative assertion: it's NOT a State object.
    expect(typeof auxW === "object" && auxW !== null && "shape" in auxW).toBe(false);
    // Also pin the byte content.
    expect(Array.from(auxW as Uint8Array)).toEqual(Array.from(initial));
  });
});
