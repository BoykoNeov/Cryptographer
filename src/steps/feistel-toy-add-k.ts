/**
 * Toy Feistel F-function: per-byte modular addition with a constant key.
 * Used ONLY by `tests/feistel-primitive.test.ts` and the toy spec wired
 * into the default registry — NOT a shipped cipher step type.
 *
 * Asymmetry matters. The plan (`docs/plans/des-feistel.md` Phase 2)
 * deliberately picks `F(R, K) = (R + K) mod 256` over the cheaper
 * `F(R, K) = R XOR K`: the XOR version is self-inverse and would round-
 * trip a 2-round Feistel even with a SWAPPED `combineKind`, hiding any
 * runtime bug in the combine application. Addition's lack of self-
 * inverse means a buggy combine produces a different ciphertext, which
 * the KAT assertion in the test catches.
 *
 * Params:
 *   - `k`: the constant key byte (0..255).
 *
 * Input/output:
 *   - State: `bytes` (any non-zero length — the runtime slices each
 *     track to its declared `inputBytes`, so this executor operates on
 *     a track-local 2-byte slice in the test, but isn't length-coupled).
 *   - Output: same length, each byte = (input + k) mod 256.
 *
 * The executor is registered as `feistel.toy-add-k@1` in
 * `src/ciphers/default-registry.ts` and is exercised only by Phase 2
 * tests. When the toy is no longer needed (after DES ships in Phase 3
 * and exercises every branching-primitive path), this file + its
 * registration can be removed.
 */

import type {
  Json,
  PortContract,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";

export const feistelToyAddK: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("feistel.toy-add-k@1 expects bytes state");
  }
  const k = readK(params);
  const out = new Uint8Array(state.bytes.length);
  for (let i = 0; i < state.bytes.length; i++) {
    out[i] = ((state.bytes[i] ?? 0) + k) & 0xff;
  }
  return { state: { shape: "bytes", bytes: out } };
};

const readK = (params: Json): number => {
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("feistel.toy-add-k@1 params must be an object with `k`");
  }
  const k = (params as { k?: unknown }).k;
  if (typeof k !== "number" || !Number.isInteger(k) || k < 0 || k > 255) {
    throw new Error("feistel.toy-add-k@1 param `k` must be an integer 0..255");
  }
  return k;
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.8) ───────────────
// Lifted alongside the seven DES step types in Slice 1.8. Toy fixture
// only — the legacy `feistel-primitive.test.ts` exercises it via
// `runFeistelRound` inside a 2-round Feistel spec. **byteLength absent
// on both state ports** because the toy is length-polymorphic (the
// executor operates on any non-zero length; the track-local slice size
// is determined by the parent `feistel-round`'s `inputBytes`). Matches
// Slice 1.6 Speck's polymorphic bytes-port posture (block size varies
// across Speck variants); the toy varies across test fixtures instead.

export const feistelToyAddKMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
};

export const feistelToyAddKPortContract: PortContract = {
  inputs: new Map([["state", { layout: "raw" }]]),
  outputs: new Map([["state", { layout: "raw" }]]),
};

export const feistelToyAddKDoc: StepDocumentation = {
  name: "Toy Feistel F (add-K)",
  summary: "Per-byte modular addition with a constant key. Test-fixture only.",
  detail:
    "Adds the constant `k` to each byte of the current track-local state, mod 256. " +
    "Used as the F-function for the Phase-2 toy Feistel test fixture. Asymmetric " +
    "(not self-inverse) so a swapped combine kind would produce a different ciphertext.",
  params: new Map([["k", "Constant byte added per position. Integer 0..255."]]),
  references: ["docs/plans/des-feistel.md (Phase 2)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};
