/**
 * Port-provenance — cell-level "which input byte feeds this output byte" math
 * for the linear-view inspector hover (inspector-cell-hover plan, Slice 1,
 * 2026-06-04). The port-native rebuild of the cell-level provenance highlight
 * introduced in `21d06cf` (2026-05-18) and deleted in `a1b64b2` (the Slice
 * 2.9c-e "honest close") once it rotted onto the retired `stateAfter` field +
 * MatrixView.
 *
 * **Why this won't rot the same way.** Provenance is pure *index* math, never a
 * value lookup. For every port-native primitive, "which input cell feeds output
 * cell `i`" is fixed by the primitive's *structure* — its `params` plus the port
 * byte-*lengths* — and never by the byte *values*. So the whole feature is a
 * pure function `(params, portInputs, portOutputs, outPort, outCellIndex) →
 * ProvenanceCell[]`. It may read port lengths (for `concat`/`split`/`slice`); it
 * must NEVER branch on a byte value. That value-independence is the property the
 * node tests pin and the reason this module can't desync onto a per-frame value
 * snapshot.
 *
 * **Why this lives in `core/` and is centralized (decided 2026-06-04).** It is
 * pure index math, node-testable with no jsdom, and cannot desync onto a render
 * surface — the exact rot vector last time. The fns are NOT co-located in each
 * `src/steps/<prim>.ts`: that would invert the layer direction (`core/` importing
 * executor-adjacent exports from `steps/`). The desync hard-requirement is met
 * instead by an executor *perturbation cross-check* in `tests/port-provenance.test.ts`
 * — for each gather/linear primitive it perturbs the REAL executor's input cells
 * and asserts the provenance set equals the set of cells whose perturbation
 * changes the output. That ties provenance to executor *behaviour* (it catches a
 * gather→scatter semantic drift), strictly stronger than co-location's eyeball
 * guard.
 *
 * **Scope = exact mappings only (v1).** Approximate mappings that render
 * identically to exact ones would silently break the "missing never wrong" trust
 * property and miseducate (e.g. "byte 3 ← byte 3" for a bit-rotate-by-7, whose
 * output bits come from two input bytes). v1 ships every EXACT mapping; the
 * approximate / partial / no-input / plumbing primitives are allowlisted out
 * (`PROVENANCE_NO_OP_ALLOWLIST`) and highlight nothing. See
 * `docs/plans/inspector-cell-hover.md` for the per-primitive table + the four
 * distinct allowlist rationales.
 */

import type { Json } from "./types";

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * One input cell that feeds the hovered output cell. `portName` names the INPUT
 * port row (`input`, `operand`, `operand0`, …); `cellIndex` is the byte position
 * within that row; `label` is an optional badge (the GF(2⁸) coefficient `×2` for
 * MixColumns — the only v1 user of the channel).
 */
export type ProvenanceCell = {
  readonly portName: string;
  readonly cellIndex: number;
  readonly label?: string;
};

/**
 * Everything a provenance fn may read. `portInputs`/`portOutputs` are passed for
 * their *lengths only* — a fn that branched on a byte value would break the
 * value-independence property. `outPort` disambiguates multi-output primitives
 * (`split-bytes` has `output0`…`output{N-1}`); `outCellIndex` is the hovered
 * byte's position within `outPort`.
 */
export type ProvenanceCtx = {
  readonly params: Json;
  readonly portInputs: ReadonlyMap<string, Uint8Array>;
  readonly portOutputs: ReadonlyMap<string, Uint8Array>;
  readonly outPort: string;
  readonly outCellIndex: number;
};

export type ProvenanceFn = (ctx: ProvenanceCtx) => readonly ProvenanceCell[];

// ─── Param helpers ──────────────────────────────────────────────────────────
//
// Every fn is DEFENSIVE: it returns `[]` (highlight nothing) on any malformed
// params / missing port / out-of-range index rather than throwing. The hover
// path runs on every mouse-move; a throw there would break the inspector. "No
// highlight" is always the safe fallback per the "missing never wrong" stance.

const asRecord = (params: Json): Record<string, Json> | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  return params as Record<string, Json>;
};

const positiveInt = (v: Json | undefined): number | null =>
  typeof v === "number" && Number.isInteger(v) && v >= 1 ? v : null;

const nonNegativeInt = (v: Json | undefined): number | null =>
  typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : null;

/** Same-position single-source mapping `output[i] ← input[i]`. Used by `not@1`
 *  (bit complement) and `byte-substitute@1` (S-box swap — the VALUE changes but
 *  the cell position is preserved). */
const samePositionProvenance =
  (portName: string): ProvenanceFn =>
  (ctx) => {
    const bytes = ctx.portInputs.get(portName);
    if (bytes === undefined || ctx.outCellIndex >= bytes.length) return [];
    return [{ portName, cellIndex: ctx.outCellIndex }];
  };

// ─── Exact provenance fns ───────────────────────────────────────────────────

/**
 * `xor@1` / `and@1`: `output[i] ← operand0[i] … operand{N-1}[i]` (same column,
 * N = `params.inputCount`). A half-wired operand (missing port) is skipped, not
 * fabricated. The mapping is identical for XOR and AND — both are column-wise
 * N-ary combiners — so they share this fn.
 */
const operandColumnProvenance: ProvenanceFn = (ctx) => {
  const p = asRecord(ctx.params);
  const n = positiveInt(p?.inputCount);
  if (n === null) return [];
  const i = ctx.outCellIndex;
  const cells: ProvenanceCell[] = [];
  for (let k = 0; k < n; k++) {
    const name = `operand${k}`;
    const bytes = ctx.portInputs.get(name);
    if (bytes !== undefined && i < bytes.length) {
      cells.push({ portName: name, cellIndex: i });
    }
  }
  return cells;
};

/**
 * `xor-with-aux@1` (AES AddRoundKey, DES XOR-with-K): `output[i] ← input[i],
 * operand[i]`. The `operand` row is the round key the runtime projected from
 * `aux[auxName]` onto the frame's `portInputs` (de-risk check (a),
 * `runtime.ts:~720`). Half-wired guard: if the `operand` port is absent
 * (`auxReadMissing`), emit only `{input, i}` — never a phantom missing-port
 * source.
 */
const xorWithAuxProvenance: ProvenanceFn = (ctx) => {
  const i = ctx.outCellIndex;
  const cells: ProvenanceCell[] = [];
  const input = ctx.portInputs.get("input");
  if (input !== undefined && i < input.length) cells.push({ portName: "input", cellIndex: i });
  const operand = ctx.portInputs.get("operand");
  if (operand !== undefined && i < operand.length)
    cells.push({ portName: "operand", cellIndex: i });
  return cells;
};

/**
 * `permute@1` (AES ShiftRows): `output[i] ← input[indices[i]]` — a pure forward
 * gather. The provenance is the forward read of `indices`, the SIMPLEST exact
 * mapping (de-risk check (b): no table inversion, so no "silent wrong-inversion"
 * failure mode — that only existed for a scatter).
 */
const permuteProvenance: ProvenanceFn = (ctx) => {
  const p = asRecord(ctx.params);
  const indices = p?.indices;
  if (!Array.isArray(indices)) return [];
  const src = indices[ctx.outCellIndex];
  if (typeof src !== "number" || !Number.isInteger(src) || src < 0) return [];
  const input = ctx.portInputs.get("input");
  if (input === undefined || src >= input.length) return [];
  return [{ portName: "input", cellIndex: src }];
};

/**
 * `concat@1`: the output is `input0 || input1 || … || input{N-1}`, so global
 * output index `i` maps to the input port whose running-offset range covers `i`.
 * Reads input port LENGTHS (allowed — lengths, not values) to walk the offsets.
 * A missing port aborts (can't resolve later offsets reliably).
 */
const concatProvenance: ProvenanceFn = (ctx) => {
  const p = asRecord(ctx.params);
  const n = positiveInt(p?.inputCount);
  if (n === null) return [];
  const i = ctx.outCellIndex;
  let offset = 0;
  for (let k = 0; k < n; k++) {
    const name = `input${k}`;
    const bytes = ctx.portInputs.get(name);
    if (bytes === undefined) return [];
    if (i < offset + bytes.length) {
      return [{ portName: name, cellIndex: i - offset }];
    }
    offset += bytes.length;
  }
  return [];
};

/**
 * `split-bytes@1`: the inverse of concat — one `input`, N outputs
 * `output0`…`output{N-1}`. Output `output{k}` cell `j` ← `input[(Σ widths[0..k-1])
 * + j]`. The `outPort` name carries `k`; `params.widths` gives the offsets.
 */
const splitBytesProvenance: ProvenanceFn = (ctx) => {
  const p = asRecord(ctx.params);
  const widths = p?.widths;
  if (!Array.isArray(widths)) return [];
  const m = /^output(\d+)$/.exec(ctx.outPort);
  if (m === null) return [];
  const k = Number(m[1]);
  if (!Number.isInteger(k) || k < 0 || k >= widths.length) return [];
  let offset = 0;
  for (let j = 0; j < k; j++) {
    const w = widths[j];
    if (typeof w !== "number") return [];
    offset += w;
  }
  const wk = widths[k];
  if (typeof wk !== "number" || ctx.outCellIndex >= wk) return [];
  const srcIndex = offset + ctx.outCellIndex;
  const input = ctx.portInputs.get("input");
  if (input === undefined || srcIndex >= input.length) return [];
  return [{ portName: "input", cellIndex: srcIndex }];
};

/** `byte-slice@1`: `output[i] ← input[offset + i]` (a single contiguous range). */
const byteSliceProvenance: ProvenanceFn = (ctx) => {
  const p = asRecord(ctx.params);
  const offset = nonNegativeInt(p?.offset);
  if (offset === null) return [];
  const srcIndex = offset + ctx.outCellIndex;
  const input = ctx.portInputs.get("input");
  if (input === undefined || srcIndex >= input.length) return [];
  return [{ portName: "input", cellIndex: srcIndex }];
};

/**
 * `gf-matrix-multiply@1` (AES MixColumns) — the headline, and the one v1 user of
 * the `label` channel. The input is N column-major 4-byte columns
 * (`out[r + 4c] = ⊕_k gfMul(matrix[r][k], in[k + 4c])`), so output cell `i` lives
 * at column `c = ⌊i/4⌋`, row `r = i mod 4`, and its contributors are the four
 * same-column input cells `{4c+k}`, each labelled with its GF(2⁸) coefficient
 * `×matrix[r][k]`.
 *
 * **Zero-coefficient contributors are OMITTED** — a `matrix[r][k] === 0` cell
 * does not feed the output. This is the honest rendering for the "swap in the
 * identity matrix and watch diffusion collapse" pedagogy: with the identity
 * matrix the hover shows ONE source (the diagonal), not four. Pinned by the
 * identity-matrix node test.
 */
const gfMatrixMultiplyProvenance: ProvenanceFn = (ctx) => {
  const p = asRecord(ctx.params);
  const matrix = p?.matrix;
  if (!Array.isArray(matrix) || matrix.length !== 4) return [];
  const i = ctx.outCellIndex;
  const c = Math.floor(i / 4);
  const r = i % 4;
  const row = matrix[r];
  if (!Array.isArray(row) || row.length !== 4) return [];
  const input = ctx.portInputs.get("input");
  if (input === undefined) return [];
  const cells: ProvenanceCell[] = [];
  for (let k = 0; k < 4; k++) {
    const coeff = row[k];
    if (typeof coeff !== "number" || coeff === 0) continue; // omit zero-coeff
    const srcIndex = k + 4 * c;
    if (srcIndex >= input.length) continue;
    cells.push({ portName: "input", cellIndex: srcIndex, label: `×${coeff}` });
  }
  return cells;
};

// ─── Registry + allowlist ───────────────────────────────────────────────────

/**
 * The 12 EXACT-mapping provenance fns, keyed by bare port-native step type. The
 * UI's `PortFlowView` resolves a hovered output cell's sources via
 * `lookupProvenance(frame.stepType)`.
 */
const PROVENANCE_REGISTRY: ReadonlyMap<string, ProvenanceFn> = new Map<string, ProvenanceFn>([
  ["xor@1", operandColumnProvenance],
  ["and@1", operandColumnProvenance],
  ["not@1", samePositionProvenance("input")],
  ["xor-with-aux@1", xorWithAuxProvenance],
  ["byte-substitute@1", samePositionProvenance("input")],
  // `truncate-to-reference@1`: the surviving bytes keep their positions, so
  // `output[i] ← input[i]` — the identity prefix. `reference` contributes NO
  // cell: only its length is read, never its bytes, and highlighting it would
  // claim a data dependency that does not exist. The guard inside
  // `samePositionProvenance` is naturally satisfied here (output is never
  // wider than input), which is exactly what makes this mapping exact.
  ["truncate-to-reference@1", samePositionProvenance("input")],
  ["permute@1", permuteProvenance],
  ["concat@1", concatProvenance],
  ["split-bytes@1", splitBytesProvenance],
  ["byte-slice@1", byteSliceProvenance],
  ["gf-matrix-multiply@1", gfMatrixMultiplyProvenance],
  // @2 (Twofish MDS) shares @1's provenance exactly — the column contributor
  // math is index-only (`out[r+4c]` ← same-column input cells `{4c+k}`); the
  // field polynomial differs but does not change WHICH cells contribute.
  ["gf-matrix-multiply@2", gfMatrixMultiplyProvenance],
]);

/** Bare step types that have an exact provenance fn — exported for the
 *  coverage-contract test's set-equality pin. */
export const PROVENANCE_FN_STEP_TYPES: ReadonlySet<string> = new Set(PROVENANCE_REGISTRY.keys());

/**
 * Resolve the provenance fn for a step type, or `undefined` when none is
 * registered (the cell hover then highlights nothing — the "missing never wrong"
 * stance for approximate / partial / no-input / plumbing primitives).
 */
export const lookupProvenance = (stepType: string): ProvenanceFn | undefined =>
  PROVENANCE_REGISTRY.get(stepType);

/**
 * Bare port-native step types we deliberately give NO provenance fn, with four
 * distinct rationales (kept honest — see `docs/plans/inspector-cell-hover.md`):
 *
 *  - **approximate** (an exact-looking byte highlight would mislead):
 *    `add-mod-32@1` / `add-mod-16@1` (carry crosses byte boundaries),
 *    `rotate-bits-right@1` / `rotate-bits-left@1` / `shift-bits-right@1`
 *    (bit-level → byte-approximate),
 *    `increment-counter@1` (CTR's +1 — an exact cone that would still mislead,
 *    see its inline note),
 *    the RSA big-integer primitives `mul@1` / `sub@1` / `mod-mul@1` /
 *    `cond-mod-mul@1` / `mod-inverse@1`, the LCG family's `add-mod@1`,
 *    the Z_q vector family `zq-vec-add@1` / `zq-vec-sub@1` /
 *    `zq-vec-mul-scalar@1` (element-wise, but the dependency inside one
 *    element is value-dependent — see the inline note),
 *    and the traced extended-Euclid loop
 *    `eea-step@1` / `eea-extract@1` (full-width carries/borrows mix every
 *    output byte across all input bytes — there is no clean per-cell mapping).
 *    Deferred to the distinct `≈`-treatment fast-follow.
 *  - **no inputs**: `constant-load@1`, `right-encode@1`, `zero-fill@1` (emit a
 *    literal / a param-derived encoding / a run of zeros — nothing to point
 *    back to).
 *  - **partial — synthesizes bytes with no input source**: `pad-with-byte@1`,
 *    `append-be64-length@1`, `encode-string@1`, `bytepad@1` (output bytes are
 *    partly fabricated — a length prefix / zero padding — not all gathered).
 *  - **exact-but-plumbing — identity bridge, deferred as low-value (NOT
 *    approximate)**: `state-to-bytes@1`, `bytes-to-state@1`, `aux-load-bytes@1`.
 *    `output[i] = input[i]` is trivially exact; a 1:1 passthrough highlight just
 *    teaches nothing, so v1 defers them. Labelling them "approximate" would lie.
 *
 * The coverage-contract test asserts the bare-name registry vocabulary is
 * exactly `PROVENANCE_FN_STEP_TYPES ∪ PROVENANCE_NO_OP_ALLOWLIST`, so a future
 * bare-name primitive fails CI until a fn is wired or an entry lands here.
 */
export const PROVENANCE_NO_OP_ALLOWLIST: ReadonlySet<string> = new Set<string>([
  // approximate
  "add-mod-32@1",
  "add-mod-16@1",
  // approximate — CTR's counter +1. The dependency cone is technically exact
  // (`output[j]` can only be affected by `input[j..len-1]`, since the carry
  // travels right-to-left), but highlighting that whole tail would mislead:
  // the carry reaches past the last byte on only 1 increment in 256, so an
  // exact-looking highlight would show a dozen "contributing" bytes that
  // almost never contribute. Same rationale as `add-mod-32@1` above.
  "increment-counter@1",
  "rotate-bits-right@1",
  // approximate — same rationale as its right-handed sibling above, and for
  // the same reason: `rotate-bits-left@1` IS that sibling under the hood
  // (ROL(w, n) === ROR(w, B - n)), so a rotation by a non-multiple of 8 draws
  // each output byte from two input bytes and byte-level provenance can only
  // ever be approximate. ChaCha20's 12- and 7-bit rotations are exactly that
  // case.
  "rotate-bits-left@1",
  "shift-bits-right@1",
  // approximate — same rationale as its right-handed sibling: a shift by a
  // non-multiple of 8 draws each output byte from two input bytes. MT19937's
  // 7- and 15-bit tempering shifts are exactly that case.
  "shift-bits-left@1",
  // approximate — per-lane bit rotation (Keccak ρ); a rotated byte draws from
  // up to two input bytes, so byte-level provenance is only approximate.
  "rotate-lanes@1",
  // approximate — RSA big-integer arithmetic (carries/borrows mix all bytes)
  "mul@1",
  "sub@1",
  "mod-mul@1",
  "cond-mod-mul@1",
  "mod-inverse@1",
  // approximate — the LCG family's "+ c". Same rationale as `add-mod-32@1`
  // above (a carry crosses byte boundaries) compounded by the reduction, which
  // can rewrite every byte at once when the sum crosses the modulus.
  "add-mod@1",
  // approximate — the Z_q vector family (ML-KEM). Worth spelling out, because
  // "element-wise" makes these look like they belong with `xor@1`'s exact
  // column mapping and they do not. The true dependency set of one OUTPUT byte
  // is the whole 2-byte element it sits in, on every input port — a carry
  // between the two bytes and the reduction mod q both cross the boundary. And
  // it is worse than merely coarse: whether the low byte actually reaches the
  // high one depends on the VALUES, so no value-independent index fn can be
  // exact here. Highlighting the whole element would over-report, which is the
  // "missing never wrong" property this module exists to protect. Same
  // rationale as `add-mod@1` / `mod-mul@1` above, one element at a time.
  "zq-vec-add@1",
  "zq-vec-sub@1",
  "zq-vec-mul-scalar@1",
  // approximate — the compression pair (ML-KEM P2), same one-element-at-a-time
  // story as the three above and then some: both are round-to-nearest over a
  // ratio, so a single low-bit change in the input can carry all the way up
  // through the element. `zq-decompress@1` is additionally NOT the inverse of
  // its partner, which makes an exact-looking highlight doubly misleading.
  "zq-compress@1",
  "zq-decompress@1",
  // approximate — the dense d-bit packing pair (ML-KEM P2). These are the ONE
  // place in the Z_q family where the reason is coarseness rather than
  // value-dependence, and the distinction is worth recording because it was a
  // conscious call: the mapping IS a pure value-independent bit shuffle, so an
  // exact fn is derivable. It would just be a bad highlight. At d = 12 the
  // coefficients stop landing on byte boundaries, so one output byte carries
  // bits from two different coefficients and a byte-level cone over-reports by
  // roughly half its area. That is precisely the `rotate-bits-right@1` /
  // `shift-bits-right@1` rationale — bit-level op, byte-level answer — and the
  // "missing never wrong" stance says decline rather than over-report.
  "zq-byte-encode@1",
  "zq-byte-decode@1",
  // approximate — the traced extended-Euclid loop (RSA Phase 4): each rung's
  // quotient/remainder + the mod-φ-reduced coefficient mix every output byte
  // across the input tuple, exactly like the `mod-inverse@1` oracle they
  // decompose.
  "eea-step@1",
  "eea-extract@1",
  // no inputs
  "constant-load@1",
  "right-encode@1", // emits right_encode(value) from a param — nothing to point back to
  // no inputs — emits `byteLength` zeros. There is a further reason beyond
  // "nothing to point back to": a generator's body deliberately IGNORES the
  // bytes this produces, reading only their width. Highlighting a provenance
  // cone from a value nothing consumes would be actively misleading.
  "zero-fill@1",
  // partial — synthesizes bytes
  "pad-with-byte@1",
  "append-be64-length@1",
  // partial — SP 800-185 encodings prepend a synthesized length prefix (and
  // bytepad appends zero padding); the input bytes are copied but the prefix has
  // no input source, so no clean per-cell mapping.
  "encode-string@1",
  "bytepad@1",
  // exact-but-plumbing — identity bridge, deferred
  "state-to-bytes@1",
  "bytes-to-state@1",
  "aux-load-bytes@1",
]);
