/**
 * Convert a byte-typed aux value into a MatrixState-typed aux value.
 *
 * The bridge between "an IV is just 16 bytes the user typed in" (delivered
 * by the App as a `Uint8Array` under `aux["iv"]`) and "the chaining loop
 * wants to XOR matrices together" (the runtime's per-iter state is a
 * `MatrixState`). One step early in any chaining spec — CBC, OFB, CFB —
 * runs once before the iterate loop and produces a matrix-shaped aux entry
 * that the in-loop `xor-aux-into-state` consumes.
 *
 * State is passthrough; the real output lives in `aux[outAuxName]`. The
 * existing IV bytes under `aux[ivAuxName]` are NOT erased, so a later
 * frame can still display the original IV alongside the running chain.
 *
 * Why a dedicated bridge step (vs. having the App seed the matrix shape
 * directly): pedagogy. The trace shows ONE frame where `Uint8Array (16
 * bytes)` becomes `MatrixState 4×4`, with `auxRead[iv]` and `auxWritten[
 * chain]` visible in the inspector — students see "an IV is just another
 * byte sequence packed into the AES state shape," which removes the
 * mystery from where a chain value comes from.
 *
 * AES-shaped (16 bytes → 4×4). A future block cipher with different
 * geometry would need a sibling step that produces its native state shape.
 */

import { matrixFromBytes } from "../core/state/matrix";
import type {
  AuxValue,
  Json,
  PortContract,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";

export const ivLoad: StepExecutor = (state, params, ctx) => {
  const { ivAuxName, outAuxName } = readParams(params);

  // Declare the read regardless of presence so the runtime records misses
  // in `frame.auxReadMissing` — Slice 9's validateGraph surfaces an
  // orphan-read warning glyph on a half-wired iv-load node.
  const auxReads: readonly string[] = [ivAuxName];

  const ivValue = ivAuxName === "" ? undefined : ctx.aux.get(ivAuxName);

  // Missing-key path: passthrough, no write. Authoring-time state — the
  // user dropped iv-load on the canvas but hasn't connected an IV yet.
  if (ivValue === undefined) {
    return { state, auxReads };
  }

  // Structural validation. iv-load is a SHAPE bridge — it has a precise
  // input contract (Uint8Array of length 16). Anything else is a bug, not
  // a wiring choice, so throw.
  if (!(ivValue instanceof Uint8Array)) {
    throw new Error(
      `iv-load: aux["${ivAuxName}"] must be a Uint8Array, got ${describeValue(ivValue)}`,
    );
  }
  if (ivValue.length !== 16) {
    throw new Error(`iv-load: aux["${ivAuxName}"] must be 16 bytes, got ${ivValue.length}`);
  }

  // `matrixFromBytes` already allocates fresh storage — no risk of aux[
  // outAuxName] aliasing the source IV bytes.
  const matrix = matrixFromBytes(ivValue);

  if (outAuxName === "") {
    // Wired-on-read-side-only. The read was successful (no orphan), but
    // there's nowhere to write. Return passthrough.
    return { state, auxReads };
  }

  const auxWrites = new Map<string, AuxValue>([[outAuxName, matrix]]);
  return { state, auxReads, auxWrites };
};

export const ivLoadDoc: StepDocumentation = {
  name: "IV Load",
  summary:
    "Read a 16-byte aux value (typically the IV) and republish it under another aux key in MatrixState shape, ready for the chaining XOR.",
  detail: `## IV Load

The bridge between byte-typed aux entries (a Uint8Array — what the App
seeds when the user types an IV) and matrix-typed aux entries (what
in-loop chaining steps such as \`xor-aux-into-state\` need).

\`\`\`
state                       → state (passthrough)
aux[ivAuxName] : Uint8Array → aux[outAuxName] := MatrixState(bytes)
\`\`\`

The original byte-typed entry is preserved — students can still see the
literal IV later in the trace, separate from the running chain that
will overwrite \`aux[outAuxName]\` block-by-block.

**Where it lives in a spec.** Once, before the per-block iterate loop:

\`\`\`
key-expansion
split-blocks                   (BytesState → MatrixState[] in aux)
compute-block-count
iv-load   ivAuxName=iv outAuxName=chain     ← here
iterate { … per-block AES body uses aux[chain] … }
concat-blocks
\`\`\`

**AES-shaped today.** Only 16-byte inputs are supported because the
output is the AES 4×4 column-major matrix. A future block cipher with a
different state geometry would register its own bridge step.

**Graceful when wires aren't connected yet.** If \`aux[ivAuxName]\` is
not present at run time the step is a passthrough; the visual editor
flags the missing read with an orange \`!\` glyph.`,
  params: new Map([
    [
      "ivAuxName",
      "Aux key to read. Must reference a Uint8Array of exactly 16 bytes. Typically `iv` (the App seeds the IV under this key when CBC is active).",
    ],
    [
      "outAuxName",
      "Aux key to write the resulting MatrixState under. Typically `chain` for CBC — the running feedback that the per-block XOR mutates.",
    ],
  ]),
  references: [
    "FIPS-197 §3.4 (State)",
    "NIST SP 800-38A §6.2 (CBC), §6.3 (CFB), §6.4 (OFB), §6.5 (CTR)",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.2) ───────────────
// `ivLoadMeta`: aux-only step (no state ports). Reads a 16-byte Uint8Array
// IV under `aux[ivAuxName]`; writes a `MatrixState` (16 bytes column-
// major) under `aux[outAuxName]`. The MatrixState shape on the write
// side is the load-bearing detail — downstream `xor-aux-into-state@1`
// validates `operand.shape === "matrix4x4-bytes"`.
//
// **Decode layout:** the runtime reconstructs the aux value's shape from
// the PortContract's output-port `layout` tag. `"matrix-cm-4x4"` → a
// `MatrixState` is rebuilt; raw bytes alone would be a Uint8Array and
// `xor-aux-into-state` would throw on the shape mismatch. See
// `auxPortBytesToValue` in `core/port-projection.ts`.
//
// Iteration order: legacy declares `auxReads: [ivAuxName]`, so the read-
// binding Map matches. Empty `ivAuxName` still emits the binding so
// `auxReadMissing: [""]` materializes identically on both paths for the
// fresh-palette-drop case.

export const ivLoadMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  auxReadPorts: (params: Json) => {
    const { ivAuxName } = readParams(params);
    return new Map([["iv", ivAuxName]]);
  },
  auxWritePorts: (params: Json) => {
    const { outAuxName } = readParams(params);
    if (outAuxName === "") return new Map();
    return new Map([["chain", outAuxName]]);
  },
};

/**
 * Declared port surface. `chain` is `matrix-cm-4x4` because the
 * downstream consumer (`xor-aux-into-state`) expects MatrixState shape;
 * the runtime uses this tag at decode time to rebuild the variant.
 * `byteLength: 16` is the fixed AES block size — iv-load is AES-shaped.
 */
export const ivLoadPortContract: PortContract = {
  inputs: new Map([["iv", { byteLength: 16, layout: "raw" }]]),
  outputs: new Map([["chain", { byteLength: 16, layout: "matrix-cm-4x4" }]]),
};

const readParams = (params: Json): { ivAuxName: string; outAuxName: string } => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("iv-load: params must be an object");
  }
  const p = params as { ivAuxName?: unknown; outAuxName?: unknown };
  if (p.ivAuxName !== undefined && typeof p.ivAuxName !== "string") {
    throw new Error("iv-load: ivAuxName must be a string");
  }
  if (p.outAuxName !== undefined && typeof p.outAuxName !== "string") {
    throw new Error("iv-load: outAuxName must be a string");
  }
  return {
    ivAuxName: (p.ivAuxName as string | undefined) ?? "",
    outAuxName: (p.outAuxName as string | undefined) ?? "",
  };
};

// Mirror of the helper in aux-xor.ts. Kept tiny rather than imported so a
// future executor that reformats this slightly doesn't have to touch a
// shared module.
const describeValue = (v: unknown): string => {
  if (v === null || v === undefined) return String(v);
  if (typeof v === "number") return `number (${v})`;
  if (typeof v === "bigint") return "bigint";
  if (Array.isArray(v)) return `State[] (length ${v.length})`;
  if (typeof v === "object" && v !== null && "shape" in v) {
    return `State<${(v as { shape: string }).shape}>`;
  }
  return typeof v;
};
