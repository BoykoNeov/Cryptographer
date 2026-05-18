/**
 * Boundary narrators — Phase 3 of the per-frame value-prose plan.
 *
 * Five step types that bridge between BytesState (the padding chain shape)
 * and MatrixState (the AES round-body shape), or that count blocks for the
 * iterate loop:
 *
 *   - `generic.load-block@1`         → BytesState → MatrixState. 1 unit
 *                                       explaining the column-major packing.
 *   - `generic.store-block@1`        → MatrixState → BytesState (inverse).
 *   - `generic.split-blocks@1`       → BytesState passthrough; writes
 *                                       MatrixState[] into aux. 1 unit reading
 *                                       block count from `frame.auxWritten`.
 *   - `generic.concat-blocks@1`      → MatrixState passthrough; reads
 *                                       MatrixState[] from aux. 1 unit.
 *   - `generic.compute-block-count@1` → BytesState passthrough; writes the
 *                                       integer count into aux. 1 unit.
 *
 * Each emits exactly ONE conceptual unit because the operation is one
 * algorithmic beat (pack a block, split into N blocks, count blocks). The
 * per-byte detail is visible in the MatrixView / BytesView the same frame
 * renders alongside the narration.
 */

import type { BytesState, Json, MatrixState, TraceFrame } from "@/core/types";
import type { NarrationFn } from "./registry";

// ─── load-block ──────────────────────────────────────────────────────

/**
 * Reads BytesState (16 bytes), produces MatrixState (4×4 column-major).
 * No aux. The narrator just explains the column-major packing once —
 * a useful pedagogical beat the first time a learner sees the AES state
 * shape materialize.
 */
export const loadBlockNarration: NarrationFn = (frame) => {
  const before = readBytesState(frame.stateBefore);
  if (!before) return null;
  const len = before.length;
  return [
    {
      key: "pack",
      label: `pack ${len}-byte sequence into 4×4 column-major matrix`,
      Prose: () => (
        <div>
          <p>
            AES operates on a 4×4 byte matrix in <strong>column-major order</strong> (FIPS-197
            §3.4): the byte at row r, column c lives at flat index r + 4·c. Bytes 0..3 fill column 0
            (top to bottom), bytes 4..7 fill column 1, and so on.
          </p>
          <p>
            This step is the bridge between the variable-length padding chain (BytesState) and the
            fixed-shape round function (MatrixState). The underlying buffer is unchanged — the same
            16 bytes — only the <em>shape label</em> flips from <code>bytes</code> to{" "}
            <code>matrix4x4-bytes</code>.
          </p>
        </div>
      ),
    },
  ];
};

// ─── store-block ─────────────────────────────────────────────────────

/**
 * Inverse of load-block. Reads MatrixState, produces BytesState of same
 * length (16). Same bytes, different shape label.
 */
export const storeBlockNarration: NarrationFn = (frame) => {
  const before = readMatrixState(frame.stateBefore);
  if (!before) return null;
  return [
    {
      key: "unpack",
      label: "unpack 4×4 matrix back into 16-byte sequence",
      Prose: () => (
        <div>
          <p>
            The inverse of <code>load-block</code>: flatten the AES 4×4 column-major matrix back
            into a 16-byte sequence. Since the matrix is stored column-major internally, this is a
            structural relabel (<code>matrix4x4-bytes</code> → <code>bytes</code>) — the byte values
            and order are identical on both sides.
          </p>
          <p>
            Sits between the AES round function and the unpad chain on the decrypt path: AES
            finishes in <code>matrix4x4-bytes</code>; <code>pkcs7-unpad</code> / friends consume{" "}
            <code>bytes</code>.
          </p>
        </div>
      ),
    },
  ];
};

// ─── split-blocks ────────────────────────────────────────────────────

/**
 * Reads BytesState (variable length, clean block multiple), writes
 * MatrixState[] into aux. State is passthrough. The "real" output lives
 * in `frame.auxWritten[outBlocksAux]`.
 *
 * The narrator reads the produced array's length to report the block
 * count concretely. If the aux write is missing (defensive — shouldn't
 * happen for a frame that landed in the trace), return null.
 */
export const splitBlocksNarration: NarrationFn = (frame) => {
  const before = readBytesState(frame.stateBefore);
  if (!before) return null;
  const outBlocksAux = readStringParam(frame.params, "outBlocksAux");
  const blockSize = readBlockSize(frame.params);
  // Look at auxWritten to confirm the array is there and read its length.
  let auxName: string | null = outBlocksAux;
  let blocksLength: number | null = null;
  if (auxName !== null) {
    const v = frame.auxWritten.get(auxName);
    if (Array.isArray(v)) blocksLength = v.length;
  }
  // Fall back to deriving the count from input length when aux is missing
  // (helps the half-wired authoring state stay informative).
  if (blocksLength === null && blockSize !== null && blockSize > 0) {
    blocksLength = before.length / blockSize;
  }
  if (auxName === null) auxName = "<outBlocksAux>";
  const unitLabel =
    blocksLength !== null
      ? `slice into ${blocksLength} block${blocksLength === 1 ? "" : "s"} of ${blockSize ?? "blockSize"} bytes`
      : "slice into per-block matrices";
  return [
    {
      key: "split",
      label: unitLabel,
      Prose: () => (
        <div>
          <p>
            Walk the {before.length}-byte input in {blockSize !== null ? blockSize : "blockSize"}
            -byte chunks. Pack each chunk into a 4×4 column-major matrix (same shape as{" "}
            <code>load-block</code>). The resulting array of{" "}
            {blocksLength !== null ? blocksLength : "K"} MatrixState
            {blocksLength === 1 ? "" : "s"} is written into <code>aux[{auxName}]</code> for the
            <code> iterate</code> loop to consume.
          </p>
          <p>
            State itself stays as the original BytesState — downstream non-iterating steps (e.g.{" "}
            <code>compute-block-count</code>) can still see the full input. The runtime swaps state
            to <code>blocks[i]</code> only inside the iterate node.
          </p>
        </div>
      ),
    },
  ];
};

// ─── concat-blocks ───────────────────────────────────────────────────

/**
 * Reads MatrixState[] from aux, produces a flattened BytesState. The
 * incoming `state` is the LAST iteration's output matrix, but the cipher's
 * actual ciphertext is the concatenation of EVERY iteration's output —
 * read from aux, not state.
 */
export const concatBlocksNarration: NarrationFn = (frame) => {
  const blocksAux = readStringParam(frame.params, "blocksAux");
  let auxName: string | null = blocksAux;
  let blocksLength: number | null = null;
  if (auxName !== null) {
    const v = frame.auxRead.get(auxName);
    if (Array.isArray(v)) blocksLength = v.length;
  }
  if (auxName === null) auxName = "<blocksAux>";
  const after = readBytesState(frame.stateAfter);
  const outLen = after ? after.length : null;
  return [
    {
      key: "concat",
      label:
        blocksLength !== null
          ? `concat ${blocksLength} block${blocksLength === 1 ? "" : "s"} → ${outLen ?? "?"} bytes`
          : "concat per-block matrices into one byte sequence",
      Prose: () => (
        <div>
          <p>
            After the <code>iterate</code> loop finishes,{" "}
            <code>
              aux[
              {auxName}]
            </code>{" "}
            holds the per-iteration outputs as a MatrixState array. This step walks that array,
            flattens each 4×4 matrix back to 16 bytes (column-major, like <code>store-block</code>),
            and concatenates the results into a single BytesState of{" "}
            {blocksLength !== null && outLen !== null
              ? `${blocksLength} × 16 = ${outLen}`
              : "K × 16"}{" "}
            bytes.
          </p>
          <p>
            The incoming <code>state</code> argument is ignored — the runtime leaves it as the LAST
            iteration's matrix after the loop, but the cipher's true output is the FULL
            concatenation read from aux.
          </p>
        </div>
      ),
    },
  ];
};

// ─── compute-block-count ─────────────────────────────────────────────

/**
 * Reads BytesState's length, divides by blockSize, writes the integer
 * count into aux. State passthrough. Trivial arithmetic kept as a separate
 * step so the user sees `blockCount = 2` materialize as its own frame.
 */
export const computeBlockCountNarration: NarrationFn = (frame) => {
  const before = readBytesState(frame.stateBefore);
  if (!before) return null;
  const blockSize = readBlockSize(frame.params);
  const countAux = readStringParam(frame.params, "countAux");
  let count: number | null = null;
  if (countAux !== null) {
    const v = frame.auxWritten.get(countAux);
    if (typeof v === "number") count = v;
  }
  if (count === null && blockSize !== null && blockSize > 0) {
    count = before.length / blockSize;
  }
  const auxKey = countAux ?? "<countAux>";
  return [
    {
      key: "count",
      label: `blockCount = ${count !== null ? count : "?"}`,
      Prose: () => (
        <p>
          {before.length} bytes ÷ {blockSize !== null ? blockSize : "blockSize"} bytes per block ={" "}
          {count !== null ? count : "K"} block{count === 1 ? "" : "s"}. Stash this count under{" "}
          <code>aux[{auxKey}]</code> so the downstream <code>iterate</code> node can read it as its
          loop bound. State is passthrough.
        </p>
      ),
    },
  ];
};

// ─── Helpers ─────────────────────────────────────────────────────────

const readBytesState = (state: TraceFrame["stateBefore"] | null): Uint8Array | null => {
  if (!state) return null;
  if (state.shape !== "bytes") return null;
  return (state as BytesState).bytes;
};

const readMatrixState = (state: TraceFrame["stateBefore"] | null): Uint8Array | null => {
  if (!state) return null;
  if (state.shape !== "matrix4x4-bytes") return null;
  return (state as MatrixState).bytes;
};

const readBlockSize = (params: Json): number | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>).blockSize;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 1) return null;
  return v;
};

const readStringParam = (params: Json, key: string): string | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>)[key];
  return typeof v === "string" && v.length > 0 ? v : null;
};
