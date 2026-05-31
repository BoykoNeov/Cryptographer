/**
 * Padding narrators — Phase 3 of the per-frame value-prose plan.
 *
 * Six narrators, one per padding step:
 *
 *   - `generic.pkcs7-pad@1`        → "Input was L bytes; append N copies of 0xNN to reach K."
 *   - `generic.pkcs7-unpad@1`      → "Last byte is 0xNN (= N); strip N trailing bytes."
 *   - `generic.zero-pad@1`         → "Input was L bytes; append N copies of 0x00 to reach K."
 *                                     Special-cases the N=0 (already aligned) no-op.
 *   - `generic.zero-unpad@1`       → "Stripped N trailing 0x00 bytes (lossy: original
 *                                     trailing zeros are eaten too)."
 *   - `generic.iso7816-4-pad@1`    → "Input was L bytes; append 0x80 sentinel + (N-1)
 *                                     zeros to reach K."
 *   - `generic.iso7816-4-unpad@1`  → "Found 0x80 sentinel at offset M; strip everything
 *                                     from offset M onward."
 *
 * State shape: every padding step operates on bytes and produces bytes of
 * (typically) different length. Each padding step is hybrid-ported with a
 * `"state"` port, so the narrator reads the input / output bytes via the
 * shared `framePrimaryInBytes` / `framePrimaryOutBytes` helpers (port-first,
 * Slice 5.3c) — these lengths are NOT equal across the transition, unlike
 * the AES round body where they always are.
 *
 * Each narrator emits ONE conceptual unit (the padding decision) rather
 * than one unit per padding byte. The pedagogical beat is the algorithm
 * choice (pad length N comes from a specific formula), not the per-byte
 * fill — which is the same byte repeated and visible in the `<ByteRow>`
 * cells of the after-state's view anyway.
 */

import { framePrimaryInBytes, framePrimaryOutBytes } from "@/core/frame-state";
import type { Json } from "@/core/types";
import { formatByteInline } from "../components/byte-row";
import type { NarrationFn } from "./registry";

// ─── PKCS#7 pad ──────────────────────────────────────────────────────

/**
 * PKCS#7 pad: appends N bytes of value N where N = blockSize - (L mod blockSize).
 * N is always in [1, blockSize] — pad NEVER produces a no-op (a fully-aligned
 * input gets a full extra block).
 *
 * Reads input length from the `"state"` input port and output length from the
 * `"state"` output port (via `framePrimaryInBytes`/`framePrimaryOutBytes`). The
 * pad-length N is `after.length - before.length` — equivalent to reading the
 * last byte of the output, but cleaner (no off-by-one risk).
 */
export const pkcs7PadNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  if (!before || !after) return null;
  const inputLen = before.length;
  const outputLen = after.length;
  const padLen = outputLen - inputLen;
  if (padLen < 1) return null; // defensive — pkcs7-pad always adds ≥1 byte
  const blockSize = readBlockSize(frame.params);
  return [
    {
      key: "pad",
      label: `pad with ${padLen} byte${padLen === 1 ? "" : "s"} of 0x${padLen.toString(16).padStart(2, "0")}`,
      Prose: (props) => (
        <div>
          <p>
            Input was {inputLen} byte{inputLen === 1 ? "" : "s"}.
            {blockSize !== null
              ? ` Block size is ${blockSize}, so N = ${blockSize} − (${inputLen} mod ${blockSize}) = ${padLen}.`
              : ` Padding length is ${padLen}.`}{" "}
            Append {padLen} cop{padLen === 1 ? "y" : "ies"} of the byte{" "}
            {formatByteInline(padLen, props.fmt)} to reach {outputLen} byte
            {outputLen === 1 ? "" : "s"}.
          </p>
          <p>
            PKCS#7 always adds at least one byte — when the input is already a clean block multiple,
            a full extra block of the byte value <em>blockSize</em> is appended. That property is
            what makes <code>pkcs7-unpad</code> unambiguous: the last byte is always the pad length.
          </p>
        </div>
      ),
    },
  ];
};

// ─── PKCS#7 unpad ────────────────────────────────────────────────────

/**
 * PKCS#7 unpad: reads the trailing byte N, strips N bytes. Inverse of
 * pkcs7-pad. The before-length is always a clean block multiple; the
 * after-length is L - N.
 */
export const pkcs7UnpadNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  if (!before || !after) return null;
  if (before.length === 0) return null;
  const padLen = before.length - after.length;
  if (padLen < 1) return null;
  const trailingByte = before[before.length - 1] ?? 0;
  return [
    {
      key: "unpad",
      label: `strip ${padLen} byte${padLen === 1 ? "" : "s"} of 0x${padLen.toString(16).padStart(2, "0")}`,
      Prose: (props) => (
        <div>
          <p>
            Read the trailing byte: {formatByteInline(trailingByte, props.fmt)} (= {padLen}). PKCS#7
            encodes the pad length in the bytes themselves, so the last byte names how many bytes to
            drop. Strip the trailing {padLen} byte
            {padLen === 1 ? "" : "s"} — they all equal {formatByteInline(padLen, props.fmt)} by
            construction.
          </p>
          <p>
            Result: {after.length} byte{after.length === 1 ? "" : "s"} (down from {before.length}).
            If the trailing bytes did NOT all equal the pad-length value, <code>pkcs7-unpad</code>{" "}
            would have thrown — that's the (very weak) integrity check the scheme provides.
          </p>
        </div>
      ),
    },
  ];
};

// ─── Zero pad ────────────────────────────────────────────────────────

/**
 * Zero pad: appends N bytes of 0x00 where N = (blockSize - L mod blockSize) mod blockSize.
 * Unlike PKCS#7, N CAN be zero — when the input is already block-aligned, no
 * padding is added at all. We special-case that in the prose so users see
 * the difference from PKCS#7's "always at least one byte" guarantee.
 */
export const zeroPadNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  if (!before || !after) return null;
  const inputLen = before.length;
  const outputLen = after.length;
  const padLen = outputLen - inputLen;
  const blockSize = readBlockSize(frame.params);
  return [
    {
      key: "pad",
      label:
        padLen === 0
          ? "no padding — already aligned"
          : `pad with ${padLen} byte${padLen === 1 ? "" : "s"} of 0x00`,
      Prose: () => (
        <div>
          <p>
            Input was {inputLen} byte{inputLen === 1 ? "" : "s"}.
            {blockSize !== null
              ? ` Block size is ${blockSize}, so N = (${blockSize} − ${inputLen} mod ${blockSize}) mod ${blockSize} = ${padLen}.`
              : ` Padding length is ${padLen}.`}{" "}
            {padLen === 0
              ? "Already a clean block multiple — append nothing."
              : `Append ${padLen} cop${padLen === 1 ? "y" : "ies"} of 0x00 to reach ${outputLen} byte${outputLen === 1 ? "" : "s"}.`}
          </p>
          <p>
            Unlike PKCS#7, zero-pad CAN be a no-op (N = 0 when the input is aligned). That makes its
            inverse <code>zero-unpad</code> ambiguous: if the original plaintext ended in 0x00, the
            stripped output is shorter than the original. ISO 7816-4 fixes this by always adding at
            least the 0x80 sentinel.
          </p>
        </div>
      ),
    },
  ];
};

// ─── Zero unpad ──────────────────────────────────────────────────────

/**
 * Zero unpad: walks backward from the end, dropping every 0x00 byte until
 * a non-zero is reached. Lossy by design — any 0x00 bytes in the original
 * plaintext are indistinguishable from padding.
 */
export const zeroUnpadNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  if (!before || !after) return null;
  const stripped = before.length - after.length;
  return [
    {
      key: "unpad",
      label:
        stripped === 0
          ? "no trailing 0x00 — nothing to strip"
          : `strip ${stripped} trailing 0x00 byte${stripped === 1 ? "" : "s"}`,
      Prose: () => (
        <div>
          <p>
            Walk backward from offset {before.length - 1} until a non-zero byte appears, then drop
            every 0x00 byte after it. Stripped {stripped} byte{stripped === 1 ? "" : "s"}; kept{" "}
            {after.length} byte{after.length === 1 ? "" : "s"}.
          </p>
          <p>
            <strong>Lossy.</strong> If the original plaintext ended in 0x00 bytes, those are
            indistinguishable from padding and have been removed too. PKCS#7's pad-length byte
            avoids this; ISO 7816-4's 0x80 sentinel avoids this. Zero-pad accepts the ambiguity in
            exchange for being the simplest scheme to implement.
          </p>
        </div>
      ),
    },
  ];
};

// ─── ISO 7816-4 pad ──────────────────────────────────────────────────

/**
 * ISO 7816-4 pad: appends a 0x80 sentinel followed by (N-1) zeros, where
 * N = blockSize - (L mod blockSize). Always adds at least one byte (the
 * sentinel itself). Inverse-unambiguous without encoding the pad length —
 * the sentinel marks the boundary.
 */
export const iso78164PadNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  if (!before || !after) return null;
  const inputLen = before.length;
  const outputLen = after.length;
  const padLen = outputLen - inputLen;
  if (padLen < 1) return null;
  const blockSize = readBlockSize(frame.params);
  return [
    {
      key: "pad",
      label: `pad with 0x80 sentinel${padLen > 1 ? ` + ${padLen - 1} zero${padLen - 1 === 1 ? "" : "s"}` : ""}`,
      Prose: (props) => (
        <div>
          <p>
            Input was {inputLen} byte{inputLen === 1 ? "" : "s"}.
            {blockSize !== null
              ? ` Block size is ${blockSize}, so N = ${blockSize} − (${inputLen} mod ${blockSize}) = ${padLen}.`
              : ` Padding length is ${padLen}.`}{" "}
            Append the byte {formatByteInline(0x80, props.fmt)} (sentinel), followed by {padLen - 1}{" "}
            zero{padLen - 1 === 1 ? "" : "s"}, to reach {outputLen} byte
            {outputLen === 1 ? "" : "s"}.
          </p>
          <p>
            The 0x80 marker is "one bit set, followed by zeros" at the bit level. Inverse just walks
            past trailing zeros until it hits the 0x80 — no pad-length arithmetic needed, unlike
            PKCS#7. Always adds at least the sentinel, so unpad always has a boundary to find.
          </p>
        </div>
      ),
    },
  ];
};

// ─── ISO 7816-4 unpad ────────────────────────────────────────────────

/**
 * ISO 7816-4 unpad: walks backward past trailing 0x00 bytes until the
 * 0x80 sentinel. Drops the sentinel and everything after.
 */
export const iso78164UnpadNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  if (!before || !after) return null;
  const stripped = before.length - after.length;
  if (stripped < 1) return null;
  const sentinelOffset = after.length;
  return [
    {
      key: "unpad",
      label: `find 0x80 sentinel at offset ${sentinelOffset}; strip ${stripped} byte${stripped === 1 ? "" : "s"}`,
      Prose: (props) => (
        <div>
          <p>
            Walk backward from offset {before.length - 1}, skipping 0x00 bytes, until the{" "}
            {formatByteInline(0x80, props.fmt)} sentinel is found at offset {sentinelOffset}. Drop
            the sentinel and the {stripped - 1} zero{stripped - 1 === 1 ? "" : "s"} after it ({" "}
            {stripped} byte{stripped === 1 ? "" : "s"} total).
          </p>
          <p>
            Result: {after.length} byte{after.length === 1 ? "" : "s"} (down from {before.length}).
            If no 0x80 had been found in the trailing block, <code>iso7816-4-unpad</code> would have
            thrown — the sentinel's absence means the padding was corrupted or the input was never
            ISO 7816-4 padded.
          </p>
        </div>
      ),
    },
  ];
};

// ─── Helpers ─────────────────────────────────────────────────────────

/**
 * Read `params.blockSize` if present. Padding executors require it, but
 * the narrator stays graceful (returns null if absent) so a half-wired
 * frame still gets a prose without the block-size formula spelled out.
 */
const readBlockSize = (params: Json): number | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>).blockSize;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 1) return null;
  return v;
};
