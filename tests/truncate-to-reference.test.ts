/**
 * `truncate-to-reference@1` unit tests — the trim CTR's ragged tail rests on.
 *
 * The step is one `subarray`, but two of its properties are load-bearing in
 * ways that hide well:
 *
 *   • it keeps the **prefix**, not the suffix — a trim from the wrong end
 *     still produces the right NUMBER of bytes, still round-trips (both
 *     directions would make the same mistake), and disagrees only with an
 *     external oracle three files away;
 *   • its width comes from `reference`'s **length**, never its bytes — the
 *     property that lets one leaf serve every block size and every message
 *     length without a param.
 *
 * Pinning both here means a failure names the bug instead of surfacing as an
 * unexplained AES-CTR mismatch.
 *
 * References: NIST SP 800-38A §6.5 (CTR mode — the final partial block).
 */

import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import { truncateToReference } from "@/steps/truncate-to-reference";
import { describe, expect, it } from "vitest";

/** Run the executor over hex input/reference, return the hex output. */
const trim = (inputHex: string, referenceHex: string): string => {
  const out = truncateToReference(
    new Map([
      ["input", bytesFromHex(inputHex)],
      ["reference", bytesFromHex(referenceHex)],
    ]),
    {},
    undefined as never,
  );
  const bytes = out.get("output");
  if (bytes === undefined) throw new Error("truncate-to-reference produced no 'output' port");
  return hexFromBytes(bytes);
};

describe("truncate-to-reference@1 — CTR's ragged-tail trim", () => {
  it("keeps the FIRST n bytes, where n is the reference's length", () => {
    // The prefix, not the suffix. Keeping the wrong end would produce the same
    // byte count and pass a round-trip; only this (and node:crypto) catches it.
    expect(trim("a1b2c3d4e5f60718", "00000000")).toBe("a1b2c3d4");
  });

  it("is an exact passthrough when the widths already match", () => {
    // Every block but a final short one takes this path, so it is the common
    // case, not an edge case.
    expect(trim("a1b2c3d4", "ffffffff")).toBe("a1b2c3d4");
  });

  it("reads only the reference's LENGTH, never its bytes", () => {
    // The property that makes the step width-free. Two references with wildly
    // different contents but the same length must give identical results.
    expect(trim("a1b2c3d4e5f60718", "00000000")).toBe(trim("a1b2c3d4e5f60718", "deadbeef"));
  });

  it("trims to a single byte (the shortest ragged tail)", () => {
    // L % B === 1 — the narrowest final block CTR can produce.
    expect(trim("a1b2c3d4e5f60718", "00")).toBe("a1");
  });

  it("trims a 16-byte AES keystream to every width from 1 to 15", () => {
    // The block-size-generic sweep in miniature: one step, every raggedness
    // class an AES-sized block can have.
    const keystream = "000102030405060708090a0b0c0d0e0f";
    for (let n = 1; n <= 15; n++) {
      expect(trim(keystream, "aa".repeat(n)), `n=${n}`).toBe(keystream.slice(0, n * 2));
    }
  });

  it("rejects a reference WIDER than the input rather than inventing bytes", () => {
    // Fires when a spec wires the two ports backwards. Naming both widths
    // turns a baffling downstream length mismatch into a located bug.
    expect(() => trim("a1b2", "0000000000")).toThrow(/wider than 'input'/);
  });

  it("rejects each missing port by name so the editor can flag the unwired arrow", () => {
    expect(() =>
      truncateToReference(new Map([["reference", bytesFromHex("00")]]), {}, undefined as never),
    ).toThrow(/missing required input port 'input'/);
    expect(() =>
      truncateToReference(new Map([["input", bytesFromHex("00")]]), {}, undefined as never),
    ).toThrow(/missing required input port 'reference'/);
  });

  it("produces a freshly-owned buffer, not a view onto the input", () => {
    // The runtime treats outputs as owned arrays, and the trace has already
    // snapshotted the keystream block — a `subarray` view would alias it.
    const input = bytesFromHex("a1b2c3d4");
    const out = truncateToReference(
      new Map([
        ["input", input],
        ["reference", bytesFromHex("0000")],
      ]),
      {},
      undefined as never,
    );
    const bytes = out.get("output");
    if (bytes === undefined) throw new Error("no output");
    bytes[0] = 0xff;
    expect(hexFromBytes(input)).toBe("a1b2c3d4");
  });

  it("accepts a zero-length reference (a degenerate but total case)", () => {
    // Not reachable through CTR (the App bounds input at ≥1 byte, and a whole
    // multiple never leaves a zero-width tail), but the step is total rather
    // than throwing on a case its arithmetic handles fine.
    expect(trim("a1b2c3d4", "")).toBe("");
  });
});
