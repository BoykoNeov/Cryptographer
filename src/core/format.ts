/**
 * Byte format-aware rendering and parsing. The cryptographer is a learning
 * tool, and "what does this byte look like" is a useful axis — beginners
 * find decimal more intuitive than hex, ASCII makes structural patterns
 * (English words, repeating-key XOR ghosts) jump out.
 *
 * Three formats, each round-trips through `formatBytes` ↔ `parseBytes`:
 *
 *   hex     — 2 hex chars per byte, no separators. "0041ff" = [0x00, 0x41, 0xff]
 *   decimal — base-10 tokens, space- or comma-separated. "0 65 255" = same bytes
 *   ascii   — printable chars literal, everything else as `\xNN`. "A" = 0x41
 *
 * Why a dedicated module (not just extending `state/bytes.ts`): the
 * parsers grew non-trivial enough that they deserve their own home; bytes
 * stays focused on the underlying Uint8Array conversion. Pure functions
 * only — no Solid signals, no DOM.
 */

import { bytesFromHex } from "./state/bytes";

export type ByteFormat = "hex" | "decimal" | "ascii";

export const ALL_BYTE_FORMATS: readonly ByteFormat[] = ["hex", "decimal", "ascii"];

/**
 * Max characters needed to display a single byte in this format. Used by
 * cell-input widgets to size their input boxes (hex=2, decimal=3, ascii=4).
 */
export const byteDisplayWidth = (fmt: ByteFormat): number => {
  switch (fmt) {
    case "hex":
      return 2;
    case "decimal":
      return 3;
    case "ascii":
      return 4;
  }
};

/**
 * Render a single byte. ASCII renders printable bytes as the literal
 * character, with two exceptions:
 *   - Backslash (0x5c) → \x5c (otherwise it would collide with our escape
 *     syntax and `\x` could be ambiguous when followed by 1–2 hex chars).
 *   - Non-printable (< 0x20 or > 0x7e) → \xNN.
 * Space (0x20) is treated as printable; users typing "Hello world" expect
 * to see a space, not an escape.
 */
export const formatByte = (b: number, fmt: ByteFormat): string => {
  if (!Number.isInteger(b) || b < 0 || b > 0xff) {
    throw new Error(`byte out of range (0..255): ${b}`);
  }
  switch (fmt) {
    case "hex":
      return b.toString(16).padStart(2, "0");
    case "decimal":
      return b.toString(10);
    case "ascii":
      if (b >= 0x20 && b <= 0x7e && b !== 0x5c) {
        return String.fromCharCode(b);
      }
      return `\\x${b.toString(16).padStart(2, "0")}`;
  }
};

/**
 * Parse a single byte. Returns null on any failure — callers (cell inputs)
 * use null to mean "revert to the upstream value." Throwing here would
 * make the per-cell editor noisier than it needs to be.
 */
export const parseByte = (s: string, fmt: ByteFormat): number | null => {
  const trimmed = s.trim();
  if (trimmed.length === 0) return null;
  switch (fmt) {
    case "hex": {
      if (!/^[0-9a-fA-F]{1,2}$/.test(trimmed)) return null;
      return Number.parseInt(trimmed, 16);
    }
    case "decimal": {
      if (!/^\d{1,3}$/.test(trimmed)) return null;
      const n = Number.parseInt(trimmed, 10);
      return n >= 0 && n <= 255 ? n : null;
    }
    case "ascii": {
      if (trimmed.length === 1) {
        const code = trimmed.charCodeAt(0);
        return code <= 0xff ? code : null;
      }
      const m = /^\\x([0-9a-fA-F]{2})$/.exec(trimmed);
      return m ? Number.parseInt(m[1] ?? "", 16) : null;
    }
  }
};

/**
 * Render a sequence of bytes. Hex/ASCII concatenate without separators;
 * decimal joins on a single space because "017034" would be unreadable.
 */
export const formatBytes = (bytes: Uint8Array, fmt: ByteFormat): string => {
  const parts = new Array<string>(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    parts[i] = formatByte(bytes[i] ?? 0, fmt);
  }
  return parts.join(fmt === "decimal" ? " " : "");
};

/**
 * Parse a byte sequence. Returns whatever the input contains — no length
 * check. Use `parseBytesWithLength` when you want the friendly "expected
 * N, got M" error.
 *
 * Throws on a *structural* parse failure (invalid hex char, decimal > 255,
 * malformed escape). Returns an empty array for empty input.
 */
export const parseBytes = (input: string, fmt: ByteFormat): Uint8Array => {
  switch (fmt) {
    case "hex": {
      const clean = input.replace(/\s+/g, "");
      if (clean.length === 0) return new Uint8Array(0);
      return bytesFromHex(clean);
    }
    case "decimal": {
      const tokens = input
        .trim()
        .split(/[\s,]+/)
        .filter((t) => t.length > 0);
      if (tokens.length === 0) return new Uint8Array(0);
      const out = new Uint8Array(tokens.length);
      for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i] ?? "";
        if (!/^\d{1,3}$/.test(tok)) {
          throw new Error(`invalid decimal token at position ${i}: "${tok}"`);
        }
        const n = Number.parseInt(tok, 10);
        if (n > 255) {
          throw new Error(`decimal value out of range (0..255) at position ${i}: ${n}`);
        }
        out[i] = n;
      }
      return out;
    }
    case "ascii": {
      const out: number[] = [];
      let i = 0;
      while (i < input.length) {
        // \xNN escape: 4 chars total, captures 1 byte.
        if (input[i] === "\\" && input[i + 1] === "x") {
          const hex = input.slice(i + 2, i + 4);
          if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
            throw new Error(`invalid \\x escape at offset ${i}`);
          }
          out.push(Number.parseInt(hex, 16));
          i += 4;
          continue;
        }
        // Anything else is a literal char. JS strings are UTF-16; we only
        // accept code points that fit in a byte. A literal "é" (0xe9) is
        // fine; "😀" (a surrogate pair) is not.
        const code = input.charCodeAt(i);
        if (code > 0xff) {
          throw new Error(`non-byte char at offset ${i}: U+${code.toString(16).padStart(4, "0")}`);
        }
        out.push(code);
        i += 1;
      }
      return new Uint8Array(out);
    }
  }
};

/**
 * Parse + enforce a specific byte length. The error message names the
 * format so the user knows what they typed wrong: hex chars, decimal
 * tokens, or chars+escapes. Used by the App-level Run handler.
 */
export const parseBytesWithLength = (
  input: string,
  fmt: ByteFormat,
  expectedLen: number,
): Uint8Array => {
  const bytes = parseBytes(input, fmt);
  if (bytes.length !== expectedLen) {
    throw new Error(
      `expected ${expectedLen} bytes (${formatLengthHint(fmt, expectedLen)}), got ${bytes.length}`,
    );
  }
  return bytes;
};

const formatLengthHint = (fmt: ByteFormat, expectedLen: number): string => {
  switch (fmt) {
    case "hex":
      return `${expectedLen * 2} hex chars`;
    case "decimal":
      return `${expectedLen} decimal tokens`;
    case "ascii":
      return `${expectedLen} chars+escapes`;
  }
};
