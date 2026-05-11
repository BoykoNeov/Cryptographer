/**
 * Phase 3 — byte format core. Tests the formatters/parsers in isolation
 * from any UI, so the contract is provable without needing a DOM.
 *
 * Three formats: hex, decimal, ASCII. Each must round-trip
 * (parseBytes(formatBytes(x)) deep-equals x) and produce friendly errors
 * on malformed input.
 */

import {
  ALL_BYTE_FORMATS,
  type ByteFormat,
  byteDisplayWidth,
  formatByte,
  formatBytes,
  parseByte,
  parseBytes,
  parseBytesWithLength,
} from "@/core/format";
import { describe, expect, it } from "vitest";

const range256 = Array.from({ length: 256 }, (_, i) => i);
const ALL_BYTES_VALUE = new Uint8Array(range256);

describe("format — single byte", () => {
  describe("formatByte", () => {
    it("renders hex as two lowercase chars with leading zero", () => {
      expect(formatByte(0x00, "hex")).toBe("00");
      expect(formatByte(0x05, "hex")).toBe("05");
      expect(formatByte(0xff, "hex")).toBe("ff");
    });

    it("renders decimal without padding", () => {
      expect(formatByte(0, "decimal")).toBe("0");
      expect(formatByte(7, "decimal")).toBe("7");
      expect(formatByte(255, "decimal")).toBe("255");
    });

    it("renders printable ASCII as the literal char", () => {
      expect(formatByte(0x41, "ascii")).toBe("A");
      expect(formatByte(0x7e, "ascii")).toBe("~");
      expect(formatByte(0x20, "ascii")).toBe(" "); // space is printable
    });

    it("escapes backslash specifically (would collide with our escape syntax)", () => {
      expect(formatByte(0x5c, "ascii")).toBe("\\x5c");
    });

    it("escapes non-printable ASCII bytes as \\xNN", () => {
      expect(formatByte(0x00, "ascii")).toBe("\\x00");
      expect(formatByte(0x1f, "ascii")).toBe("\\x1f");
      expect(formatByte(0x7f, "ascii")).toBe("\\x7f");
      expect(formatByte(0xff, "ascii")).toBe("\\xff");
    });

    it("throws on out-of-range input", () => {
      expect(() => formatByte(-1, "hex")).toThrow();
      expect(() => formatByte(256, "hex")).toThrow();
      expect(() => formatByte(1.5, "hex")).toThrow();
    });
  });

  describe("parseByte", () => {
    it("parses hex (1 or 2 digits, both cases)", () => {
      expect(parseByte("0", "hex")).toBe(0);
      expect(parseByte("ff", "hex")).toBe(255);
      expect(parseByte("FF", "hex")).toBe(255);
      expect(parseByte(" 41 ", "hex")).toBe(0x41); // whitespace trimmed
    });

    it("rejects non-hex tokens in hex mode", () => {
      expect(parseByte("zz", "hex")).toBeNull();
      expect(parseByte("100", "hex")).toBeNull(); // > 2 chars
      expect(parseByte("", "hex")).toBeNull();
    });

    it("parses decimal in 0..255", () => {
      expect(parseByte("0", "decimal")).toBe(0);
      expect(parseByte("65", "decimal")).toBe(65);
      expect(parseByte("255", "decimal")).toBe(255);
    });

    it("rejects out-of-range decimal", () => {
      expect(parseByte("256", "decimal")).toBeNull();
      expect(parseByte("-1", "decimal")).toBeNull();
      expect(parseByte("abc", "decimal")).toBeNull();
    });

    it("parses ASCII (literal char or \\xNN escape)", () => {
      expect(parseByte("A", "ascii")).toBe(0x41);
      expect(parseByte("\\x00", "ascii")).toBe(0x00);
      expect(parseByte("\\xFF", "ascii")).toBe(0xff);
    });

    it("rejects malformed ASCII escapes", () => {
      expect(parseByte("\\x", "ascii")).toBeNull();
      expect(parseByte("\\xZZ", "ascii")).toBeNull();
      expect(parseByte("\\x0", "ascii")).toBeNull(); // only 1 hex digit
    });
  });
});

describe("format — byte sequences", () => {
  describe("formatBytes", () => {
    it("hex: concatenates without separators", () => {
      expect(formatBytes(new Uint8Array([0x00, 0x11, 0x22]), "hex")).toBe("001122");
    });

    it("decimal: space-separates tokens", () => {
      expect(formatBytes(new Uint8Array([0, 17, 34]), "decimal")).toBe("0 17 34");
    });

    it("ascii: mixes literal chars and \\xNN escapes", () => {
      // "AB" + two nulls + backslash (escaped).
      expect(formatBytes(new Uint8Array([0x41, 0x42, 0x00, 0x00, 0x5c]), "ascii")).toBe(
        "AB\\x00\\x00\\x5c",
      );
    });

    it("handles empty input", () => {
      expect(formatBytes(new Uint8Array(0), "hex")).toBe("");
      expect(formatBytes(new Uint8Array(0), "decimal")).toBe("");
      expect(formatBytes(new Uint8Array(0), "ascii")).toBe("");
    });
  });

  describe("parseBytes — hex", () => {
    it("parses a 32-char hex string into 16 bytes", () => {
      const out = parseBytes("00112233445566778899aabbccddeeff", "hex");
      expect(Array.from(out)).toEqual([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
      ]);
    });

    it("strips internal whitespace", () => {
      expect(Array.from(parseBytes("00 11  22", "hex"))).toEqual([0x00, 0x11, 0x22]);
    });

    it("rejects odd-length input", () => {
      expect(() => parseBytes("abc", "hex")).toThrow();
    });
  });

  describe("parseBytes — decimal", () => {
    it("accepts space-separated tokens", () => {
      expect(Array.from(parseBytes("0 17 34 255", "decimal"))).toEqual([0, 17, 34, 255]);
    });

    it("accepts comma-separated tokens", () => {
      expect(Array.from(parseBytes("0,17,34,255", "decimal"))).toEqual([0, 17, 34, 255]);
    });

    it("accepts mixed comma+space separators", () => {
      expect(Array.from(parseBytes("0, 17,  34 ,255", "decimal"))).toEqual([0, 17, 34, 255]);
    });

    it("rejects out-of-range values with a position-aware error", () => {
      expect(() => parseBytes("0 256 0", "decimal")).toThrow(/out of range.*position 1/);
    });

    it("rejects non-numeric tokens", () => {
      expect(() => parseBytes("0 abc 0", "decimal")).toThrow(/invalid decimal token/);
    });
  });

  describe("parseBytes — ascii", () => {
    it("parses literal chars as their byte codes", () => {
      expect(Array.from(parseBytes("ABC", "ascii"))).toEqual([0x41, 0x42, 0x43]);
    });

    it("parses \\xNN escapes", () => {
      expect(Array.from(parseBytes("\\x00\\xff", "ascii"))).toEqual([0x00, 0xff]);
    });

    it("mixes literal chars and escapes; counts bytes after escape expansion", () => {
      // "AB" (2 bytes) + 12 null bytes (12 escapes) + "x" (1 byte) + "y" = 16 bytes
      const text = `AB${"\\x00".repeat(12)}xy`;
      const bytes = parseBytes(text, "ascii");
      expect(bytes.length).toBe(16);
      expect(bytes[0]).toBe(0x41);
      expect(bytes[14]).toBe(0x78);
      expect(bytes[15]).toBe(0x79);
    });

    it("treats a bare backslash without 'x' as a literal byte", () => {
      // "\\n" → backslash (0x5c) + n (0x6e). NOT interpreted as a newline.
      expect(Array.from(parseBytes("\\n", "ascii"))).toEqual([0x5c, 0x6e]);
    });

    it("rejects malformed escapes (non-hex after \\x)", () => {
      expect(() => parseBytes("\\xZZ", "ascii")).toThrow(/invalid \\x escape/);
    });

    it("rejects non-byte characters (above 0xff)", () => {
      expect(() => parseBytes("éĀ", "ascii")).toThrow(/non-byte char/);
    });
  });

  describe("round-trip across all formats", () => {
    for (const fmt of ALL_BYTE_FORMATS) {
      it(`every byte 0..255 round-trips through ${fmt}`, () => {
        const rendered = formatBytes(ALL_BYTES_VALUE, fmt);
        const reparsed = parseBytes(rendered, fmt);
        expect(Array.from(reparsed)).toEqual(range256);
      });
    }

    it("cross-format conversion: hex → decimal → ascii → hex preserves bytes", () => {
      // The in-place format switch logic in App.tsx relies on this. If any
      // intermediate format loses info, the switch would clobber the user's
      // data — test it explicitly.
      const startHex = "00112233445566778899aabbccddeeff";
      const bytes1 = parseBytes(startHex, "hex");
      const decimal = formatBytes(bytes1, "decimal");
      const bytes2 = parseBytes(decimal, "decimal");
      const ascii = formatBytes(bytes2, "ascii");
      const bytes3 = parseBytes(ascii, "ascii");
      const endHex = formatBytes(bytes3, "hex");
      expect(endHex).toBe(startHex);
    });
  });
});

describe("parseBytesWithLength", () => {
  it("returns parsed bytes when length matches", () => {
    const bytes = parseBytesWithLength("0011", "hex", 2);
    expect(Array.from(bytes)).toEqual([0x00, 0x11]);
  });

  it("error message names the format-specific length hint (hex)", () => {
    expect(() => parseBytesWithLength("0011", "hex", 16)).toThrow(/32 hex chars.*got 2/);
  });

  it("error message names the format-specific length hint (decimal)", () => {
    expect(() => parseBytesWithLength("1 2 3", "decimal", 16)).toThrow(/16 decimal tokens.*got 3/);
  });

  it("error message names the format-specific length hint (ascii)", () => {
    expect(() => parseBytesWithLength("AB", "ascii", 16)).toThrow(/16 chars\+escapes.*got 2/);
  });
});

describe("byteDisplayWidth", () => {
  it("returns 2/3/4 for hex/decimal/ascii", () => {
    expect(byteDisplayWidth("hex")).toBe(2);
    expect(byteDisplayWidth("decimal")).toBe(3);
    expect(byteDisplayWidth("ascii")).toBe(4);
  });

  it("covers every format in ALL_BYTE_FORMATS", () => {
    for (const fmt of ALL_BYTE_FORMATS) {
      expect(byteDisplayWidth(fmt as ByteFormat)).toBeGreaterThan(0);
    }
  });
});
