import type { BytesState } from "../types";

export const makeBytesState = (bytes: Uint8Array): BytesState => ({
  shape: "bytes",
  bytes: new Uint8Array(bytes),
});

export const cloneBytes = (s: BytesState): BytesState => ({
  shape: "bytes",
  bytes: new Uint8Array(s.bytes),
});

export const bytesFromHex = (hex: string): Uint8Array => {
  const clean = hex.replace(/\s+/g, "");
  if (clean.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
};

export const hexFromBytes = (bytes: Uint8Array): string => {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    s += b.toString(16).padStart(2, "0");
  }
  return s;
};
