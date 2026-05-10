import type { BitVecState } from "../types";

export const makeBitVec = (bits: Uint8Array, bitLength: number): BitVecState => ({
  shape: "bitvec",
  bits: new Uint8Array(bits),
  bitLength,
});

export const cloneBitVec = (s: BitVecState): BitVecState => ({
  shape: "bitvec",
  bits: new Uint8Array(s.bits),
  bitLength: s.bitLength,
});
