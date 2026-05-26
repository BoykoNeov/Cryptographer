import type { BitVecState } from "../types";

// `makeBitVec` factory removed 2026-05-26 (S2(g) audit, sha-256-density-polish
// plan): zero consumers in src/ or tests/. `cloneBitVec` stays — it's the
// per-shape branch the universal `cloneState` switch dispatches into when the
// runtime mutates a bitvec frame, and removing it would require removing the
// `BitVecState` variant from the `State` union (a coordinated Phase 5
// deprecation that needs document-schema migration). The full audit lives in
// `docs/plans/sha-256-density-polish.md` under "Slice S2(g)".

export const cloneBitVec = (s: BitVecState): BitVecState => ({
  shape: "bitvec",
  bits: new Uint8Array(s.bits),
  bitLength: s.bitLength,
});
