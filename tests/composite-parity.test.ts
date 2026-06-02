/**
 * Compose-and-save parity gate (universal-port Phase 4f, Slice E) — the
 * correctness oracle.
 *
 * Capturing a group as a composite and cloning it back MUST preserve the
 * computation byte-for-byte. We prove it the strongest way available: splice a
 * captured+cloned AES round back into the AES-128 spec (replacing the original
 * round.1, rewiring round.2's seed to the clone) and assert the cipher still
 * produces the FIPS-197 §C.1 ciphertext — rounds 2..10 consume round 1's
 * output, so any divergence in the clone corrupts the known answer. A direct
 * per-leaf frame comparison pins the byte-identity at the round boundary too.
 *
 * This is the analogue of `port-wiring-roundtrip.test.ts` for 4d-bis: the
 * load-bearing assertion the plan promised.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { framePrimaryOutBytes } from "@/core/frame-state";
import { runSpec } from "@/core/runtime";
import {
  captureCompositeFromGroup,
  cloneGroupWithFreshIds,
  collectSpecIds,
  findStepAndParent,
} from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, StepGroup, Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY = "000102030405060708090a0b0c0d0e0f"; // FIPS-197 §A.1
const PT = "00112233445566778899aabbccddeeff";
const FIPS_CT = "69c4e0d86a7b0430d8cdb78070b4c55a"; // FIPS-197 §C.1
const registry = buildDefaultRegistry();

const run = (spec: CipherSpec): Trace =>
  runSpec(spec, registry, {
    initialState: makeBytesState(bytesFromHex(PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]),
  });

const ciphertext = (spec: CipherSpec): string => hexFromBytes(run(spec).finalState.bytes);

const leafOut = (trace: Trace, stepId: string): Uint8Array | null => {
  const f = trace.frames.find((fr) => fr.stepId === stepId);
  return f ? framePrimaryOutBytes(f) : null;
};

/**
 * Build an AES-128 spec with round.1 replaced by a captured+cloned copy
 * (id `r1copy`), wired exactly as the original was: the clone keeps round.1's
 * seed, and round.2 (which seeded from round.1) is repointed at the clone.
 */
const specWithClonedRound1 = (): CipherSpec => {
  const round1 = findStepAndParent(aes128Spec, "round.1");
  if (round1?.node.kind !== "group") throw new Error("test setup: round.1 is not a group");
  const origSeed = round1.node.seedInput;

  const template = captureCompositeFromGroup(aes128Spec, "round.1", "Round Copy");
  const { group: clone } = cloneGroupWithFreshIds(template, "r1copy", collectSpecIds(aes128Spec));
  // Capture clears seedInput (context-free template); restore the original
  // round's seed so the splice is wired identically.
  const cloneSeeded: StepGroup = origSeed !== undefined ? { ...clone, seedInput: origSeed } : clone;

  return {
    ...aes128Spec,
    steps: aes128Spec.steps.map((n) => {
      if (n.id === "round.1") return cloneSeeded;
      // round.2 seeded from round.1 — repoint it at the clone's published exit.
      if (n.kind === "group" && n.seedInput?.node === "round.1") {
        return { ...n, seedInput: { node: "r1copy", port: n.seedInput.port } };
      }
      return n;
    }),
  };
};

describe("compose-and-save parity", () => {
  it("sanity: canonical AES-128 produces the FIPS-197 ciphertext", () => {
    expect(ciphertext(aes128Spec)).toBe(FIPS_CT);
  });

  it("a captured+cloned round, spliced back in, reproduces the FIPS-197 ciphertext", () => {
    expect(ciphertext(specWithClonedRound1())).toBe(FIPS_CT);
  });

  it("every cloned round-1 leaf is byte-identical to the original round's frame", () => {
    const canonical = run(aes128Spec);
    const withClone = run(specWithClonedRound1());
    for (const leaf of ["sub-bytes", "shift-rows", "mix-columns", "add-round-key"]) {
      const orig = leafOut(canonical, `round.1.${leaf}`);
      const cloned = leafOut(withClone, `r1copy.${leaf}`);
      expect(orig, `original round.1.${leaf} frame should exist`).not.toBeNull();
      expect(cloned, `cloned r1copy.${leaf} frame should exist`).not.toBeNull();
      expect(hexFromBytes(cloned as Uint8Array)).toBe(hexFromBytes(orig as Uint8Array));
    }
  });
});
