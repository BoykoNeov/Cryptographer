/**
 * DES decrypt tests. Inverse KAT against the same FIPS 46-3 vectors as
 * `des-vectors.test.ts`, plus a random-roundtrip pin.
 *
 * The decrypt spec (`src/ciphers/des-decrypt.ts`) is the same port-native
 * structure as encrypt (B4 — universal-port Phase 4d) with round keys
 * consumed in reverse order (roundKey.15, roundKey.14, …, roundKey.0).
 * Round 16 keeps the no-swap recombine order — the "no swap on last round"
 * exception applies to each direction independently and is what makes the
 * cipher self-inverse under key-reversal.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import type { AuxValue, BytesState, PortBinding, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

type VectorFixture = {
  readonly pt: string;
  readonly key: string;
  readonly ct: string;
};

type Fixture = {
  readonly vectors: readonly VectorFixture[];
};

const FIXTURE_PATH = join(process.cwd(), "tests", "fixtures", "des-kat.json");
const FIXTURE: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as Fixture;

/** Depth-first search for a leaf by id across nested groups. */
const findLeaf = (nodes: readonly StepNode[], id: string): StepNode | undefined => {
  for (const n of nodes) {
    if (n.id === id) return n;
    if (n.kind === "group") {
      const hit = findLeaf(n.children, id);
      if (hit) return hit;
    }
  }
  return undefined;
};

const roundKeyAuxOf = (id: string): string | undefined => {
  const leaf = findLeaf(desDecryptSpec.steps, id);
  if (leaf?.kind !== "step") return undefined;
  return (leaf.params as { roundKeyAux?: string }).roundKeyAux;
};

const recombineInput0 = (id: string): PortBinding | undefined => {
  const leaf = findLeaf(desDecryptSpec.steps, id);
  if (leaf?.kind !== "step") return undefined;
  return leaf.portInputs?.input0;
};

describe("DES decrypt — inverse of encrypt on FIPS test vectors", () => {
  for (const vec of FIXTURE.vectors) {
    it(`CT=${vec.ct} K=${vec.key} → PT=${vec.pt}`, () => {
      const ciphertext: BytesState = { shape: "bytes", bytes: bytesFromHex(vec.ct) };
      const key = bytesFromHex(vec.key);
      const initialAux = new Map<string, AuxValue>([["key", key]]);
      const trace = runSpec(desDecryptSpec, buildDefaultRegistry(), {
        initialState: ciphertext,
        initialAux,
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(vec.pt);
    });
  }
});

describe("DES roundtrip — encrypt then decrypt is the identity", () => {
  it("random 8-byte inputs with random keys", () => {
    // Fixed seeds so the test is deterministic — vary the inputs to
    // exercise different bit patterns but keep CI reproducible.
    const cases = [
      { pt: "0000000000000001", key: "0000000000000001" },
      { pt: "fedcba9876543210", key: "0123456789abcdef" },
      { pt: "deadbeefcafebabe", key: "1234567890abcdef" },
      { pt: "1111222233334444", key: "aaaabbbbccccdddd" },
      { pt: "00ff00ff00ff00ff", key: "0f0f0f0f0f0f0f0f" },
    ];
    const registry = buildDefaultRegistry();
    for (const { pt, key } of cases) {
      const keyBytes = bytesFromHex(key);
      const initialAux = new Map<string, AuxValue>([["key", keyBytes]]);
      // Encrypt
      const encTrace = runSpec(desSpec, registry, {
        initialState: { shape: "bytes", bytes: bytesFromHex(pt) },
        initialAux,
      });
      if (encTrace.finalState.shape !== "bytes") throw new Error("encrypt shape");
      const ct = encTrace.finalState.bytes;
      // Decrypt — fresh aux so we don't leak encrypt's roundKey.* into decrypt
      // (the schedule recomputes identically; this is paranoia).
      const decAux = new Map<string, AuxValue>([["key", keyBytes]]);
      const decTrace = runSpec(desDecryptSpec, registry, {
        initialState: { shape: "bytes", bytes: ct },
        initialAux: decAux,
      });
      if (decTrace.finalState.shape !== "bytes") throw new Error("decrypt shape");
      expect(
        hexFromBytes(decTrace.finalState.bytes),
        `roundtrip failed for PT=${pt} K=${key}`,
      ).toBe(pt);
    }
  });
});

describe("DES decrypt — consumes round keys in REVERSE order (port-native spec)", () => {
  // Pin the spec-visible property: decrypt round 1 references roundKey.15;
  // decrypt round 16 references roundKey.0. The "no swap on last round"
  // applies to round 16 of EACH direction (and uses K_1, not K_16, for
  // decrypt).
  it("round 1 xor-K consumes roundKey.15", () => {
    expect(roundKeyAuxOf("round.1.xor-K")).toBe("roundKey.15");
  });

  it("round 16 xor-K consumes roundKey.0", () => {
    expect(roundKeyAuxOf("round.16.xor-K")).toBe("roundKey.0");
  });

  // The Feistel swap IS the concat argument order. Rounds 1..15 feed the
  // split's R half (output1) into the recombine's input0 (the swap); round
  // 16 (no-swap) feeds the L⊕F xor into input0 instead.
  it("round 1 recombine uses the swap order (input0 ← split.output1)", () => {
    const b = recombineInput0("round.1.recombine");
    expect(b?.node).toBe("round.1.split");
    expect(b?.port).toBe("output1");
  });

  it("round 16 recombine uses the NO-swap order (input0 ← fxor.output)", () => {
    const b = recombineInput0("round.16.recombine");
    expect(b?.node).toBe("round.16.fxor");
    expect(b?.port).toBe("output");
  });
});
