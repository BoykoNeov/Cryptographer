/**
 * DES decrypt tests. Inverse KAT against the same FIPS 46-3 vectors as
 * `des-vectors.test.ts`, plus a random-roundtrip pin.
 *
 * The decrypt spec (`src/ciphers/des-decrypt.ts`) is the same Feistel
 * structure as encrypt with round keys consumed in reverse order
 * (roundKey.15, roundKey.14, …, roundKey.0). Round 16 keeps the
 * `feistel-no-swap` combine kind — the "no swap on last round" exception
 * applies to each direction independently and is what makes the cipher
 * self-inverse under key-reversal.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import type { AuxValue, BytesState } from "@/core/types";
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

describe("DES decrypt — consumes round keys in REVERSE order", () => {
  // Pin the spec-visible property: decrypt round 1 references roundKey.15;
  // decrypt round 16 references roundKey.0. The "no swap on last round"
  // applies to round 16 of EACH direction (and uses K_1, not K_16, for
  // decrypt).
  it("round 1 xor-K consumes roundKey.15", () => {
    const round1 = desDecryptSpec.steps[2];
    expect(round1?.kind).toBe("group");
    if (round1?.kind !== "group") return;
    const r1 = round1.children[0];
    expect(r1?.kind).toBe("feistel-round");
    if (r1?.kind !== "feistel-round") return;
    const rTrack = r1.tracks[1];
    expect(rTrack?.name).toBe("R");
    if (!rTrack) return;
    const xorK = rTrack.children.find((c) => c.kind === "step" && c.type === "des.xor-with-K@1");
    expect(xorK).toBeDefined();
    if (!xorK || xorK.kind !== "step") return;
    const params = xorK.params as { roundKeyAux?: string };
    expect(params.roundKeyAux).toBe("roundKey.15");
  });

  it("round 16 uses combineKind 'feistel-no-swap' AND consumes roundKey.0", () => {
    const rounds = desDecryptSpec.steps[2];
    if (rounds?.kind !== "group") throw new Error("rounds group missing");
    const r16 = rounds.children[15];
    expect(r16?.kind).toBe("feistel-round");
    if (r16?.kind !== "feistel-round") return;
    expect(r16.combineKind).toBe("feistel-no-swap");
    const rTrack = r16.tracks[1];
    if (!rTrack) return;
    const xorK = rTrack.children.find((c) => c.kind === "step" && c.type === "des.xor-with-K@1");
    if (!xorK || xorK.kind !== "step") return;
    const params = xorK.params as { roundKeyAux?: string };
    expect(params.roundKeyAux).toBe("roundKey.0");
  });
});
