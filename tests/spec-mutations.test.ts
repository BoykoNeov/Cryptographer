import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { findStep, updateAllStepsByType, updateStepParams } from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, Json } from "@/core/types";
import { describe, expect, it } from "vitest";

describe("spec mutation helpers", () => {
  describe("findStep", () => {
    it("locates a leaf step nested inside a round group", () => {
      // round.1.sub-bytes lives inside the round.1 group.
      const found = findStep(aes128Spec, "round.1.sub-bytes");
      expect(found).not.toBeNull();
      expect(found?.type).toBe("generic.byte-substitution@1");
    });

    it("returns null for a non-existent id", () => {
      expect(findStep(aes128Spec, "nope.does-not-exist")).toBeNull();
    });

    it("returns null when the id refers to a group, not a leaf", () => {
      // round.1 is a group; findStep is documented to find leaves only.
      expect(findStep(aes128Spec, "round.1")).toBeNull();
    });
  });

  describe("updateStepParams", () => {
    it("replaces params on the targeted leaf only", () => {
      const newParams = { auxName: "roundKey.0" };
      const updated = updateStepParams(aes128Spec, "initial.add-round-key", newParams);

      const target = findStep(updated, "initial.add-round-key");
      expect(target?.params).toEqual(newParams);

      // Other steps unaffected
      const otherSubBytes = findStep(updated, "round.1.sub-bytes");
      const originalSubBytes = findStep(aes128Spec, "round.1.sub-bytes");
      expect(otherSubBytes?.params).toEqual(originalSubBytes?.params);
    });

    it("returns the original spec by reference when stepId doesn't match", () => {
      const result = updateStepParams(aes128Spec, "nope", {});
      expect(result).toBe(aes128Spec); // ===, not just equal
    });

    it("does not mutate the original spec", () => {
      const before = JSON.stringify(aes128Spec);
      updateStepParams(aes128Spec, "round.1.sub-bytes", { sbox: new Array(256).fill(0) });
      expect(JSON.stringify(aes128Spec)).toBe(before);
    });
  });

  describe("updateAllStepsByType", () => {
    it("applies the update function to every matching step", () => {
      // Replace the S-box on every byte-substitution step (10 rounds + the
      // one inside key-expansion would be... actually key-expansion uses
      // type aes.key-expansion@1, not byte-substitution. So 10 round
      // SubBytes steps will be updated.
      const identitySbox = Array.from({ length: 256 }, (_, i) => i);
      const updated = updateAllStepsByType(aes128Spec, "generic.byte-substitution@1", (params) => ({
        ...(params as { sbox: number[] }),
        sbox: identitySbox,
      }));

      // Every byte-substitution step should now have the identity S-box.
      let count = 0;
      const visit = (
        nodes: readonly {
          kind: string;
          type?: string;
          children?: readonly unknown[];
          params?: Json;
        }[],
      ): void => {
        for (const node of nodes) {
          if (node.kind === "step" && node.type === "generic.byte-substitution@1") {
            count++;
            const sbox = (node.params as { sbox: number[] }).sbox;
            expect(sbox).toEqual(identitySbox);
          } else if (node.kind === "group") {
            visit(node.children as never);
          }
        }
      };
      visit(updated.steps as never);
      expect(count).toBe(10); // one per round
    });

    it("end-to-end: swapping the S-box changes the ciphertext", () => {
      // The headline modularity test. Swap every S-box for the identity
      // permutation, run encryption, expect a different ciphertext.
      const identitySbox = Array.from({ length: 256 }, (_, i) => i);
      const swapped = updateAllStepsByType(aes128Spec, "generic.byte-substitution@1", (params) => ({
        ...(params as { sbox: number[] }),
        sbox: identitySbox,
      }));

      const pt = matrixFromBytes(bytesFromHex("00112233445566778899aabbccddeeff"));
      const initialAux = new Map<string, AuxValue>([
        ["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")],
      ]);

      const trace = runSpec(swapped, buildDefaultRegistry(), {
        initialState: pt,
        initialAux,
      });

      if (trace.finalState.shape !== "matrix4x4-bytes") throw new Error("bad shape");
      // Output should NOT be the standard AES ciphertext anymore.
      expect(hexFromBytes(trace.finalState.bytes)).not.toBe("69c4e0d86a7b0430d8cdb78070b4c55a");
    });
  });
});
