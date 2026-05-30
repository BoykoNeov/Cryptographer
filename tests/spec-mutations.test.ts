import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import {
  type ParamCellDiff,
  compareSpecs,
  findStep,
  updateAllStepsByType,
  updateCipherConstant,
  updateStepParams,
} from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Json } from "@/core/types";
import { describe, expect, it } from "vitest";

describe("spec mutation helpers", () => {
  describe("findStep", () => {
    it("locates a leaf step nested inside a round group", () => {
      // round.1.sub-bytes lives inside the round.1 group.
      const found = findStep(aes128Spec, "round.1.sub-bytes");
      expect(found).not.toBeNull();
      expect(found?.type).toBe("byte-substitute@1");
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
      const updated = updateAllStepsByType(aes128Spec, "byte-substitute@1", (params) => ({
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
          if (node.kind === "step" && node.type === "byte-substitute@1") {
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

    // ─── compareSpecs richer diff shape (May 2026) ─────────────────────────
    // The legend used to read "round.1.sub-bytes: sbox changed". With the
    // SpecParamDiff.cells extension the diff now carries the exact (row, col,
    // from, to) of every changed cell so the formatter can render
    // "S-box[row 0, col 0] 63 → 00". These tests pin the producer-side shape.

    it("emits 2D cell diffs for a length-256 array param (AES S-box convention)", () => {
      // Tweak one S-box entry on a single round and confirm compareSpecs
      // surfaces the exact (row, col) and before/after byte values.
      const original = findStep(aes128Spec, "round.1.sub-bytes");
      const originalSbox = (original?.params as { sbox: number[] }).sbox;
      const tweakedSbox = [...originalSbox];
      // Pick an index whose canonical value is non-zero so the diff is
      // unambiguous. AES sbox[0x00] = 0x63 by convention.
      const before = tweakedSbox[0] ?? -1;
      tweakedSbox[0] = 0x00;
      const tweaked = updateStepParams(aes128Spec, "round.1.sub-bytes", { sbox: tweakedSbox });

      const diffs = compareSpecs(aes128Spec, tweaked);
      // Exactly one leaf differs.
      expect(diffs.length).toBe(1);
      const d = diffs[0];
      expect(d?.stepId).toBe("round.1.sub-bytes");
      expect(d?.paramName).toBe("sbox");
      expect(d?.stepType).toBe("byte-substitute@1");
      const cells = d?.cells ?? [];
      expect(cells.length).toBe(1);
      const c = cells[0] as ParamCellDiff;
      expect(c.kind).toBe("2d");
      if (c.kind === "2d") {
        // Index 0 → (row 0, col 0).
        expect(c.row).toBe(0);
        expect(c.col).toBe(0);
        expect(c.from).toBe(before);
        expect(c.to).toBe(0x00);
      }
    });

    it("emits 2D cell diffs for a nested 4×4 matrix param (MixColumns convention)", () => {
      // Pick a MixColumns step and tweak one cell of its matrix. The diff
      // should report (row, col) straight from the 2D nesting.
      const original = findStep(aes128Spec, "round.1.mix-columns");
      const originalMatrix = (original?.params as { matrix: number[][] }).matrix.map((r) => [...r]);
      // Clone deeply, modify [2][3]. Pull the row out to avoid a non-null
      // assertion (biome blocks `tweakedMatrix[2]![3]` style).
      const tweakedMatrix = originalMatrix.map((r) => [...r]);
      const row2 = tweakedMatrix[2] ?? [];
      const before = row2[3] ?? -1;
      row2[3] = 0xff;
      const tweaked = updateStepParams(aes128Spec, "round.1.mix-columns", {
        matrix: tweakedMatrix,
      });

      const diffs = compareSpecs(aes128Spec, tweaked);
      expect(diffs.length).toBe(1);
      const cells = diffs[0]?.cells ?? [];
      expect(cells.length).toBe(1);
      const c = cells[0] as ParamCellDiff;
      expect(c.kind).toBe("2d");
      if (c.kind === "2d") {
        expect(c.row).toBe(2);
        expect(c.col).toBe(3);
        expect(c.from).toBe(before);
        expect(c.to).toBe(0xff);
      }
    });

    it("emits a scalar diff when only a primitive param value differs (e.g. rounds count)", () => {
      // Synthetic spec where only a number-valued param differs. Use
      // updateStepParams on key-expansion which has a `rounds` field.
      const tweaked = updateStepParams(aes128Spec, "key-expansion", {
        keyAuxName: "key",
        outputPrefix: "roundKey",
        sbox: [...(findStep(aes128Spec, "key-expansion")?.params as { sbox: number[] }).sbox],
        rcon: [...(findStep(aes128Spec, "key-expansion")?.params as { rcon: number[] }).rcon],
        rounds: 999, // was 10
      });

      const diffs = compareSpecs(aes128Spec, tweaked);
      // Just `rounds` should differ (other keys re-spread from the original).
      expect(diffs.length).toBe(1);
      expect(diffs[0]?.paramName).toBe("rounds");
      expect(diffs[0]?.scalar).toEqual({ from: 10, to: 999 });
      expect(diffs[0]?.cells).toBeUndefined();
    });

    it("end-to-end: swapping the S-box changes the ciphertext", () => {
      // The headline modularity test. Swap every S-box for the identity
      // permutation, run encryption, expect a different ciphertext.
      const identitySbox = Array.from({ length: 256 }, (_, i) => i);
      const swapped = updateAllStepsByType(aes128Spec, "byte-substitute@1", (params) => ({
        ...(params as { sbox: number[] }),
        sbox: identitySbox,
      }));

      // Byte-native AES-128 (Slice B1): bytes state + ported dispatch.
      const pt = makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff"));
      const initialAux = new Map<string, AuxValue>([
        ["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")],
      ]);

      const trace = runSpec(swapped, buildDefaultRegistry(), {
        initialState: pt,
        initialAux,
        portedDispatchEnabled: true,
      });

      if (trace.finalState.shape !== "bytes") throw new Error("bad shape");
      // Output should NOT be the standard AES ciphertext anymore.
      expect(hexFromBytes(trace.finalState.bytes)).not.toBe("69c4e0d86a7b0430d8cdb78070b4c55a");
    });

    it("end-to-end: swapping a single Serpent S-box on one round changes the ciphertext", () => {
      // Serpent equivalent of the AES modularity test. Each round leaf
      // carries its own 16-entry S-box copy; mutating round.5's S-box
      // should change the ciphertext for a fixed (key, plaintext) without
      // touching any other round.
      const identitySbox4 = Array.from({ length: 16 }, (_, i) => i);

      // Confirm structurally that there are 32 sub-bytes leaves.
      let beforeCount = 0;
      const visit = (
        nodes: readonly {
          kind: string;
          type?: string;
          children?: readonly unknown[];
        }[],
      ): void => {
        for (const node of nodes) {
          if (node.kind === "step" && node.type === "serpent.sub-bytes@1") beforeCount++;
          else if (node.kind === "group") visit(node.children as never);
        }
      };
      visit(serpent128Spec.steps as never);
      expect(beforeCount).toBe(32);

      const swapped = updateStepParams(serpent128Spec, "round.5.sub-bytes", {
        sbox: identitySbox4,
        sboxIndex: 4,
      });

      const pt = makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff"));
      const initialAux = new Map<string, AuxValue>([
        ["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")],
      ]);
      const baseline = runSpec(serpent128Spec, buildDefaultRegistry(), {
        initialState: pt,
        initialAux,
      });
      const modified = runSpec(swapped, buildDefaultRegistry(), {
        initialState: pt,
        initialAux,
      });
      if (baseline.finalState.shape !== "bytes" || modified.finalState.shape !== "bytes") {
        throw new Error("bad shape");
      }
      expect(hexFromBytes(modified.finalState.bytes)).not.toBe(
        hexFromBytes(baseline.finalState.bytes),
      );
    });
  });

  describe("updateCipherConstant (A1)", () => {
    it("replaces one constant's bytes, preserving the others by reference", () => {
      const spec = buildSha256Spec();
      const newH = new Uint8Array(32).fill(0xab);
      const updated = updateCipherConstant(spec, "H", newH);
      expect(updated).not.toBe(spec);
      expect(updated.cipherConstants?.H).toBe(newH);
      // K is untouched — same reference as the source spec.
      expect(updated.cipherConstants?.K).toBe(spec.cipherConstants?.K);
    });

    it("returns the spec by reference (no-op) for an unknown constant name", () => {
      const spec = buildSha256Spec();
      const updated = updateCipherConstant(spec, "does-not-exist", new Uint8Array([1]));
      expect(updated).toBe(spec);
    });

    it("returns the spec by reference when the spec has no cipherConstants", () => {
      // AES has no cipherConstants in A1 (its S-box moves there in B1).
      const updated = updateCipherConstant(aes128Spec, "K", new Uint8Array([1]));
      expect(updated).toBe(aes128Spec);
    });

    it("an edited constant changes the digest (the run actually consumes it)", () => {
      const spec = buildSha256Spec();
      const pt = { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) } as const;
      const baseline = runSpec(spec, buildDefaultRegistry(), {
        initialState: pt,
        portedDispatchEnabled: true,
      });
      // Flip every byte of H — the initial working vars (and final add) change.
      const flippedH = Uint8Array.from(spec.cipherConstants?.H as Uint8Array, (b) => b ^ 0xff);
      const edited = updateCipherConstant(spec, "H", flippedH);
      const modified = runSpec(edited, buildDefaultRegistry(), {
        initialState: pt,
        portedDispatchEnabled: true,
      });
      if (baseline.finalState.shape !== "bytes" || modified.finalState.shape !== "bytes") {
        throw new Error("bad shape");
      }
      expect(hexFromBytes(modified.finalState.bytes)).not.toBe(
        hexFromBytes(baseline.finalState.bytes),
      );
    });
  });
});
