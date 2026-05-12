/**
 * Serpent cipher spec factory. Emits a full CipherSpec for a chosen
 * `(keyByteLength, direction)` pair.
 *
 * All three key sizes share the same key schedule, round body, and S-box
 * cycling — only the key input length differs. The variant identity
 * (Serpent-128 / 192 / 256) is encoded entirely in the `keyByteLength`
 * param on the key-expansion step and the spec's declared
 * `inputs.key.byteLength`.
 *
 * The six shipped Serpent specs (128/192/256 × encrypt/decrypt) all route
 * through this one factory so they cannot drift in step count, step ids,
 * or round structure.
 */

import type { CipherSpec, StepNode } from "../core/types";
import { buildSerpentDecryptBody, buildSerpentEncryptBody } from "./serpent-round-builder";

export type SerpentDirection = "encrypt" | "decrypt";
export type SerpentKeyByteLength = 16 | 24 | 32;

export const buildSerpentSpec = (
  keyByteLength: SerpentKeyByteLength,
  direction: SerpentDirection,
): CipherSpec => {
  const keyBits = keyByteLength * 8;
  const dirTag = direction === "encrypt" ? "" : "-decrypt";
  const id = `serpent-${keyBits}${dirTag}@1`;
  const name = `Serpent-${keyBits}${direction === "decrypt" ? " (decrypt)" : ""}`;

  const keyExpansion: StepNode = {
    kind: "step",
    id: "key-expansion",
    type: "serpent.key-expansion@1",
    params: {
      keyAuxName: "key",
      outputPrefix: "roundKey",
      keyByteLength,
    },
  };

  const body = direction === "encrypt" ? buildSerpentEncryptBody() : buildSerpentDecryptBody();

  return {
    id,
    name,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: keyByteLength },
    },
    steps: [keyExpansion, ...body],
  };
};
