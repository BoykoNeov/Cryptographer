/**
 * Slice 2.7 of the universal-port dataflow plan
 * (`docs/plans/universal-port-dataflow.md`). Pins the discriminator that
 * decides — at the live App's runSpec call site — whether to pass
 * `portedDispatchEnabled: true` to the runtime.
 *
 * The slice's pass/fail gate is: SHA-256 derives `true`; every other
 * shipped spec (AES-128 / AES-192 / AES-256 in single-block + ECB +
 * CBC where shipped, Speck32/64 BE + LE, Serpent-128/192/256, DES)
 * derives `false` so they continue running under the legacy dispatch
 * path. This file walks the full set and pins both directions.
 *
 * A separate synthetic-Feistel test ensures the helper descends into
 * `FeistelRoundGroup.tracks[].children` — the easy container kind to
 * miss because DES today only carries lifted-legacy leaves (so the
 * shipped DES rows above would NOT detect a missed track descent).
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128CbcDecryptSpec } from "@/ciphers/aes-128-cbc-decrypt";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes128EcbDecryptSpec } from "@/ciphers/aes-128-ecb-decrypt";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes192DecryptSpec } from "@/ciphers/aes-192-decrypt";
import { aes256Spec } from "@/ciphers/aes-256";
import { aes256DecryptSpec } from "@/ciphers/aes-256-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
import { requiresPortedDispatch } from "@/core/dispatch";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

// One row per shipped spec from `defaults` in `stores/spec.ts`, plus
// SHA-256 (which Slice 2.10 will add to the selector). Expected column
// pins the slice gate: only SHA-256 is `true` today.
const shippedSpecs: ReadonlyArray<readonly [string, CipherSpec, boolean]> = [
  ["aes-128 single-block encrypt", aes128Spec, false],
  ["aes-128 single-block decrypt", aes128DecryptSpec, false],
  ["aes-128 ecb encrypt", aes128EcbSpec, false],
  ["aes-128 ecb decrypt", aes128EcbDecryptSpec, false],
  ["aes-128 cbc encrypt", aes128CbcSpec, false],
  ["aes-128 cbc decrypt", aes128CbcDecryptSpec, false],
  ["aes-192 single-block encrypt", aes192Spec, false],
  ["aes-192 single-block decrypt", aes192DecryptSpec, false],
  ["aes-256 single-block encrypt", aes256Spec, false],
  ["aes-256 single-block decrypt", aes256DecryptSpec, false],
  ["speck-32-64-be encrypt", speck32_64BeSpec, false],
  ["speck-32-64-be decrypt", speck32_64BeDecryptSpec, false],
  ["speck-32-64-le encrypt", speck32_64LeSpec, false],
  ["speck-32-64-le decrypt", speck32_64LeDecryptSpec, false],
  ["serpent-128 encrypt", serpent128Spec, false],
  ["serpent-128 decrypt", serpent128DecryptSpec, false],
  ["serpent-192 encrypt", serpent192Spec, false],
  ["serpent-192 decrypt", serpent192DecryptSpec, false],
  ["serpent-256 encrypt", serpent256Spec, false],
  ["serpent-256 decrypt", serpent256DecryptSpec, false],
  ["des encrypt", desSpec, false],
  ["des decrypt", desDecryptSpec, false],
  ["sha-256", buildSha256Spec(), true],
];

describe("requiresPortedDispatch — shipped specs", () => {
  for (const [name, spec, expected] of shippedSpecs) {
    it(`${name} → ${String(expected)}`, () => {
      expect(requiresPortedDispatch(spec, registry)).toBe(expected);
    });
  }
});

describe("requiresPortedDispatch — container descent", () => {
  it("descends into feistel-round tracks (synthetic port-native leaf in R)", () => {
    // Synthetic 2-track Feistel round whose right track contains the
    // port-native `not@1` primitive. If the walker fails to descend
    // through `tracks[].children`, the assertion would catch the bug
    // by returning `false` instead of `true`. DES's shipped spec uses
    // only lifted-legacy leaves so it cannot detect this regression.
    const spec: CipherSpec = {
      id: "synthetic-feistel-port-native@1",
      name: "synthetic-feistel-port-native",
      stateShape: "bytes",
      inputs: {
        plaintext: { shape: "bytes" },
        key: { byteLength: 0 },
      },
      steps: [
        {
          kind: "feistel-round",
          id: "round.1",
          combineKind: "feistel-standard",
          tracks: [
            { name: "L", inputBytes: [0, 1], children: [] },
            {
              name: "R",
              inputBytes: [2, 3],
              children: [
                {
                  kind: "step",
                  id: "round.1:R:not",
                  type: "not@1",
                  params: {},
                },
              ],
            },
          ],
        },
      ],
    };
    expect(requiresPortedDispatch(spec, registry)).toBe(true);
  });

  it("descends into deeply nested groups (synthetic port-native leaf at depth 3)", () => {
    // Three-deep group nesting with a port-native leaf at the bottom.
    // None of the shipped specs nest groups this deeply, so this is
    // the only assertion that pins the group recursion's depth.
    const spec: CipherSpec = {
      id: "synthetic-nested-groups@1",
      name: "synthetic-nested-groups",
      stateShape: "bytes",
      inputs: {
        plaintext: { shape: "bytes" },
        key: { byteLength: 0 },
      },
      steps: [
        {
          kind: "group",
          id: "g1",
          label: "g1",
          children: [
            {
              kind: "group",
              id: "g2",
              label: "g2",
              children: [
                {
                  kind: "group",
                  id: "g3",
                  label: "g3",
                  children: [
                    {
                      kind: "step",
                      id: "g3.not",
                      type: "not@1",
                      params: {},
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    };
    expect(requiresPortedDispatch(spec, registry)).toBe(true);
  });

  it("returns false for an empty spec", () => {
    // Vacuous case — no leaves, nothing to require ported dispatch.
    const spec: CipherSpec = {
      id: "empty@1",
      name: "empty",
      stateShape: "bytes",
      inputs: {
        plaintext: { shape: "bytes" },
        key: { byteLength: 0 },
      },
      steps: [],
    };
    expect(requiresPortedDispatch(spec, registry)).toBe(false);
  });
});
