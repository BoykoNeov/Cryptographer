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
 * UPDATE (scaffolding-suppression Slices B1.1–B1.3, 2026-05-29): every
 * single-block AES spec (128/192/256, both directions) is now byte-native
 * (port-native primitives with no legacy executor), so it derives `true` —
 * it CANNOT run under legacy dispatch. Only the AES-128 ECB/CBC modes stay
 * matrix (legacy) until Slice B1.4, so they remain `false`.
 *
 * A separate synthetic-Feistel test ensures the helper descends into
 * `FeistelRoundGroup.tracks[].children` — the easy container kind to
 * miss. After B4, no SHIPPED spec uses `feistel-round` anymore (DES is
 * port-native), so this synthetic spec is the only remaining coverage of
 * track descent (the `FeistelRoundGroup` type survives until Phase 5).
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
import type { CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

// One row per shipped spec from `defaults` in `stores/spec.ts`, plus
// SHA-256 (which Slice 2.10 will add to the selector). Expected column
// pins the gate: every shipped cipher/hash is now byte-native port-native
// → `true`. B4 made DES the last to convert, so there is no shipped spec
// left that requires the legacy path (the synthetic-Feistel descent test
// below is the only `false`-vs-`true` discriminator now).
const shippedSpecs: ReadonlyArray<readonly [string, CipherSpec, boolean]> = [
  // Byte-native (Slice B1.1 encrypt / B1.2 decrypt) — port-native primitives,
  // no legacy path → true.
  ["aes-128 single-block encrypt", aes128Spec, true],
  ["aes-128 single-block decrypt", aes128DecryptSpec, true],
  // Byte-native (Slice B1.4a ECB / B1.4b CBC) — port-mode iterate + port-native
  // body → true. CBC adds the cross-iteration chain port; still all port-native.
  ["aes-128 ecb encrypt", aes128EcbSpec, true],
  ["aes-128 ecb decrypt", aes128EcbDecryptSpec, true],
  ["aes-128 cbc encrypt", aes128CbcSpec, true],
  ["aes-128 cbc decrypt", aes128CbcDecryptSpec, true],
  // Byte-native (Slice B1.3) — port-native primitives, no legacy path → true.
  ["aes-192 single-block encrypt", aes192Spec, true],
  ["aes-192 single-block decrypt", aes192DecryptSpec, true],
  ["aes-256 single-block encrypt", aes256Spec, true],
  ["aes-256 single-block decrypt", aes256DecryptSpec, true],
  // Byte-native (Slice B2) — the two ARX rounds are port-native (no legacy
  // path); the key-schedule is now port-native too (Slice 5.2, hybrid-ported)
  // → the whole spec runs ported, true.
  ["speck-32-64-be encrypt", speck32_64BeSpec, true],
  ["speck-32-64-be decrypt", speck32_64BeDecryptSpec, true],
  ["speck-32-64-le encrypt", speck32_64LeSpec, true],
  ["speck-32-64-le decrypt", speck32_64LeDecryptSpec, true],
  // Byte-native (Slice B3) — the five round-body executors are port-native
  // (no legacy path); the key-expansion is now port-native too (Slice 5.2,
  // hybrid-ported) → the whole spec runs ported, true.
  ["serpent-128 encrypt", serpent128Spec, true],
  ["serpent-128 decrypt", serpent128DecryptSpec, true],
  ["serpent-192 encrypt", serpent192Spec, true],
  ["serpent-192 decrypt", serpent192DecryptSpec, true],
  ["serpent-256 encrypt", serpent256Spec, true],
  ["serpent-256 decrypt", serpent256DecryptSpec, true],
  // Byte-native (Slice B4 — universal-port Phase 4d) — the F-function leaves
  // are port-native (no legacy path); the round body is wired from native
  // split/xor/concat. The key-schedule is now port-native too (Slice 5.2,
  // hybrid-ported) → the whole spec runs ported, true.
  ["des encrypt", desSpec, true],
  ["des decrypt", desDecryptSpec, true],
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

// ─── Slice 5.3a — PortFlowView is the universal inspector default ──────────
//
// The linear inspector dispatches a frame to `PortFlowView` iff the runtime
// captured port I/O, which it does iff the step's registration has
// `legacy === undefined` (the gate at `runtime.ts:767`; `isPortNativeFrame`
// in `PortFlowView.tsx` then reads the populated fields). So the contract
// 5.3a formalizes — "no user-selectable cipher reaches `BytesView`" — is
// EXACTLY "every leaf of every shipped spec has a port-native (legacy-free)
// registration." `BytesView` is reachable ONLY by the lifted-legacy
// `feistel.toy-add-k@1` step, which is test-only (injected via
// `__setSpecForTests`, never in the cipher selector). Reuses `shippedSpecs`
// above so the enumeration can't drift between the two invariants.
//
// (Rejoin frames route to `RejoinFrameView`, key-expansion to
// `KeyScheduleExplorer` — also not `BytesView`. No shipped spec uses
// `feistel-round` post-B4, so no shipped frame is a rejoin frame either.)
const collectLeafTypes = (nodes: readonly StepNode[], out: string[]): string[] => {
  for (const node of nodes) {
    if (node.kind === "step") {
      out.push(node.type);
      continue;
    }
    if (node.kind === "feistel-round") {
      for (const track of node.tracks) collectLeafTypes(track.children, out);
      continue;
    }
    // group / iterate / for-each-subgraph* — structural, no frame of their
    // own; descend into children.
    collectLeafTypes(node.children, out);
  }
  return out;
};

describe("PortFlowView universal default (5.3a) — no selectable cipher reaches BytesView", () => {
  for (const [name, spec] of shippedSpecs) {
    it(`${name}: every leaf is port-native (registration.legacy === undefined)`, () => {
      const leafTypes = collectLeafTypes(spec.steps, []);
      expect(leafTypes.length).toBeGreaterThan(0);
      for (const type of leafTypes) {
        const reg = registry.getRegistration(type);
        expect(reg, `no registration for "${type}"`).toBeDefined();
        if (reg === undefined) continue;
        // Port-native ⟺ kind "ported" with NO `legacy` fallback — the exact
        // condition under which the runtime captures port I/O (runtime.ts:767)
        // → `isPortNativeFrame` → PortFlowView. `kind: "legacy"` or a lifted
        // ported reg (legacy defined) would route to BytesView.
        const isPortNative = reg.kind === "ported" && reg.legacy === undefined;
        expect(
          isPortNative,
          `"${type}" is not port-native (kind=${reg.kind}) → would route to BytesView`,
        ).toBe(true);
      }
    });
  }

  it("positive control: the lifted-legacy feistel toy WOULD route to BytesView", () => {
    // Proves the invariant above has teeth. The one lifted-legacy step (the
    // test-only toy) is a ported registration that KEEPS a `legacy` fallback →
    // the runtime skips port capture → its frames fall through to `BytesView`.
    // If this regresses to `undefined`, the Feistel components break AND the
    // invariant above goes vacuous.
    const reg = registry.getRegistration("feistel.toy-add-k@1");
    expect(reg).toBeDefined();
    expect(reg?.kind).toBe("ported");
    if (reg?.kind === "ported") {
      expect(reg.legacy).toBeDefined();
    }
  });
});
