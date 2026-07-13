/**
 * Tests for the hash branch of the spec store — Slice 2.10b of
 * `docs/plans/universal-port-dataflow.md` (2026-05-25).
 *
 * Slice 2.10a (the type-scaffolding predecessor) widened `SpecsByMode`
 * into a discriminated union `CipherSpecsByMode | HashSpecsByMode` but
 * left the hash branch unreachable: `buildCanonicalPair` always
 * constructed `kind: "cipher"`. Slice 2.10b adds:
 *
 *   - `hashDefaults` table (today: `sha-256` → `buildSha256Spec()`)
 *   - `buildCanonicalHash(hash)` returning a `kind: "hash"` SpecsByMode
 *     with a `hash: Hash` discriminant carried forward through
 *     `updateActive` / `updateBoth`
 *   - `setSpecFromDocument` early-branch on `isHash(doc.algorithm)` so
 *     hash docs land into the single slot without trying to compute an
 *     encrypt/decrypt counterpart
 *   - `isCustomSpec` + `resetSpec` hash branches that look up the
 *     canonical via the discriminant
 *
 * Reachability in 2.10b is **tests-only** (user pick (i) at slice start)
 * — there is no production code path that constructs a hash kind. The
 * production gateway lands in 2.10c with the algorithm-selector UI. This
 * file walks the hash branch via the same `setSpecFromDocument` API the
 * file-load / URL-share Surfaces use, so when 2.10c plugs the dropdown
 * in, this coverage already verifies the store contract end-to-end.
 *
 * What we explicitly DON'T test here:
 *   - Cross-mode mirror setters on hash spec — those throw upstream of
 *     the store (cipher-only registry gate); the store-level throw is a
 *     defensive-programming guard, not a user-reachable path.
 *   - `duplicateRoundInSpec` on hash spec — same defensive-throw posture.
 *   - Padding / cipherMode reactions on hash spec — those signals don't
 *     change semantics for hashes; behavior is "do nothing, leave it."
 *     A future test layer once 2.10c hides those selectors for hashes
 *     can pin the UI side; the store-level contract here is "hash
 *     SpecsByMode survives any of those signal flips intact."
 */

import { buildSha256Spec } from "@/ciphers/sha-256";
import { buildShakeSpec } from "@/ciphers/shake";
import {
  CURRENT_SCHEMA_VERSION,
  type CipherDocument,
  parseDocument,
  serializeDocument,
} from "@/core/document";
import type { StepLeaf, StepNode } from "@/core/types";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import {
  __resetSpecForTests,
  buildCanonicalHash,
  editStepParams,
  isCustomSpec,
  resetSpec,
  setHash,
  setShakeOutputLength,
  setSpecFromDocument,
  useShakeOutputLength,
  useSpec,
  useSpecsByMode,
} from "@/ui/stores/spec";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetPaddingForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetLayoutsForTests();
  __resetSpecForTests();
};

// Mutate the loaded SHA-256 spec's `length-append` leaf's params so we
// have an unambiguously-non-canonical spec for `isCustomSpec` / `resetSpec`
// coverage. The exact leaf id doesn't matter as long as it's a real
// leaf; we recursively walk to find one and rewrite its params.
const mutateFirstLeafParams = (
  spec: ReturnType<typeof buildSha256Spec>,
): ReturnType<typeof buildSha256Spec> => {
  let didMutate = false;
  const mutate = (nodes: readonly StepNode[]): StepNode[] =>
    nodes.map((n): StepNode => {
      if (didMutate) return n;
      if (n.kind === "step") {
        didMutate = true;
        const leaf: StepLeaf = {
          ...n,
          params: { ...(n.params as Record<string, unknown>), __markerForTest: true },
        };
        return leaf;
      }
      return { ...n, children: mutate(n.children) };
    });
  return { ...spec, steps: mutate(spec.steps) };
};

describe("spec store — hash branch (Slice 2.10b)", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  // ─── buildCanonicalHash ────────────────────────────────────────────────

  describe("buildCanonicalHash", () => {
    it("returns a kind:'hash' SpecsByMode with the canonical SHA-256 spec", () => {
      const built = buildCanonicalHash("sha-256");
      expect(built.kind).toBe("hash");
      if (built.kind !== "hash") return;
      // `hash` discriminant carries forward — load-bearing for resetSpec
      // and isCustomSpec which look up the canonical via this field.
      expect(built.hash).toBe("sha-256");
      // The single slot holds the SHA-256 spec we registered in
      // `hashDefaults`. Deep-equal against a freshly-built spec since
      // hashDefaults eagerly constructs at module load.
      expect(built.single).toEqual(buildSha256Spec());
    });
  });

  // ─── setSpecFromDocument: hash branch ──────────────────────────────────

  describe("setSpecFromDocument with a hash document", () => {
    it("lands a hash doc into a kind:'hash' SpecsByMode (early short-circuit)", () => {
      // Production entry point. The early branch in setSpecFromDocument
      // matches on `isHash(doc.algorithm)` BEFORE the `resolveDefault`
      // construction below, so the cipher-axis lookups never fire — the
      // advisor flagged this as the load-bearing gotcha for 2.10b.
      const sha256Spec = buildSha256Spec();
      const doc: CipherDocument = {
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: sha256Spec,
        algorithm: "sha-256",
      };
      setSpecFromDocument(doc);
      const s = useSpecsByMode()();
      expect(s.kind).toBe("hash");
      if (s.kind !== "hash") return;
      expect(s.hash).toBe("sha-256");
      // The literal `doc.spec` lands in the single slot — no padding
      // overlay, no encrypt/decrypt counterpart construction.
      expect(s.single).toBe(sha256Spec);
      // The active-spec accessor reads through to the hash single slot
      // regardless of `mode()` (which is semantically meaningless for
      // hashes but still has some signal value).
      expect(useSpec()()).toBe(sha256Spec);
    });

    it("preserves the hash discriminant across an edit (updateActive write path)", () => {
      // Customize the hash spec via setSpecFromDocument with a mutated
      // copy; mutating again via the same path should hold the kind+hash.
      const customSpec = mutateFirstLeafParams(buildSha256Spec());
      setSpecFromDocument({
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: customSpec,
        algorithm: "sha-256",
      });
      const s = useSpecsByMode()();
      expect(s.kind).toBe("hash");
      if (s.kind !== "hash") return;
      expect(s.hash).toBe("sha-256");
      expect(s.single).toBe(customSpec);
    });
  });

  // ─── Document round-trip ───────────────────────────────────────────────

  describe("document round-trip via serializeDocument + parseDocument", () => {
    it("preserves algorithm:'sha-256' through encode + decode", () => {
      const doc: CipherDocument = {
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: buildSha256Spec(),
        algorithm: "sha-256",
      };
      const text = serializeDocument(doc);
      const result = parseDocument(text);
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.doc.algorithm).toBe("sha-256");
      expect(result.doc).toEqual(doc);
    });
  });

  // ─── isCustomSpec on hash branch ───────────────────────────────────────

  describe("isCustomSpec", () => {
    it("returns false on a freshly-loaded canonical hash spec", () => {
      // Land canonical via the production entry point.
      setSpecFromDocument({
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: buildSha256Spec(),
        algorithm: "sha-256",
      });
      expect(isCustomSpec()).toBe(false);
    });

    it("returns true after a non-canonical hash spec lands", () => {
      const customSpec = mutateFirstLeafParams(buildSha256Spec());
      setSpecFromDocument({
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: customSpec,
        algorithm: "sha-256",
      });
      expect(isCustomSpec()).toBe(true);
    });
  });

  // ─── SHAKE editable output length — the on-demand-build contract ────────
  //
  // SHAKE is the ONLY hash whose canonical spec is built from a signal
  // (`resolveHashDefault` → `buildShakeSpec(hash, shakeOutputLength())`), rather
  // than a static `hashDefaults` entry. That makes `isCustomSpec` reactive to
  // the length: a PURE length change rebuilds both the active spec AND the
  // canonical it compares against, at the SAME length, so it must read "not
  // custom" (the user picked editable-length precisely so it feels first-class,
  // not like customizing). Only a real leaf edit should read "custom". These
  // guard that lockstep contract against future drift (someone dropping the
  // signal read, or making `buildShakeSpec` non-deterministic).

  describe("SHAKE output-length lockstep with isCustomSpec", () => {
    it("a pure output-length change reads as NOT custom (rebuilds spec + canonical in lockstep)", () => {
      setHash("shake128");
      expect(isCustomSpec()).toBe(false); // fresh canonical
      setShakeOutputLength(300);
      // The active spec actually rebuilt at the new length…
      expect(useShakeOutputLength()()).toBe(300);
      const s = useSpecsByMode()();
      expect(s.kind).toBe("hash");
      if (s.kind === "hash") {
        const truncate = s.single.steps.find((n) => n.id === "squeeze.truncate");
        expect(truncate?.kind).toBe("step");
        if (truncate?.kind === "step") {
          expect((truncate.params as Record<string, unknown>).length).toBe(300);
        }
      }
      // …and isCustomSpec compares against a canonical built at the SAME length.
      expect(isCustomSpec()).toBe(false);
    });

    it("a real leaf param edit reads as custom (not a length change)", () => {
      setHash("shake256");
      expect(isCustomSpec()).toBe(false);
      editStepParams("pad", { rate: 136, domainByte: 0x1f, __markerForTest: true });
      expect(isCustomSpec()).toBe(true);
    });

    it("loading a SHAKE doc syncs the output-length signal and reads as not custom", () => {
      // A shake256 doc authored at output length 96. applyDocument's hash branch
      // must sync the signal from the loaded truncate step so the control shows
      // 96 AND a later resetSpec rebuilds at 96 (not the 200 default).
      setShakeOutputLength(200); // start off-value so the sync is observable
      setSpecFromDocument({
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: buildShakeSpec("shake256", 96),
        algorithm: "shake256",
      });
      expect(useShakeOutputLength()()).toBe(96);
      expect(isCustomSpec()).toBe(false);
    });
  });

  // ─── resetSpec on hash branch ──────────────────────────────────────────

  describe("resetSpec", () => {
    it("restores a customized hash spec to canonical via the discriminant lookup", () => {
      // 1. Land a customized hash spec.
      const customSpec = mutateFirstLeafParams(buildSha256Spec());
      setSpecFromDocument({
        schemaVersion: CURRENT_SCHEMA_VERSION,
        spec: customSpec,
        algorithm: "sha-256",
      });
      expect(isCustomSpec()).toBe(true);

      // 2. Reset. The hash branch reads `current.hash` ("sha-256") and
      // looks up `hashDefaults["sha-256"]` — no `useCipher()` /
      // `useCipherMode()` reads, no padding overlay.
      resetSpec();

      // 3. Live spec equals canonical; isCustomSpec returns false.
      expect(isCustomSpec()).toBe(false);
      expect(useSpec()()).toEqual(buildSha256Spec());

      // 4. The discriminant survives the reset — important because
      // `updateActive` is the write path used by resetSpec and could
      // accidentally drop the `hash` field if the reconstruction
      // shape is wrong.
      const s = useSpecsByMode()();
      expect(s.kind).toBe("hash");
      if (s.kind === "hash") expect(s.hash).toBe("sha-256");
    });
  });
});
