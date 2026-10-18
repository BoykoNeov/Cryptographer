/**
 * The two shipped ML-KEM-768 specs, pinned BY HASH.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHY THIS FILE EXISTS, AND WHY THE NUMBERS IN IT ARE OLDER THAN THE CODE
 *
 * ML-DSA's plan (`docs/plans/refactored-petting-tide.md`, P1) parameterizes the
 * NTT builder so the same seven-or-eight-layer machinery serves both q = 3329
 * and q = 8380417. ML-KEM embeds that builder in every key generation,
 * encapsulation and decapsulation, so the extraction must leave both specs
 * byte for byte identical — and a refactor that silently reshaped them would
 * still pass every behavioural test, because those check OUTPUT bytes.
 *
 * **The digests below were captured BEFORE the parameterization, from the
 * shipped builders** — the `k-pke-spec-digests.test.ts` and
 * `ntt-3329-256-kat.test.ts` precedent. Capture them afterwards and the test
 * pins the new bytes to themselves, asserting nothing.
 *
 * Spec-only saves feed the URL-share hash, so these bytes are also what keeps
 * previously shared links pointing at the same spec. When one fails, decide
 * whether the change was intended — do not reflexively re-capture.
 */

import { createHash } from "node:crypto";
import { buildMlKemDecapsSpec, buildMlKemEncapsSpec } from "@/ciphers/ml-kem-768";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const digest = (spec: CipherSpec): string =>
  createHash("sha256").update(JSON.stringify(spec)).digest("hex");

describe("the shipped ML-KEM-768 specs are byte-identical to their pre-ML-DSA form", () => {
  it("encapsulation (default seed)", () => {
    expect(digest(buildMlKemEncapsSpec())).toBe(
      "4a32959c1e4ddf91d66d8a5e2133f7014f44a94b8e684f4e4928d8d44501bf10",
    );
  });

  it("decapsulation (default seed)", () => {
    expect(digest(buildMlKemDecapsSpec())).toBe(
      "04f84e519090cb2d31e7edff4c2db4867fe041f7024bb70a74c5609dc514c5d3",
    );
  });
});
