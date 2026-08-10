/**
 * The three shipped K-PKE specs, pinned BY HASH.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHY THIS FILE EXISTS, AND WHY THE NUMBERS IN IT ARE OLDER THAN THE CODE
 *
 * P4 embeds K-PKE's three bodies inside ML-KEM's encapsulation and
 * decapsulation, which means `k-pke.ts` has to hand its node lists out under an
 * id prefix instead of only ever emitting three fixed specs. That is a pure
 * extraction — the three specs a learner can already reach must come out byte
 * for byte identical — and a refactor that silently reshaped them would still
 * pass every behavioural test in `k-pke-kat.test.ts`, because those check
 * OUTPUT bytes and the outputs would not change.
 *
 * **The digests below were captured BEFORE the extraction, from the shipped
 * builders.** That order is the whole point, and it is the one thing about this
 * file that is easy to get backwards: capture them afterwards and the test
 * cheerfully pins the new bytes to themselves, asserting nothing. The precedent
 * is `chacha20-csprng.ts`'s `buildDoubleRoundGroups` extraction, which took its
 * digests the same way and for the same reason.
 *
 * A spec's exact bytes are load-bearing beyond refactor safety: spec-only saves
 * feed the URL-share hash, so a reflowed narration sentence repoints every
 * previously shared link. When one of these fails, decide whether the change was
 * intended — do not reflexively re-capture.
 */

import { createHash } from "node:crypto";
import { buildKPkeDecryptSpec, buildKPkeEncryptSpec, buildKPkeKeyGenSpec } from "@/ciphers/k-pke";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const digest = (spec: CipherSpec): string =>
  createHash("sha256").update(JSON.stringify(spec)).digest("hex");

/** Synthetic key material. Encrypt and Decrypt bake their `ek` / `dk` into
 *  `cipherConstants`, so the digest depends on them — these exact patterns are
 *  what the pre-refactor capture used and must not be "tidied". */
const EK = new Uint8Array(1184).map((_, i) => (i * 7) % 251);
const DK = new Uint8Array(1152).map((_, i) => (i * 11) % 241);
const R = new Uint8Array(32).fill(0x5a);

describe("the shipped K-PKE specs are byte-identical to their pre-P4 form", () => {
  it("K-PKE.KeyGen", () => {
    expect(digest(buildKPkeKeyGenSpec())).toBe(
      "504461e56d051756745f0f074d4b26991195178e804f37296d1c4d7215cb555c",
    );
  });

  it("K-PKE.Encrypt", () => {
    expect(digest(buildKPkeEncryptSpec(EK, R))).toBe(
      "70024528be65bfeae4574ad3c6440dd6ace80877a170a4ffe4a8c322b3c71ffb",
    );
  });

  it("K-PKE.Decrypt", () => {
    expect(digest(buildKPkeDecryptSpec(DK))).toBe(
      "923f974c11c6c2da68cbe9d69c4da093ebd8321aea4f1c5bcd33d6288b1e4180",
    );
  });
});
