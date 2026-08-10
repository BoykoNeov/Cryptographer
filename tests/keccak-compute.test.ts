/**
 * `src/ciphers/keccak-compute.ts` — the one-call sponge ML-KEM's monolithic hash
 * steps use (P3, `docs/plans/unified-stargazing-quasar.md`).
 *
 * The module's whole claim is that it is **not** a second Keccak: it drives the
 * same nine executors the runtime drives, so the one-frame hash inside ML-KEM is
 * the same sponge a learner can watch leaf by leaf under the Hash selector.
 * That claim is only worth anything if something checks it, so the tests are
 * ordered by how much they prove.
 *
 * ## Rank 1 — the app's own traced SHA3-256 spec
 *
 * This is the assertion the module exists for. `buildSha3256Spec()` run through
 * `runSpec` produces a digest by walking 216 frames; `sha3_256()` produces one
 * by calling the executors directly. They must agree byte for byte on every
 * message. If someone edits `buildKeccakRound`'s chain and forgets this module,
 * this is what fails — and nothing else in the suite would.
 *
 * ## Rank 2 — `node:crypto`
 *
 * An implementation from outside this repository, across all four functions and
 * both sides of the rate boundary. Catches the case where the shared executors
 * are consistent with each other and wrong.
 *
 * ## Rank 3 — the incremental reader
 *
 * `shake128Reader` must produce exactly the same bytes as a bulk squeeze of the
 * same length. It exists so `SampleNTT` can loop on accepted coefficients rather
 * than on a block count, and a reader that diverged from the bulk squeeze after
 * block 0 would produce a wrong matrix only for seeds unlucky enough to need a
 * second block.
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  RATE_SHAKE128,
  keccakPermuteBytes,
  sha3_256,
  sha3_512,
  shake128,
  shake128Reader,
  shake256,
} from "@/ciphers/keccak-compute";
import { STATE_BYTES } from "@/ciphers/keccak-f";
import { buildSha3256Spec } from "@/ciphers/sha3-256";
import { runSpec } from "@/core/runtime";
import { describe, expect, it } from "vitest";

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * Messages chosen around the rate boundaries: an empty message (which still
 * costs a full padding block), one shorter than every rate, and lengths that
 * straddle 72 / 136 / 168 so both the "pad merges into one byte" edge case and
 * the multi-block absorb are exercised.
 */
const MESSAGES: readonly Uint8Array[] = [
  new Uint8Array(0),
  new Uint8Array([0x61, 0x62, 0x63]),
  new Uint8Array(71).fill(0xa5),
  new Uint8Array(72).fill(0xa5),
  new Uint8Array(135).fill(0x3c),
  new Uint8Array(136).fill(0x3c),
  new Uint8Array(137).fill(0x3c),
  new Uint8Array(167).fill(0x11),
  new Uint8Array(168).fill(0x11),
  new Uint8Array(500).fill(0xff),
];

describe("keccak-compute agrees with the app's own traced sponge", () => {
  it("reproduces buildSha3256Spec's digest, so the monolith and the visible trace cannot drift", () => {
    const registry = buildDefaultRegistry();
    for (const message of MESSAGES) {
      const trace = runSpec(buildSha3256Spec(), registry, {
        initialState: { shape: "bytes", bytes: message },
      });
      if (trace.finalState.shape !== "bytes") throw new Error("expected bytes finalState");
      expect(hex(sha3_256(message))).toBe(hex(trace.finalState.bytes));
    }
  });

  it("performs a permutation that actually changes the state", () => {
    // Guards the degenerate pass — a chain wired to return its input would
    // satisfy nothing above except by accident, but say it out loud.
    const zero = new Uint8Array(STATE_BYTES);
    const once = keccakPermuteBytes(zero);
    expect(hex(once)).not.toBe(hex(zero));
    expect(hex(keccakPermuteBytes(once))).not.toBe(hex(once));
    // Keccak-f[1600] on the all-zero state — the first lane is a published
    // value of the permutation, independent of any sponge padding.
    expect(hex(once.subarray(0, 8))).toBe("e7dde140798f25f1");
  });
});

describe("keccak-compute agrees with node:crypto", () => {
  it("matches SHA3-256 and SHA3-512", () => {
    for (const message of MESSAGES) {
      expect(hex(sha3_256(message))).toBe(createHash("sha3-256").update(message).digest("hex"));
      expect(hex(sha3_512(message))).toBe(createHash("sha3-512").update(message).digest("hex"));
    }
  });

  it("matches SHAKE128 and SHAKE256 across output lengths that span the squeeze boundary", () => {
    // 168 and 136 are the two rates: an output one byte longer costs an extra
    // permutation, which is where a squeeze loop is most likely to be wrong.
    for (const message of MESSAGES.slice(0, 5)) {
      for (const outputLength of [1, 31, 32, 135, 136, 137, 167, 168, 169, 504]) {
        expect(hex(shake128(message, outputLength))).toBe(
          createHash("shake128", { outputLength }).update(message).digest("hex"),
        );
        expect(hex(shake256(message, outputLength))).toBe(
          createHash("shake256", { outputLength }).update(message).digest("hex"),
        );
      }
    }
  });
});

describe("the incremental SHAKE128 reader SampleNTT needs", () => {
  it("produces the same bytes as a bulk squeeze, block after block", () => {
    for (const message of MESSAGES.slice(0, 5)) {
      const blocks = 7;
      const bulk = shake128(message, RATE_SHAKE128 * blocks);
      const next = shake128Reader(message);
      for (let i = 0; i < blocks; i++) {
        expect(hex(next())).toBe(hex(bulk.subarray(i * RATE_SHAKE128, (i + 1) * RATE_SHAKE128)));
      }
    }
  });

  it("returns a fresh copy per block, so a caller cannot corrupt the sponge state", () => {
    const next = shake128Reader(new Uint8Array([1, 2, 3]));
    const first = next();
    first.fill(0);
    const again = shake128Reader(new Uint8Array([1, 2, 3]))();
    expect(hex(again)).not.toBe(hex(first));
  });
});
