/**
 * ChaCha20-CSPRNG known-answer tests — the app's fourth generator, and the
 * first with a live external oracle.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ORACLE.
 *
 * The three LCGs have no reproducible oracle in `node:crypto` and lean on an
 * ISO conformance value. This generator has the best oracle in the repo:
 * **`node:crypto`'s `chacha20`, encrypting a buffer of zeros.**
 *
 * A stream cipher's ciphertext for an all-zero plaintext IS its keystream
 * (`0 ⊕ k === k`), and this generator's output IS that keystream — so a
 * different implementation, in C, in the Node runtime, produces the exact bytes
 * this spec must produce, at every length, for every seed. There is nothing to
 * transcribe and nothing to trust.
 *
 * Layered underneath it, RFC 8439 Appendix A.1's first block-function test
 * vector (key = 0, nonce = 0, counter = 0) is pinned as a literal, because the
 * app's DEFAULT seed is all-zero and that makes the app's first paint a
 * published standard — the property MINSTD gets from seed 1 and AES-128 from
 * FIPS-197 §C.1. It also anchors the oracle itself: if `node:crypto` and this
 * spec ever agreed on something wrong, the literal would still fail.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * SEEDING AND COUNTER CONVENTION — written down, because this is the trap.
 *
 *     seed  = the 32 bytes verbatim, occupying ChaCha20's 256-bit key region.
 *     nonce = 12 zero bytes.
 *     block counter starts at 0.
 *
 * The counter is the dangerous one. RFC 8439's §2.4.2 ENCRYPTION vectors start
 * their counter at 1, and the shipped ChaCha20 cipher follows them; this
 * generator starts at 0, as a generator reading its stream from the beginning
 * should. Get it wrong and the output is a perfectly plausible ChaCha20
 * keystream that matches no other implementation — the same failure class as
 * ChaCha's counter-1 vs Salsa's counter-0, which this repo has been bitten by
 * twice. Group 3 pins the distinction directly.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * GROUP 5 IS A REFACTORING GUARD, NOT A CRYPTO TEST.
 *
 * This phase extracted `buildDoubleRoundGroups` out of `chacha20.ts` so the
 * generator could compose the same twenty rounds. The two digests pinned there
 * were taken from the shipped specs BEFORE that extraction — the ordering
 * matters, since digests taken after would pin the post-refactor bytes to
 * themselves and guard nothing.
 *
 * Why it is worth a test at all: spec-only saves are byte-stable and feed the
 * `#doc=` URL-share hash, so a one-byte drift in the ChaCha20 spec silently
 * repoints every ChaCha20 link anyone has ever shared, while every behavioural
 * test in the repo stays green.
 */

import { createCipheriv } from "node:crypto";
import { createHash } from "node:crypto";
import { chacha20DecryptSpec, chacha20EncryptSpec } from "@/ciphers/chacha20";
import {
  CHACHA20_CSPRNG_SEED_BYTES,
  CSPRNG_ADVANCE_ID,
  CSPRNG_COUNTER_INIT_ID,
  CSPRNG_ITERATE_ID,
  PRNG_SEED_AUX,
  buildChaCha20CsprngSpec,
} from "@/ciphers/chacha20-csprng";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { readPrngOutputLength } from "@/ciphers/prng-request";
import { arxDoubleRoundsById, arxRoundNeverModes } from "@/core/arx-group";
import { findActiveChaChaQuarterRound } from "@/core/chacha-shape";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** The seed the app defaults to, and the one RFC 8439 §A.1 uses. */
const ZERO_SEED = new Uint8Array(CHACHA20_CSPRNG_SEED_BYTES);

/** A seed with every byte distinct, so a byte-order error cannot hide. */
const COUNTING_SEED = Uint8Array.from({ length: CHACHA20_CSPRNG_SEED_BYTES }, (_, i) => i);

/**
 * Run the generator through the REAL runtime — registry, ports, iterate and
 * all — exactly as the app does, including publishing the seed to `aux`.
 *
 * That aux publish is `App.tsx`'s job in production (the seed cannot reach
 * inside the iterate through a port, since port flow does not cross a container
 * scope). Reproducing it here rather than importing a helper keeps this test
 * honest about what the app must do.
 */
const generate = (seed: Uint8Array, outputLength: number): Uint8Array => {
  const trace = runSpec(buildChaCha20CsprngSpec(outputLength), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: new Uint8Array(seed) },
    initialAux: new Map<string, AuxValue>([
      ["key", new Uint8Array(0)],
      [PRNG_SEED_AUX, new Uint8Array(seed)],
    ]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");
  return trace.finalState.bytes;
};

/**
 * The external oracle: ChaCha20's keystream from a different implementation.
 *
 * The 16-byte IV is the app's OpenSSL-compatible blob — a 32-bit little-endian
 * counter followed by the 12-byte nonce — packed by hand so a change to the
 * generator's counter or nonce convention has to be reflected in a test that
 * fails, rather than being imported from the code under test.
 */
const oracle = (seed: Uint8Array, outputLength: number, counter = 0): Uint8Array => {
  const iv = new Uint8Array(16);
  new DataView(iv.buffer).setUint32(0, counter, true /* little-endian */);
  // iv[4..15] stay zero — the generator's fixed nonce.
  const c = createCipheriv("chacha20", seed, iv);
  return new Uint8Array(Buffer.concat([c.update(new Uint8Array(outputLength)), c.final()]));
};

const digest = (spec: CipherSpec): string =>
  createHash("sha256").update(JSON.stringify(spec)).digest("hex");

// ─── 1. RFC 8439 Appendix A.1 — the published vector ──────────────────────

describe("RFC 8439 §A.1 — the block function at key 0, nonce 0, counter 0", () => {
  /**
   * Appendix A.1's first test vector, as a literal. This is the anchor: it is
   * not derived from this codebase, not recomputed by anything sharing a line
   * with the spec, and not obtained from `node:crypto`.
   */
  const A1_BLOCK_0 =
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" +
    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586";

  it("produces the RFC's 64 bytes from an all-zero seed", () => {
    expect(toHex(generate(ZERO_SEED, 64))).toBe(A1_BLOCK_0);
  });

  it("is what the app shows on first paint", () => {
    // The app's default seed is all-zero and its default length is 42, so the
    // first thing a user sees is a prefix of a published standard. This pins
    // the claim the file header and the store's default both make.
    expect(toHex(generate(ZERO_SEED, 42))).toBe(A1_BLOCK_0.slice(0, 84));
  });
});

// ─── 2. The live oracle, across the whole length range ────────────────────

describe("node:crypto agreement", () => {
  // Lengths chosen to straddle every boundary the iterate has: below one block,
  // one short of a block, exactly one, one past, and several with a ragged tail.
  const LENGTHS = [1, 2, 31, 42, 63, 64, 65, 100, 128, 129, 191, 192, 255, 256];

  for (const seedName of ["zero", "counting"] as const) {
    const seed = seedName === "zero" ? ZERO_SEED : COUNTING_SEED;

    for (const n of LENGTHS) {
      it(`matches node:crypto for a ${seedName} seed at ${n} bytes`, () => {
        const got = generate(seed, n);
        // Length first: a generator that produced 64 bytes for a 42-byte
        // request would fail the byte comparison too, but for a reason the
        // message would not name.
        expect(got).toHaveLength(n);
        expect(toHex(got)).toBe(toHex(oracle(seed, n)));
      });
    }
  }

  it("gives a completely different stream for a one-bit seed change", () => {
    // The avalanche claim `narrStateInit` makes on screen, asserted. Two seeds
    // differing in one bit share no byte position by luck at this length.
    const flipped = new Uint8Array(COUNTING_SEED);
    flipped[0] = (flipped[0] as number) ^ 0x01;
    const a = generate(COUNTING_SEED, 64);
    const b = generate(flipped, 64);
    const shared = Array.from(a).filter((byte, i) => byte === b[i]).length;
    // ~0.25 bytes expected to collide by chance in 64; 8 is a generous ceiling
    // that still fails hard for a seed that failed to reach the state.
    expect(shared).toBeLessThan(8);
  });
});

// ─── 3. The counter starts at 0, and advances by exactly one ──────────────

describe("the block counter", () => {
  it("starts at 0, NOT at 1", () => {
    // The trap this whole family of ciphers sets. A generator that started at
    // counter 1 would produce a flawless ChaCha20 keystream that matches
    // nothing — so this asserts against BOTH candidate oracles and requires
    // the app to pick the right one.
    const got = toHex(generate(COUNTING_SEED, 64));
    expect(got).toBe(toHex(oracle(COUNTING_SEED, 64, 0)));
    expect(got).not.toBe(toHex(oracle(COUNTING_SEED, 64, 1)));
  });

  it("advances by exactly one per block", () => {
    // Block n of a long stream must equal the block function at counter n. If
    // the counter never advanced, every 64-byte slice would be identical; if it
    // advanced by two, block 1 would equal the oracle at counter 2.
    const long = generate(COUNTING_SEED, 256);
    for (let blockIndex = 0; blockIndex < 4; blockIndex++) {
      const slice = long.subarray(blockIndex * 64, (blockIndex + 1) * 64);
      const expected = oracle(COUNTING_SEED, 64, blockIndex);
      expect(toHex(slice), `block ${blockIndex}`).toBe(toHex(expected));
    }
    // And the blocks genuinely differ — the assertion that catches a counter
    // stuck at its initial value in the case where block 0 happens to be right.
    expect(toHex(long.subarray(0, 64))).not.toBe(toHex(long.subarray(64, 128)));
  });

  it("is not affected by the final block being trimmed", () => {
    // The trim cuts the OUTPUT, never the counter: blocks are counted, not
    // bytes. So a 65-byte request's second block must be the same block-1
    // keystream a 128-byte request produces, just cut to one byte.
    const short = generate(COUNTING_SEED, 65);
    const full = generate(COUNTING_SEED, 128);
    expect(short[64]).toBe(full[64]);
  });
});

// ─── 4. Structure: the wiring the spec depends on ─────────────────────────

describe("spec structure", () => {
  const spec = buildChaCha20CsprngSpec(100);

  it("declares a zero-width key — the seed is the input, not a key field", () => {
    expect(spec.inputs.key.byteLength).toBe(0);
  });

  it("round-trips its requested length through the shared PRNG reader", () => {
    // The store reads the length back out of a loaded document with this
    // function. If the request leaf were renamed, a saved generator document
    // would load with its length silently reset to the default.
    expect(readPrngOutputLength(spec)).toBe(100);
  });

  it("loops on 64-byte blocks with a ragged tail allowed", () => {
    const iterate = spec.steps.find((n) => n.id === CSPRNG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    expect(iterate.blockByteLength).toBe(64);
    // Without this, a length that is not a multiple of 64 throws in the runtime
    // rather than producing a trimmed final block.
    expect(iterate.allowPartialFinalBlock).toBe(true);
    // The counter rides the cross-iteration carry — CTR's shape, and the
    // property that makes the stream seekable.
    expect(iterate.chainInput).toEqual({ node: CSPRNG_COUNTER_INIT_ID, port: "output" });
    expect(iterate.chainFeedback).toEqual({ node: CSPRNG_ADVANCE_ID, port: "output" });
  });

  it("contains no xor — the message the cipher would meet does not exist", () => {
    // The one structural difference from the ChaCha20 cipher, and the reason
    // this is a generator. An `xor@1` appearing at body level would mean the
    // keystream was being combined with the ignored zero-fill bytes.
    const iterate = spec.steps.find((n) => n.id === CSPRNG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    const bodyLeafTypes = iterate.children
      .filter((c) => c.kind === "step")
      .map((c) => (c.kind === "step" ? c.type : ""));
    expect(bodyLeafTypes).not.toContain("xor@1");
  });
});

// ─── 5. The shipped ChaCha20 specs are byte-identical ─────────────────────

describe("the double-round extraction changed nothing", () => {
  /**
   * Captured from the shipped specs BEFORE `buildDoubleRoundGroups` was
   * extracted from `buildBlockBody`. See the file header on why the ordering is
   * the whole value of this test.
   */
  const PRE_REFACTOR_ENCRYPT = "e40aa368dee2e034935538fa0a2c40bb886c0f149beb4e9e97bb9dc510c0f971";
  const PRE_REFACTOR_DECRYPT = "108b661063ccb1fc540ac4b65db292a1ce20c7f72d057f2e65180aee1b106d90";

  it("leaves the ChaCha20 encrypt spec byte-identical", () => {
    expect(digest(chacha20EncryptSpec)).toBe(PRE_REFACTOR_ENCRYPT);
  });

  it("leaves the ChaCha20 decrypt spec byte-identical", () => {
    expect(digest(chacha20DecryptSpec)).toBe(PRE_REFACTOR_DECRYPT);
  });

  /**
   * The payoff the plan asked to be verified: because the rounds are built by
   * the SAME function, every graph-view surface that recognizes an ARX double
   * round applies to the generator without knowing it exists.
   *
   * These import the real shipped functions rather than re-deriving the
   * recognition locally — the repo has been bitten before by replication tests
   * that rebuilt the composition and stayed green while the browser cell fell
   * apart (see `core/arx-group.ts`'s header).
   */
  it("is recognized by the ARX shape family exactly as the cipher is", () => {
    const csprng = buildChaCha20CsprngSpec(42);
    expect(arxDoubleRoundsById(csprng).size).toBe(10);
    // Byte-for-byte the same recognition the cipher gets. If a future change
    // narrowed the analyzers back to a cipher list, this diverges.
    expect(arxDoubleRoundsById(csprng).size).toBe(arxDoubleRoundsById(chacha20EncryptSpec).size);
  });

  it("guards its round splits from replication, as the cipher's are", () => {
    // THE gotcha, and it is measured not reasoned: each double round's split
    // feeds 16 consumers, five times the replication threshold. Without the
    // guard the split is DELETED and scattered into 16 chips, destroying the
    // canonical cell — a failure invisible to every behavioural test.
    const never = arxRoundNeverModes(buildChaCha20CsprngSpec(42));
    expect(Object.keys(never).some((id) => id.endsWith(".split"))).toBe(true);
    expect(Object.keys(never)).toHaveLength(
      Object.keys(arxRoundNeverModes(chacha20EncryptSpec)).length,
    );
  });

  it("lights up the quarter-round diagram on every ARX frame", () => {
    // `<ChaChaQuarterRoundDiagram />` self-detects through this function, so a
    // non-zero hit count is what makes the diagram appear for the generator.
    // 10 double rounds × 8 quarter rounds × 12 operations = 960.
    const spec = buildChaCha20CsprngSpec(42);
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: { shape: "bytes", bytes: new Uint8Array(ZERO_SEED) },
      initialAux: new Map<string, AuxValue>([
        ["key", new Uint8Array(0)],
        [PRNG_SEED_AUX, new Uint8Array(ZERO_SEED)],
      ]),
    });
    const hits = trace.frames.filter((f) => findActiveChaChaQuarterRound(f, spec) !== null).length;
    expect(hits).toBe(960);
  });

  it("builds the generator's rounds from the same ten groups the cipher uses", () => {
    // The claim that earns the shared builder: identical group ids and labels
    // mean the graph view's ARX recognizer, canonical layout cell and
    // quarter-round diagram all apply to the generator without knowing it
    // exists. They key off shape, never off the cipher.
    const iterate = buildChaCha20CsprngSpec(64).steps.find((n) => n.id === CSPRNG_ITERATE_ID);
    if (iterate === undefined || iterate.kind !== "iterate") throw new Error("no iterate");
    const groups = iterate.children.filter((c) => c.kind === "group");
    expect(groups).toHaveLength(10);
    expect(groups.map((g) => g.id)).toEqual(
      Array.from({ length: 10 }, (_, i) => `double-round.${i}`),
    );
    // 98 leaves apiece — the RFC's eight quarter rounds of twelve ops, plus the
    // split and concat at the group boundary.
    for (const g of groups) {
      if (g.kind !== "group") continue;
      expect(g.children).toHaveLength(98);
    }
  });
});
