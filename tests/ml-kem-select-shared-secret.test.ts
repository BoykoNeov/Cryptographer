/**
 * `ml-kem.select-shared-secret@1` — implicit rejection (FIPS 203 Algorithm 18).
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHAT IS WORTH ASSERTING ABOUT A SELECT
 *
 * The happy path — matching ciphertexts return the real secret — is the part a
 * round trip already covers and the part that cannot be got wrong for long. The
 * assertions that earn their place here are the other ones:
 *
 *   1. **Every single-byte difference rejects**, including one in the FIRST
 *      byte and one in the LAST. A comparison that stops early, reads a fixed
 *      prefix, or is off by one on the length passes a spot check that only
 *      corrupts the middle.
 *   2. **The output is one candidate or the other, never a blend.** A mask built
 *      with the wrong polarity, or with `&` and `|` transposed, produces bytes
 *      that are neither secret and would still "differ from K′ on rejection".
 *   3. **The mask polarity itself**: match → `K′`, mismatch → `K̄`. Inverting it
 *      gives a decapsulation that works perfectly for an attacker and fails for
 *      everyone else, and no round-trip test on one machine notices.
 *   4. **A length mismatch throws** rather than quietly reporting "different" —
 *      it means the two ports were bound to values from different schemes, and
 *      silently rejecting would hide the wiring error behind a plausible answer.
 *
 * The step also runs through the real runtime here, not just as a function
 * call, so the four-port contract is exercised the way a spec will use it.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { type AuxValue, type CipherSpec, INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "@/core/types";
import { SHARED_SECRET_BYTES, mlKemSelectSharedSecret } from "@/steps/ml-kem-select-shared-secret";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

/** Distinct, non-degenerate values — an all-zero candidate would make a blended
 *  output indistinguishable from a correctly selected one. */
const K_REAL = Uint8Array.from({ length: SHARED_SECRET_BYTES }, (_, i) => (i * 7 + 3) & 0xff);
const K_FAKE = Uint8Array.from({ length: SHARED_SECRET_BYTES }, (_, i) => (i * 11 + 200) & 0xff);
const CIPHERTEXT = Uint8Array.from({ length: 96 }, (_, i) => (i * 5 + 1) & 0xff);

const select = (c: Uint8Array, cPrime: Uint8Array): Uint8Array => {
  const out = mlKemSelectSharedSecret(
    new Map([
      ["ciphertext", c],
      ["reencryption", cPrime],
      ["shared", K_REAL],
      ["rejection", K_FAKE],
    ]),
    {},
    // The step reads no context; the runtime supplies a real one below.
    undefined as never,
  ).get("output");
  if (out === undefined) throw new Error("no output port");
  return out;
};

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

describe("implicit rejection — the verdict", () => {
  it("returns the real shared secret when the ciphertexts match", () => {
    expect(hex(select(CIPHERTEXT, CIPHERTEXT.slice()))).toBe(hex(K_REAL));
  });

  it("returns the rejection secret when ANY single byte differs", () => {
    // Every position, not a sample: a comparison reading a fixed prefix, or
    // stopping one byte short, passes a middle-of-the-array spot check.
    for (let i = 0; i < CIPHERTEXT.length; i++) {
      const corrupted = CIPHERTEXT.slice();
      corrupted[i] = ((corrupted[i] as number) ^ 0xff) & 0xff;
      expect(hex(select(CIPHERTEXT, corrupted)), `byte ${i} flipped`).toBe(hex(K_FAKE));
    }
  });

  it("rejects on a one-BIT difference, not just a whole-byte one", () => {
    const corrupted = CIPHERTEXT.slice();
    corrupted[0] = ((corrupted[0] as number) ^ 0x01) & 0xff;
    expect(hex(select(CIPHERTEXT, corrupted))).toBe(hex(K_FAKE));
  });

  it("never blends the two candidates — the output is byte-for-byte one of them", () => {
    // The failure this catches: a mask with `&`/`|` transposed, or a polarity
    // that is right for some bits and wrong for others, yields bytes belonging
    // to neither secret. Such an output still "differs from K′", so an
    // assertion phrased as "not the real one" would pass on it.
    const corrupted = CIPHERTEXT.slice();
    corrupted[40] = ((corrupted[40] as number) ^ 0x80) & 0xff;
    for (const out of [select(CIPHERTEXT, CIPHERTEXT.slice()), select(CIPHERTEXT, corrupted)]) {
      expect(hex(out) === hex(K_REAL) || hex(out) === hex(K_FAKE)).toBe(true);
    }
  });

  it("has the polarity the standard specifies, stated as an explicit pair", () => {
    // Inverting the mask gives a KEM that returns the true secret exactly when
    // the ciphertext was forged. Both arms are asserted together so a swap
    // cannot pass by satisfying one of them.
    const corrupted = CIPHERTEXT.slice();
    corrupted[7] = ((corrupted[7] as number) ^ 0x22) & 0xff;
    expect(hex(select(CIPHERTEXT, CIPHERTEXT.slice()))).toBe(hex(K_REAL));
    expect(hex(select(CIPHERTEXT, corrupted))).toBe(hex(K_FAKE));
  });
});

describe("implicit rejection — wiring errors are errors", () => {
  it("throws when the two ciphertexts are different lengths", () => {
    expect(() => select(CIPHERTEXT, CIPHERTEXT.subarray(0, 95))).toThrow(/same length/);
  });

  it("throws when a candidate secret is not 32 bytes", () => {
    expect(() =>
      mlKemSelectSharedSecret(
        new Map([
          ["ciphertext", CIPHERTEXT],
          ["reencryption", CIPHERTEXT],
          ["shared", K_REAL.subarray(0, 16)],
          ["rejection", K_FAKE],
        ]),
        {},
        undefined as never,
      ),
    ).toThrow(/32 bytes/);
  });

  it("throws when a port is missing rather than defaulting to a secret", () => {
    expect(() =>
      mlKemSelectSharedSecret(
        new Map([
          ["ciphertext", CIPHERTEXT],
          ["reencryption", CIPHERTEXT],
          ["shared", K_REAL],
        ]),
        {},
        undefined as never,
      ),
    ).toThrow(/requires/);
  });
});

describe("implicit rejection — through the runtime, on its four ports", () => {
  /**
   * The spec a decapsulation will build in miniature: the received ciphertext
   * is the input, the re-encryption is a constant, and the two candidate
   * secrets are constants. Running it through `runSpec` exercises the port
   * contract, which a direct executor call does not.
   */
  const spec = (reencryption: readonly number[]): CipherSpec => ({
    id: "select-shared-secret-fixture",
    name: "select fixture",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "c-prime",
        type: "constant-load@1",
        params: { bytes: [...reencryption] },
      },
      { kind: "step", id: "k-real", type: "constant-load@1", params: { bytes: [...K_REAL] } },
      { kind: "step", id: "k-fake", type: "constant-load@1", params: { bytes: [...K_FAKE] } },
      {
        kind: "step",
        id: "select",
        type: "ml-kem.select-shared-secret@1",
        params: {},
        portInputs: {
          ciphertext: { node: INPUT_SOURCE_ID, port: INPUT_SOURCE_PORT },
          reencryption: { node: "c-prime", port: "output" },
          shared: { node: "k-real", port: "output" },
          rejection: { node: "k-fake", port: "output" },
        },
      },
    ],
    outputFrom: { node: "select", port: "output" },
  });

  const run = (reencryption: readonly number[]): Uint8Array => {
    const trace = runSpec(spec(reencryption), registry, {
      initialState: { shape: "bytes", bytes: CIPHERTEXT },
      initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes");
    return trace.finalState.bytes;
  };

  it("returns the real secret on a match", () => {
    expect(hex(run([...CIPHERTEXT]))).toBe(hex(K_REAL));
  });

  it("returns the decoy on a mismatch", () => {
    const corrupted = [...CIPHERTEXT];
    corrupted[0] = (corrupted[0] as number) ^ 0xff;
    expect(hex(run(corrupted))).toBe(hex(K_FAKE));
  });

  it("emits a frame carrying all four inputs, which the narrator reads", () => {
    const trace = runSpec(spec([...CIPHERTEXT]), registry, {
      initialState: { shape: "bytes", bytes: CIPHERTEXT },
      initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
    });
    const frame = trace.frames.find((f) => f.stepId === "select");
    if (frame === undefined) throw new Error("no select frame");
    for (const p of ["ciphertext", "reencryption", "shared", "rejection"]) {
      expect(frame.portInputs?.get(p), `${p} should reach the frame`).toBeInstanceOf(Uint8Array);
    }
  });
});
