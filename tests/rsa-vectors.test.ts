/**
 * RSA known-answer + round-trip tests (Phase 1 of
 * `docs/plans/shimmying-booping-moth.md`).
 *
 * The load-bearing exit gate for the math: the flat RSA spec must reproduce
 * real RSA arithmetic, the key generation must derive the textbook constants,
 * and encrypt∘decrypt must round-trip.
 *
 * **Verified against a Python oracle** (`feedback_crypto_verification` — pin
 * the FIRST vector against a real reference, not a web citation):
 *
 *   >>> p,q,e,m = 61,53,17,65
 *   >>> n=p*q; phi=(p-1)*(q-1); d=pow(e,-1,phi)
 *   >>> n,phi,d            # (3233, 3120, 2753)
 *   >>> pow(m,e,n)         # 2790
 *   >>> pow(2790,d,n)      # 65
 *
 * The test ALSO recomputes c = mᵉ mod n with an independent in-test BigInt
 * modpow, so it can't drift even if the literal 2790 were mis-transcribed.
 * Values are compared by BigInt VALUE (not raw bytes): a decrypted m may
 * carry leading-zero width the original lacked.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildRsaSpec } from "@/ciphers/rsa";
import { bigIntToBytes, bytesToBigInt } from "@/core/big-int-codec";
import { runSpec } from "@/core/runtime";
import type { Trace } from "@/core/types";
import { modInverseBigInt } from "@/steps/mod-inverse";
import { describe, expect, it } from "vitest";

const W = 2; // working width used by the default spec (n < 65536)
const registry = buildDefaultRegistry();
const specs = { encrypt: buildRsaSpec("encrypt", W), decrypt: buildRsaSpec("decrypt", W) } as const;

/** Independent oracle: modular exponentiation by squaring over BigInt. */
const modPow = (base: bigint, exp: bigint, mod: bigint): bigint => {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
};

/** Run an RSA spec on a numeric message; return the trace + result value. */
const runRsa = (
  direction: "encrypt" | "decrypt",
  message: number,
): { trace: Trace; value: bigint } => {
  const trace = runSpec(specs[direction], registry, {
    initialState: { shape: "bytes", bytes: bigIntToBytes(BigInt(message), W) },
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes finalState");
  return { trace, value: bytesToBigInt(trace.finalState.bytes) };
};

/** Read a key-gen leaf's published output port as a BigInt. */
const frameOutValue = (trace: Trace, stepId: string): bigint => {
  const frame = trace.frames.find((f) => f.stepId === stepId);
  if (!frame) throw new Error(`no frame for stepId "${stepId}"`);
  const out = frame.portOutputs?.get("output");
  if (out === undefined) throw new Error(`frame "${stepId}" has no output port`);
  return bytesToBigInt(out);
};

describe("RSA key generation (traced)", () => {
  it("derives n = p·q = 3233 from the default p=61, q=53", () => {
    const { trace } = runRsa("encrypt", 65);
    expect(frameOutValue(trace, "n")).toBe(3233n);
  });

  it("derives φ(n) = (p-1)(q-1) = 3120", () => {
    const { trace } = runRsa("encrypt", 65);
    expect(frameOutValue(trace, "phi")).toBe(3120n);
  });

  it("derives d = e⁻¹ mod φ = 2753 (matches Python pow(17,-1,3120))", () => {
    const { trace } = runRsa("decrypt", 2790);
    expect(frameOutValue(trace, "d")).toBe(2753n);
  });

  it("modInverseBigInt(17, 3120) === 2753 and inverts back to 1", () => {
    const d = modInverseBigInt(17n, 3120n);
    expect(d).toBe(2753n);
    expect((17n * d) % 3120n).toBe(1n);
  });

  it("throws when e shares a factor with φ (gcd ≠ 1)", () => {
    // gcd(6, 3120) = 6 ≠ 1 → 6 has no inverse mod 3120.
    expect(() => modInverseBigInt(6n, 3120n)).toThrow(/not invertible/);
  });
});

describe("RSA encryption / decryption (KAT)", () => {
  it("encrypts m=65 to c=2790 (= pow(65,17,3233), Python-verified)", () => {
    const { value } = runRsa("encrypt", 65);
    expect(value).toBe(2790n);
    // Cross-check against the independent in-test oracle.
    expect(value).toBe(modPow(65n, 17n, 3233n));
  });

  it("decrypts c=2790 back to m=65", () => {
    const { value } = runRsa("decrypt", 2790);
    expect(value).toBe(65n);
  });

  it("round-trips every message m in 0..3232 (= [0, n)) by VALUE", () => {
    // Exhaustive over the residue ring is cheap at this size and proves the
    // ladder + key-gen agree with real RSA for every representable message.
    for (let m = 0; m < 3233; m++) {
      const c = runRsa("encrypt", m).value;
      expect(c).toBe(modPow(BigInt(m), 17n, 3233n));
      const back = runRsa("decrypt", Number(c)).value;
      expect(back).toBe(BigInt(m));
    }
  });
});
