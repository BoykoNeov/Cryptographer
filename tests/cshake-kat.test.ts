/**
 * cSHAKE128 / cSHAKE256 known-answer-test gate (NIST SP 800-185 §3.3),
 * 2026-07-13.
 *
 * `node:crypto` has **no cSHAKE**, so the oracle here is the independent
 * reference in `M:\claud_projects\temp\cshake-kmac-ref\ref.py` — a from-scratch
 * Keccak sponge that agrees byte-for-byte with pycryptodome AND the NIST
 * SP 800-185 published cSHAKE samples (three-source agreement). Vectors below
 * were emitted from that reference.
 *
 * Coverage:
 *   1. The four NIST published cSHAKE samples (exact hex).
 *   2. Output-length sweep straddling the rate boundary — the customized
 *      squeeze loop (domain 0x04) is otherwise untestable against node:crypto.
 *   3. Empty N and S ⇒ cSHAKE **is** SHAKE (domain 0x1F) — cross-checked against
 *      node:crypto's shake128/256.
 *   4. Customization sensitivity — a one-byte change to S changes every output
 *      byte.
 *   5. Squeeze-block-count structural pins.
 */

import { createHash } from "node:crypto";
import { type CshakeVariant, buildCshakeSpec } from "@/ciphers/cshake";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

const cshakeHex = (
  variant: CshakeVariant,
  message: Uint8Array,
  N: Uint8Array,
  S: Uint8Array,
  outputLength: number,
): string => {
  const trace = runSpec(buildCshakeSpec(variant, N, S, outputLength), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: message },
  });
  if (trace.finalState.shape !== "bytes") {
    throw new Error(`expected bytes finalState, got ${trace.finalState.shape}`);
  }
  return bytesToHex(trace.finalState.bytes);
};

// The count of `squeeze.perm.{j}` groups — the structural signature of the
// unrolled squeeze loop.
const squeezePermCount = (spec: CipherSpec): number =>
  spec.steps.filter((n) => n.kind === "group" && n.id.startsWith("squeeze.perm.")).length;

// ─── Reference vectors (emitted from the validated python reference) ────────

type Vec = { variant: CshakeVariant; S: string; dataLen: number; outLen: number; out: string };

// data = 0,1,…,dataLen-1 ; N = "" ; S as given.
const seq = (len: number): Uint8Array => new Uint8Array(Array.from({ length: len }, (_, i) => i));

const VECTORS: Vec[] = [
  // NIST SP 800-185 published cSHAKE samples #1-4
  {
    variant: "cshake128",
    S: "Email Signature",
    dataLen: 4,
    outLen: 32,
    out: "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5",
  },
  {
    variant: "cshake128",
    S: "Email Signature",
    dataLen: 200,
    outLen: 32,
    out: "c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b",
  },
  {
    variant: "cshake256",
    S: "Email Signature",
    dataLen: 4,
    outLen: 64,
    out: "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c",
  },
  {
    variant: "cshake256",
    S: "Email Signature",
    dataLen: 200,
    outLen: 64,
    out: "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb",
  },
  // cSHAKE128 output-length sweep (squeeze loop engages past 168)
  { variant: "cshake128", S: "Email Signature", dataLen: 4, outLen: 1, out: "c1" },
  {
    variant: "cshake128",
    S: "Email Signature",
    dataLen: 4,
    outLen: 168,
    out: "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf59cbce830079c452abdeb875366a49ebfe75b89ef17396e34898e904830b0e136f192cc062bd2e116a07fe6eb9b4fc9ba254d7dbf6ec9860c5ba38686ea294dd772c1fad20e4214aad5394a267101e4c9d09ce80281db7e9170d6052abe6e5a935713e2c62365f59c9a7df5a98e4040ff70e85060107f596acdbf876e678d73f2d4494302226219ac",
  },
  {
    variant: "cshake128",
    S: "Email Signature",
    dataLen: 4,
    outLen: 169,
    out: "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf59cbce830079c452abdeb875366a49ebfe75b89ef17396e34898e904830b0e136f192cc062bd2e116a07fe6eb9b4fc9ba254d7dbf6ec9860c5ba38686ea294dd772c1fad20e4214aad5394a267101e4c9d09ce80281db7e9170d6052abe6e5a935713e2c62365f59c9a7df5a98e4040ff70e85060107f596acdbf876e678d73f2d4494302226219acbf",
  },
  {
    variant: "cshake128",
    S: "Email Signature",
    dataLen: 4,
    outLen: 337,
    out: "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf59cbce830079c452abdeb875366a49ebfe75b89ef17396e34898e904830b0e136f192cc062bd2e116a07fe6eb9b4fc9ba254d7dbf6ec9860c5ba38686ea294dd772c1fad20e4214aad5394a267101e4c9d09ce80281db7e9170d6052abe6e5a935713e2c62365f59c9a7df5a98e4040ff70e85060107f596acdbf876e678d73f2d4494302226219acbf98d70486aff1d5bbb1d5162e0209b5afcc7a07294a530945c3bc0b351a0577cadae684f050f7e8a5853a086acbced4b1c9e98d96cb1df66273e43fefede4baf40fb954182618a4e909478b0f8efe5b1f4c4cc157142084764532b31ec51cc988ab664d0aa51454fb9732fc5ed32a8aaed3f49cd79db21ca71a0f5e766eb8846ca64705a4621ac83d23d91ceb1958d3b26a1def4a18d6a83c73c2db7079281023743f4d627d05cd8e",
  },
  // cSHAKE256 output-length sweep (S = "tag")
  { variant: "cshake256", S: "tag", dataLen: 4, outLen: 1, out: "0e" },
  {
    variant: "cshake256",
    S: "tag",
    dataLen: 4,
    outLen: 136,
    out: "0e4c0698193bd9ff213f61ff1b77ad59e791c50af8757c3b034433e067ee3c7f3a2f511d72492403b3c666e27423cfa1df85fc835e9bd0ab7825b117b5ff0cf86a6f2eafafb9d2e7a189c3d5fafec100d13e6f0fa7c3c853f2bb48534df47aab5260e483bb4404f9814b89963a48e2a1bea167d94d7c9b0506af896ec942cfed84c5444bc26e9b35",
  },
  {
    variant: "cshake256",
    S: "tag",
    dataLen: 4,
    outLen: 137,
    out: "0e4c0698193bd9ff213f61ff1b77ad59e791c50af8757c3b034433e067ee3c7f3a2f511d72492403b3c666e27423cfa1df85fc835e9bd0ab7825b117b5ff0cf86a6f2eafafb9d2e7a189c3d5fafec100d13e6f0fa7c3c853f2bb48534df47aab5260e483bb4404f9814b89963a48e2a1bea167d94d7c9b0506af896ec942cfed84c5444bc26e9b3541",
  },
];

describe("cSHAKE — reference known-answer vectors", () => {
  for (const v of VECTORS) {
    it(`${v.variant} S="${v.S}" data[${v.dataLen}] @ ${v.outLen}`, () => {
      expect(cshakeHex(v.variant, seq(v.dataLen), new Uint8Array(0), enc(v.S), v.outLen)).toBe(
        v.out,
      );
    });
  }
});

// ─── Empty N and S ⇒ cSHAKE is SHAKE (domain 0x1F) ──────────────────────────

describe("cSHAKE — empty customization reduces to SHAKE", () => {
  const nodeShake = (variant: "shake128" | "shake256", msg: Uint8Array, outLen: number): string =>
    bytesToHex(new Uint8Array(createHash(variant, { outputLength: outLen }).update(msg).digest()));

  for (const [cv, sv] of [
    ["cshake128", "shake128"],
    ["cshake256", "shake256"],
  ] as const) {
    it(`${cv}(X, "", "") == ${sv}(X) across message + output lengths`, () => {
      for (const msgLen of [0, 3, 200]) {
        for (const outLen of [16, 32, 200]) {
          const msg = seq(msgLen);
          expect(cshakeHex(cv, msg, new Uint8Array(0), new Uint8Array(0), outLen)).toBe(
            nodeShake(sv, msg, outLen),
          );
        }
      }
    });
  }
});

// ─── Customization sensitivity ──────────────────────────────────────────────

describe("cSHAKE — customization string changes the output", () => {
  it("a one-byte change to S produces unrelated output", () => {
    const msg = seq(4);
    const a = cshakeHex("cshake128", msg, new Uint8Array(0), enc("tag"), 32);
    const b = cshakeHex("cshake128", msg, new Uint8Array(0), enc("tah"), 32);
    expect(a).not.toBe(b);
  });

  it("customized (non-empty S) differs from the SHAKE reduction", () => {
    const msg = seq(4);
    const customized = cshakeHex("cshake128", msg, new Uint8Array(0), enc("tag"), 32);
    const reduced = cshakeHex("cshake128", msg, new Uint8Array(0), new Uint8Array(0), 32);
    expect(customized).not.toBe(reduced);
  });
});

// ─── Squeeze-block-count structural pins ────────────────────────────────────

describe("cSHAKE — unrolled squeeze grows with output length", () => {
  it("cshake128: ≤168 → 0 extra perms, 169 → 1, 337 → 2", () => {
    const N = new Uint8Array(0);
    const S = enc("Email Signature");
    expect(squeezePermCount(buildCshakeSpec("cshake128", N, S, 168))).toBe(0);
    expect(squeezePermCount(buildCshakeSpec("cshake128", N, S, 169))).toBe(1);
    expect(squeezePermCount(buildCshakeSpec("cshake128", N, S, 337))).toBe(2);
  });
});
