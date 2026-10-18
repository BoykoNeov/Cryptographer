/**
 * ml-dsa.hash-h — ML-DSA's `H`, which is SHAKE256 squeezed to a chosen length
 * (FIPS 204 §3.7).
 *
 * One input port `input`, one output port `output` of `outBytes` bytes.
 *
 * ## One function, five jobs, told apart by length
 *
 * ML-DSA calls `H` everywhere, and what the output MEANS differs at every call
 * site. The lengths are the quickest way to tell them apart:
 *
 * | call | output | what it is |
 * |---|---|---|
 * | `H(ξ ‖ k ‖ l, 128)` | 128 | split into ρ (32), ρ′ (64), K (32) |
 * | `H(pk, 64)` | 64 | tr, a fingerprint of the public key |
 * | `H(tr ‖ M′, 64)` | 64 | μ, the message representative |
 * | `H(K ‖ rnd ‖ μ, 64)` | 64 | ρ″, the seed for the masks |
 * | `H(μ ‖ w1Encode(w1), λ/4)` | 32 | c̃, the commitment hash |
 *
 * Callers split the output with a visible `split-bytes@1` where it has parts,
 * for the reason ML-KEM's `G` gives: what the parts mean is the call site's
 * business, and the canvas should say so.
 *
 * ## A cross-reference monolith
 *
 * The sponge is the one under **Hash → SHAKE256**, fully traced; it collapses
 * to one frame here for volume. `keccak-compute.ts` drives the same step
 * executors that trace walks, pinned against `node:crypto`. See
 * `ml-kem-hash-g.ts` for the longer note on this kind of monolith.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { shake256 } from "../ciphers/keccak-compute";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { readZqBitWidth } from "../core/zq-vector";

const STEP = "ml-dsa.hash-h";

/** Output length. 4096 is far past any call in the standard (the longest is 128). */
const readOutBytes = (params: Json): number => readZqBitWidth(params, STEP, "outBytes", 4096);

export const mlDsaHashHPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: (params: Json) =>
    new Map([["output", { layout: "raw" as const, byteLength: readOutBytes(params) }]]),
};

export const mlDsaHashH: PortedExecutor = (inputs, params, _ctx) => {
  const outBytes = readOutBytes(params);
  const input = inputs.get("input");
  if (input === undefined) throw new Error(`${STEP}: missing required input port "input"`);
  return new Map([["output", shake256(input, outBytes)]]);
};

export const mlDsaHashHDoc: StepDocumentation = {
  name: "H — SHAKE256 to a chosen length",
  summary:
    "ML-DSA's all-purpose hash: SHAKE256 over the input, squeezed to however many bytes this call site needs.",
  detail: `# H — SHAKE256

ML-DSA's hash function. It is plain **SHAKE256**, squeezed to whatever length
the caller asks for — and ML-DSA asks for five different things:

- **128 bytes** over the 32-byte key seed and \`k ‖ l\`: ρ, ρ′ and K — the
  public seed, the secret seed and a signing key.
- **64 bytes** over the public key: **tr**, a fingerprint of the public key.
- **64 bytes** over tr and the formatted message: **μ**, what actually gets
  signed.
- **64 bytes** over K, the randomness and μ: **ρ″**, the seed for this
  signature's masks.
- **32 bytes** over μ and the packed commitment: **c̃**, the commitment hash
  in the signature.

The same function serves all of them. What changes is what the bytes are
for, which is why any splitting into parts happens in a separate, visible
step after this one.

## Why fold the public key into the message hash

μ is computed from tr — a hash of the public key — and the message, never from
the message alone. That ties every signature to one specific public key, so a
signature cannot be lifted and presented as valid under a different key.

## The same sponge as Hash → SHAKE256

Collapsed to one frame here. Select **SHAKE256** under **Hash** to watch the
same sponge run round by round.`,
  params: new Map([
    [
      "outBytes",
      "How many bytes to squeeze: 128 for the key-seed expansion, 64 for tr, μ and ρ″, 32 for the commitment hash c̃.",
    ],
  ]),
  references: ["FIPS 204 §3.7 — H(str, ℓ) = SHAKE256(str, 8ℓ)", "FIPS 202 §6.2 — SHAKE256"],
};
