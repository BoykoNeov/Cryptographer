/**
 * ml-kem.hash-h — ML-KEM's `H`, which is SHA3-256 (FIPS 203 §4.1).
 *
 * One input port `input`, one output port `output` carrying 32 bytes.
 *
 * ## Why a separate step type from `ml-kem.hash-g@1`
 *
 * They are the same construction at different rates, and a single step with a
 * `digestBytes` param would be smaller code. It is deliberately not written that
 * way: `G` and `H` are different *names* in FIPS 203, used at different places
 * for different reasons, and a trace that showed "hash (32)" and "hash (64)"
 * would make the reader work out which was which. The specification's own
 * vocabulary is the thing worth preserving on the canvas.
 *
 * ## What `H` is for
 *
 * Binding, not secrecy. `H(ek)` is stored inside the decapsulation key so that
 * decapsulation can recompute `G(m′ ‖ H(ek))` without being handed the
 * encapsulation key separately — it is what ties a ciphertext to one specific
 * public key. `H(c)` appears in the implicit-rejection branch for the same
 * reason: the rejection secret must depend on the ciphertext that failed.
 *
 * See `ml-kem-hash-g.ts` for the "cross-reference monolith" note that applies to
 * this whole family, and `src/ciphers/keccak-compute.ts` for why this is the
 * same sponge as the one under the Hash selector rather than a second copy.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { sha3_256 } from "../ciphers/keccak-compute";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

const STEP = "ml-kem.hash-h";

export const mlKemHashHPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw", byteLength: 32 }]]),
};

export const mlKemHashH: PortedExecutor = (inputs, _params, _ctx) => {
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error(`${STEP}: requires an "input" port`);
  }
  return new Map([["output", sha3_256(input)]]);
};

export const mlKemHashHDoc: StepDocumentation = {
  name: "H — hash to 32 bytes (SHA3-256)",
  summary:
    "SHA3-256, collapsed to one frame. Used to bind a ciphertext to one specific public key, not to keep anything secret.",
  detail: `# H — hash to 32 bytes

Plain **SHA3-256**. Thirty-two bytes out, whatever goes in.

## What it is for here

Binding, not secrecy — everything it hashes is public.

\`H(ek)\` is stored inside the decapsulation key. Decapsulation needs it to
recompute \`G(m′ ‖ H(ek))\` and check that the ciphertext it was given really
does correspond to *this* key pair. Without that tie, a ciphertext made for one
public key could be replayed against another.

\`H(c)\` plays the same role in the rejection branch: when decapsulation fails,
the fake secret it returns has to depend on the exact ciphertext that failed, or
an attacker could tell two failures apart.

## The same sponge, one frame

Identical to the construction under **Hash → SHA3-256** in the algorithm
selector, where it is drawn out into 216 visible frames. It is one frame here
only because ML-KEM calls a sponge about seventeen times per key generation and
the polynomial arithmetic — the part this algorithm is actually about — would
disappear underneath.`,
  params: new Map(),
  references: [
    "FIPS 203 §4.1 — H is SHA3-256",
    "FIPS 203 Algorithm 16 — ML-KEM.KeyGen_internal, where H(ek) enters the decapsulation key",
    "FIPS 202 §6.1 — SHA3-256",
  ],
};
