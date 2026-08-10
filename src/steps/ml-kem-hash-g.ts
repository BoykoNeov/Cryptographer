/**
 * ml-kem.hash-g — ML-KEM's `G`, which is SHA3-512 (FIPS 203 §4.1).
 *
 * One input port `input`, one output port `output` carrying 64 bytes. Callers
 * split those 64 bytes into two 32-byte halves with a visible `split-bytes@1`,
 * because what the halves MEAN differs by call site and the spec should say so
 * on the canvas rather than inside this executor.
 *
 * ## What kind of monolith this is — say it out loud
 *
 * This app has met two kinds of opaque step before. `blowfish.key-schedule@1` is
 * the "no legible decomposition" kind: it runs a cipher on itself 521 times and
 * there is nothing useful to look at. `mt19937.twist@1` is the "structurally
 * inexpressible" kind: it reads three words where an iterate body can see one.
 *
 * This is a **third kind, and the difference matters: a cross-reference.** The
 * sponge underneath is not hidden and it is not unshowable — it is one dropdown
 * away, fully decomposed into 216 frames, under Hash → SHA3-256. It collapses to
 * a single frame here only because ML-KEM makes roughly seventeen sponge calls
 * per key generation, and 240 spec nodes apiece is ~4,080 nodes of canvas before
 * a single coefficient has been multiplied.
 *
 * So the description below names the exact function and rate and points at the
 * selector entry. Prose that read like Blowfish's would be a lie.
 *
 * ## It is the same sponge, mechanically and not just morally
 *
 * `keccakSponge` drives the **same nine step executors** the runtime calls when
 * it walks a SHA3-256 spec, with the same constants out of `keccak-f.ts`. See
 * `src/ciphers/keccak-compute.ts`; `tests/keccak-compute.test.ts` pins it against
 * both `node:crypto` and the app's own traced spec, so the one-frame form cannot
 * drift from the one the learner watches.
 *
 * ## Where `G` is used, and why both uses are one step
 *
 * K-PKE key generation calls `G(d ‖ k)` and splits the result into `(ρ, σ)` — a
 * public seed that generates the matrix and a secret seed that generates the
 * noise. Encapsulation calls `G(m ‖ H(ek))` and splits it into `(K, r)` — the
 * shared secret and the encryption randomness. Same function, two entirely
 * different pairs of meanings, which is exactly why the split lives outside.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. Port lengths are
 * wiring-determined, except the output, which SHA3-512 fixes at 64 bytes.
 */

import { sha3_512 } from "../ciphers/keccak-compute";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

const STEP = "ml-kem.hash-g";

export const mlKemHashGPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw", byteLength: 64 }]]),
};

export const mlKemHashG: PortedExecutor = (inputs, _params, _ctx) => {
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error(`${STEP}: requires an "input" port`);
  }
  return new Map([["output", sha3_512(input)]]);
};

export const mlKemHashGDoc: StepDocumentation = {
  name: "G — hash to two seeds (SHA3-512)",
  summary:
    "SHA3-512, collapsed to one frame. Its 64 bytes are always split into two 32-byte halves whose meaning depends on the caller.",
  detail: `# G — hash to two seeds

Hashes its input with **SHA3-512** and produces 64 bytes, which the caller always
cuts into two 32-byte halves.

## Two call sites, two completely different pairs

| called as | halves mean |
|---|---|
| \`G(d ‖ k)\` in key generation | \`ρ\` — public, generates the matrix<br>\`σ\` — secret, generates the noise |
| \`G(m ‖ H(ek))\` in encapsulation | \`K\` — the shared secret<br>\`r\` — the encryption randomness |

That is why the split is a separate step you can see rather than something this
one does. The bytes are just bytes; what makes half of them public and half of
them secret is what the next step does with them.

The first case is the one that makes a whole key pair reproducible from a
32-byte seed: everything else in key generation is deterministic, so \`d\` is
the key pair.

## This is the same sponge you can watch

This step is one frame, but the function inside it is not hidden. Select
**Hash → SHA3-256** and you will see the identical construction opened out into
216 frames: θ, ρ, π, χ, ι, twenty-four times, with the state visible at every
step. SHA3-512 differs from it only in absorbing 72 bytes per permutation
instead of 136, and in squeezing 64 bytes out instead of 32.

It collapses to one frame here for a reason worth knowing: ML-KEM calls a sponge
about seventeen times per key generation. Drawn in full that is over four
thousand nodes on the canvas before a single polynomial coefficient has been
multiplied — the algorithm's actual subject would be invisible underneath its
own hashing.

Mechanically it really is the same code: this step drives the very same nine
executors the SHA-3 trace walks, with the same round constants.`,
  params: new Map(),
  references: [
    "FIPS 203 §4.1 — G is SHA3-512",
    "FIPS 203 Algorithm 13 — K-PKE.KeyGen, where G(d ‖ k) splits into (ρ, σ)",
    "FIPS 203 Algorithm 17 — ML-KEM.Encaps, where G(m ‖ H(ek)) splits into (K, r)",
    "FIPS 202 §6.1 — SHA3-512",
  ],
};
