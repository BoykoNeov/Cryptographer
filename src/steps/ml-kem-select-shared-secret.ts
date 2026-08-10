/**
 * ml-kem.select-shared-secret — implicit rejection (FIPS 203 §7.3, Algorithm 18).
 *
 * Four input ports — `ciphertext` (the `c` that arrived), `reencryption` (the
 * `c′` decapsulation computed for itself), `shared` (`K′`, from `G`) and
 * `rejection` (`K̄`, from `J`) — and one 32-byte `output`.
 *
 * ## Why this is a step type and not an `if`
 *
 * The specification writes it as a branch:
 *
 * ```
 *     if c ≠ c′ then K′ ← K̄
 * ```
 *
 * A `CipherSpec` is a straight-line tree of steps, groups and iterates; there is
 * no branch node, and there is deliberately not going to be one. That constraint
 * turns out to agree with how the algorithm must actually be implemented.
 *
 * **A real decapsulation does not branch here either.** Both secrets are
 * computed every single time, and one of them is selected by arithmetic on a
 * mask derived from the comparison. If the code branched, the branch would be
 * observable — through timing, through the instruction cache, through power
 * draw — and an attacker who can see *whether* a ciphertext was rejected can
 * mount the very chosen-ciphertext attack this whole construction exists to
 * stop. So a select is not a workaround for a missing primitive; it is the
 * honest depiction, and the executor below is written the same branchless way
 * the specification's implementors are required to write it.
 *
 * ## What the comparison is defending
 *
 * K-PKE decryption never fails. Hand it any 1088 bytes and it returns *some*
 * 32-byte message. An attacker exploits that by submitting ciphertexts they
 * built by hand — slightly malformed ones, each of which leaks a little about
 * the secret key through whether it decrypts "successfully".
 *
 * The Fujisaki–Okamoto transform closes it: re-run encryption on the message
 * that came out, using randomness derived from that same message, and check you
 * get the ciphertext you were given. A hand-built ciphertext cannot survive
 * that, because its author would have to know the message in advance to derive
 * the right randomness.
 *
 * And when the check fails, decapsulation does not report an error. It returns
 * a different shared secret — derived from `z`, a secret held only by the key's
 * owner, and from the ciphertext that failed. The attacker gets 32 bytes that
 * look exactly like a real shared secret, cannot distinguish them from one, and
 * learns nothing. That is what "implicit" means.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. No params — the two
 * things it needs to know (which ciphertext arrived, which was recomputed) are
 * wired, not configured.
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

const STEP = "ml-kem.select-shared-secret";

/** ML-KEM's shared secret is 32 bytes at every parameter set. */
export const SHARED_SECRET_BYTES = 32;

export const mlKemSelectSharedSecretPortContract: PortContract = {
  inputs: new Map([
    ["ciphertext", { layout: "raw" }],
    ["reencryption", { layout: "raw" }],
    ["shared", { layout: "raw", byteLength: SHARED_SECRET_BYTES }],
    ["rejection", { layout: "raw", byteLength: SHARED_SECRET_BYTES }],
  ]),
  outputs: new Map([["output", { layout: "raw", byteLength: SHARED_SECRET_BYTES }]]),
};

/**
 * Constant-time compare-and-select.
 *
 * `diff` accumulates the OR of every byte difference, so it is zero exactly
 * when the two ciphertexts are equal, and the loop's cost does not depend on
 * where the first difference lies. `mask` is then all-ones on a match and
 * all-zeroes otherwise, and both candidate secrets are read on every path.
 *
 * A length mismatch is a wiring error rather than a rejection: it means the two
 * ports were bound to values that could not have come from the same scheme, so
 * it throws instead of quietly reporting "different".
 */
export const mlKemSelectSharedSecret: PortedExecutor = (inputs, _params, _ctx) => {
  const c = inputs.get("ciphertext");
  const cPrime = inputs.get("reencryption");
  const shared = inputs.get("shared");
  const rejection = inputs.get("rejection");

  if (c === undefined || cPrime === undefined || shared === undefined || rejection === undefined) {
    throw new Error(
      `${STEP}: requires the "ciphertext", "reencryption", "shared" and "rejection" ports`,
    );
  }
  if (c.length !== cPrime.length) {
    throw new Error(
      `${STEP}: the received ciphertext (${c.length} bytes) and the re-encryption (${cPrime.length} bytes) must be the same length`,
    );
  }
  if (shared.length !== SHARED_SECRET_BYTES || rejection.length !== SHARED_SECRET_BYTES) {
    throw new Error(
      `${STEP}: both candidate secrets must be ${SHARED_SECRET_BYTES} bytes (got ${shared.length} and ${rejection.length})`,
    );
  }

  let diff = 0;
  for (let i = 0; i < c.length; i++) {
    diff |= (c[i] as number) ^ (cPrime[i] as number);
  }
  // 0 → 0xff (equal, keep K′); anything else → 0x00 (reject, take K̄).
  const mask = ((diff - 1) >> 8) & 0xff;

  const out = new Uint8Array(SHARED_SECRET_BYTES);
  for (let i = 0; i < SHARED_SECRET_BYTES; i++) {
    out[i] = ((shared[i] as number) & mask) | ((rejection[i] as number) & ~mask & 0xff);
  }
  return new Map([["output", out]]);
};

export const mlKemSelectSharedSecretDoc: StepDocumentation = {
  name: "Implicit rejection — pick the real secret or the fake one",
  summary:
    "Compares the ciphertext that arrived against the one decapsulation recomputed, and returns either the real shared secret or an undetectable decoy. Never reports an error.",
  detail: `# Implicit rejection

Decapsulation has just done something that looks redundant: it decrypted the
ciphertext, then **encrypted the result again** and got a second ciphertext.
This step compares the two.

- **They match** → the ciphertext was honestly produced, and the real shared
  secret \`K′\` comes out.
- **They differ** → out comes \`K̄\`, a different 32 bytes derived from the
  secret value \`z\` and from the ciphertext that failed.

## Why not just return an error?

Because the error would be the attack.

The encryption scheme underneath ML-KEM never fails. Feed it any 1088 bytes and
it returns *some* 32-byte message. An attacker exploits that by submitting
ciphertexts they crafted rather than ones they encrypted — each one a probe, and
each answer of "that worked" or "that failed" leaking a little about the private
key. Enough probes recover it.

Returning a plausible fake secret removes the answer. The attacker gets 32
uniform-looking bytes and no way to tell them from a genuine shared secret; they
find out only when the session they are impersonating fails to agree on a key,
long after they could have learned anything from it. That is what **implicit**
rejection means — the rejection is never announced.

## Why the decoy has to depend on both z and c

\`K̄ = J(z ‖ c)\`.

The \`z\` half is a 32-byte secret generated with the key pair and never
published. Without it the attacker could compute the fake secret themselves and
so recognise a rejection. The \`c\` half makes every failed ciphertext produce a
*different* decoy — otherwise the same 32 bytes coming back twice would announce
"both of those were rejected".

## No branch, on purpose

There is no \`if\` here even in a real implementation. Both secrets are computed
every time and one is selected with a mask, so that nothing about the timing,
the memory access pattern or the power draw reveals which path was taken. A
branch would leak the one bit this whole construction is built to hide.

This is also the single step that separates the IND-CPA scheme underneath from
the IND-CCA KEM on top: everything before it is the textbook encryption, and
this is the part that makes it safe to let strangers send you ciphertexts.`,
  params: new Map(),
  references: [
    "FIPS 203 Algorithm 18 — ML-KEM.Decaps_internal (steps 7–10)",
    "FIPS 203 §3.3 — implicit rejection and the Fujisaki–Okamoto transform",
    "Hofheinz, Hövelmanns & Kiltz (2017) — A Modular Analysis of the Fujisaki-Okamoto Transformation",
  ],
};
