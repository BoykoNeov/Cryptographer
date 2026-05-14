import type { Json, MatrixState, StepDocumentation, StepExecutor } from "../core/types";

/**
 * XOR a 16-byte round key (read from aux) into the state matrix, byte-wise.
 *
 * params: { auxName: string }
 *   The named aux entry must be a Uint8Array of length 16.
 */
export const addRoundKey: StepExecutor = (state, params, ctx) => {
  if (state.shape !== "matrix4x4-bytes") {
    throw new Error("add-round-key expects matrix4x4-bytes state");
  }
  const auxName = readAuxName(params);
  const rk = ctx.aux.get(auxName);
  if (!(rk instanceof Uint8Array) || rk.length !== 16) {
    throw new Error(`aux '${auxName}' must be a 16-byte Uint8Array`);
  }
  const next = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    next[i] = (state.bytes[i] ?? 0) ^ (rk[i] ?? 0);
  }
  const result: MatrixState = { shape: "matrix4x4-bytes", bytes: next };
  return { state: result, auxReads: [auxName] };
};

// ─── Documentation ────────────────────────────────────────────────────────

export const addRoundKeyDoc: StepDocumentation = {
  name: "Add Round Key",
  summary: "XOR a 16-byte round key (read from aux) into the state.",
  detail: `## Add Round Key

The state is **bitwise XOR**ed with a 16-byte round key. The round key is
read from the named aux entry — typically one of the values produced by
the key expansion step (\`roundKey.0\`, \`roundKey.1\`, …).

XOR is its own inverse: applying the same key twice cancels out. This is
why decryption uses the same AddRoundKey step as encryption, just with
the round keys consumed in reverse order.

**Why it matters:** this is where the secret key actually mixes into the
cipher's state. SubBytes / ShiftRows / MixColumns are *publicly known*
transformations — without AddRoundKey, anyone could undo them. The
round key XOR is what makes each round depend on the secret.

**Position in the round matters.** Forward AES does AddRoundKey **after**
MixColumns. The inverse cipher does AddRoundKey **before** InvMixColumns
inside each round, because XOR and matrix multiplication don't commute.
(There's also an "equivalent inverse cipher" that restores symmetry by
transforming the round keys instead — useful for hardware but it
obscures what's happening.)`,
  params: new Map([
    [
      "auxName",
      'Name of the aux entry containing the 16-byte key to XOR in. Typically "roundKey.N".',
    ],
  ]),
  references: ["FIPS-197 §5.1.4 (AddRoundKey)"],
  shapeContract: { input: "matrix4x4-bytes", output: "preserveInput" },
};

const readAuxName = (params: Json): string => {
  if (
    typeof params !== "object" ||
    params === null ||
    Array.isArray(params) ||
    !("auxName" in params)
  ) {
    throw new Error("add-round-key requires params.auxName");
  }
  const auxName = (params as { auxName: unknown }).auxName;
  if (typeof auxName !== "string") {
    throw new Error("auxName must be a string");
  }
  return auxName;
};
