/**
 * Serpent Linear Transform — standard-form (table-based) version.
 *
 * Each of the 128 output bits is the XOR of a small set of input bits;
 * `SERPENT_LT_TABLE[i]` lists the input bit positions to XOR for output
 * bit `i`. The transform mixes the 128 state bits non-trivially, providing
 * the diffusion that complements the per-nibble S-box layer's non-linearity.
 *
 * Two equivalent formulations of Serpent's LT exist in the literature:
 *
 *   - **Table form** (this file): operates on the bitstream view of the
 *     state, applied AFTER the Initial Permutation. Each output bit is a
 *     XOR-sum of input bits per a fixed table.
 *   - **Word form** (rotations + shifts + XORs on 4 × 32-bit words):
 *     operates on the un-permuted state, with no IP/FP. The published
 *     equations in Anderson/Biham/Knudsen are this version.
 *
 * Both produce the SAME final ciphertext when paired with their matching
 * per-nibble vs. column-wise S-box. They are NOT interchangeable when
 * applied to the same input — they live in different "domains."
 *
 * Since this implementation runs in standard form (with explicit IP/FP
 * and a per-nibble S-box), the table form is the correct LT.
 */

import { SERPENT_LT_TABLE } from "../ciphers/serpent-constants";
import type { BytesState, StepDocumentation, StepExecutor } from "../core/types";
import { readBit, writeBit } from "./serpent-bit-ops";

export const serpentLinearTransform: StepExecutor = (state) => {
  if (state.shape !== "bytes") {
    throw new Error("serpent.linear-transform expects bytes state");
  }
  if (state.bytes.length !== 16) {
    throw new Error(
      `serpent.linear-transform expects 16-byte state; got ${state.bytes.length} bytes`,
    );
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 128; i++) {
    const sources = SERPENT_LT_TABLE[i] ?? [];
    let bit = 0;
    for (const src of sources) {
      bit ^= readBit(state.bytes, src);
    }
    writeBit(out, i, bit);
  }

  const result: BytesState = { shape: "bytes", bytes: out };
  return { state: result };
};

export const serpentLinearTransformDoc: StepDocumentation = {
  name: "Linear Transform (Serpent)",
  summary: "Diffuse the state: each output bit is the XOR of a few input bits per a fixed table.",
  detail: `## Linear Transform (Serpent, standard form)

Each of the 128 output bits is the XOR of a small set (2–7) of input bits.
The mapping from output bit position to input bit positions is a fixed
table embedded in the cipher specification (\`SERPENT_LT_TABLE\` in the
constants module).

\`\`\`
output_bit[i]  =  XOR over j in LT_TABLE[i] of  input_bit[j]
\`\`\`

This is the **diffusion layer** of Serpent. The S-box layer just before
it provides non-linearity — but a 4-bit S-box only mixes bits within each
nibble. Without diffusion, a single-bit difference in the plaintext would
only affect a few nibbles even after many rounds. The LT spreads each bit
of difference across the entire state within one round, so after a handful
of rounds every input bit has affected every output bit (the "avalanche"
property).

**Two equivalent formulations.** Production Serpent implementations
typically use the equivalent word-level formulation (rotations + shifts +
XORs across the 4 32-bit words of the state). The published equations in
the Anderson/Biham/Knudsen paper are:

\`\`\`
X0 = ROL(X0, 13);  X2 = ROL(X2, 3)
X1 = X1 XOR X0 XOR X2
X3 = X3 XOR X2 XOR (X0 << 3)
X1 = ROL(X1, 1);   X3 = ROL(X3, 7)
X0 = X0 XOR X1 XOR X3
X2 = X2 XOR X3 XOR (X1 << 7)
X0 = ROL(X0, 5);   X2 = ROL(X2, 22)
\`\`\`

That word form operates on the **un-permuted** state and pairs with a
column-wise (bitsliced) S-box. The two are equivalent through the IP/FP
boundary transforms, but they are not interchangeable mid-cipher.

**Applied 31 times per encryption.** Rounds 0..30 each include this LT
after their S-box layer. Round 31 (the final round) omits the LT and
instead applies an extra AddRoundKey with \`K_32\` — the same asymmetry
that AES uses to share structure between encryption and decryption.`,
  params: new Map(),
  references: [
    "Anderson, Biham, Knudsen 1998, §2 (Linear Transformation L), Appendix C (LT table)",
    "Serpent NIST submission, tstsubmtl/serpref.c (LT() function, LTTable[])",
  ],
};
