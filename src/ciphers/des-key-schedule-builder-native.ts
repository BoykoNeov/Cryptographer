/**
 * Byte-native DES key-schedule construction — key-schedule-decomposition
 * plan slice K4a (2026-06-02). The port-native replacement for the
 * monolithic `des.key-schedule@1` executor.
 *
 * **Why decompose.** The monolith ran the whole FIPS 46-3 §5 schedule
 * (PC-1 → 16 rounds of C/D left-rotations → PC-2 per round) inside ONE
 * executor — invisible to the trace. This builder expresses the same math
 * as a tree of port-native primitives so every sub-step is a scrubbable
 * frame, the same way `aes`/`speck`/`serpent-key-schedule-builder-native.ts`
 * (K1a/K2a/K3a) already do for the other three ciphers.
 *
 * **The punchline DES makes visible.** Unlike AES/Speck/Serpent (all ARX or
 * S-box driven), the DES key schedule contains NO arithmetic and NO S-box —
 * it is *pure bit-wiring*: two bit permutations (PC-1, PC-2) and a per-round
 * rotation of the two 28-bit halves. The decomposition shows that directly:
 * a `des.bit-permute@1` for PC-1, then 16 × (`des.rotate-halves@1` →
 * `des.bit-permute@1` PC-2), then the publish tail.
 *
 * **B-minimal (producer-only).** The schedule is visible; a single
 * meta-bearing `des.publish-round-keys@1` tail writes `aux["roundKey.0..15"]`
 * byte-identically to the monolith, so the round-body consumers
 * (`des.xor-with-K@1` reading `aux[roundKeyAux]`) and both shipped DES specs'
 * (`des.ts` + `des-decrypt.ts`) round arrangement stay UNTOUCHED.
 *
 * **No byte-order codec** (unlike K2/K3). DES uses FIPS MSB-first bit
 * numbering consistently throughout the schedule and the round body, so
 * there is no little-endian↔big-endian boundary to bridge. The 56-bit C‖D
 * register threads as a 7-byte buffer; the 48-bit round keys are 6 bytes.
 *
 * **The chained register.** PC-1 produces C₀‖D₀ (7 bytes). Round r reads the
 * previous round's rotated register, rotates by SHIFTS[r], and PC-2 selects
 * Kᵣ₊₁. So `roundKey.0 = K₁` (encrypt round 1's key), … `roundKey.15 = K₁₆`.
 */

import type { PortBinding, StepDocumentation, StepNode } from "../core/types";
import { DES_PC1, DES_PC2, DES_SHIFTS } from "./des-constants";

// ─── PortBinding + name helpers ───────────────────────────────────────────────

const port = (node: string, portName: string): PortBinding => ({ node, port: portName });
const ks = (suffix: string): string => `key-schedule.${suffix}`;

// ─── narrationOverride docs (FIPS 46-3 §5 friendly names) ─────────────────────
// One shared static doc per role (the op is identical every round; the
// per-round specifics — which shift, which bytes — are the frame's values).
// Mirrors the AES / Speck / Serpent key-schedule narration idiom.

const NARR_LOAD_KEY: StepDocumentation = {
  name: "Load master key",
  summary: "Load the 8-byte (64-bit) master key from aux to seed the schedule.",
  detail: `## Load master key

The DES master key (8 bytes / 64 bits) is read from \`aux["key"]\`. Eight of
those bits (positions 8, 16, …, 64) are historical parity bits that PC-1
drops immediately — DES is "really" keyed on 56 bits.`,
  references: ["FIPS 46-3 §5 (Key Schedule Calculation)"],
};

const NARR_PC1: StepDocumentation = {
  name: "PC-1 (drop parity, split into C₀ ‖ D₀)",
  summary: "Permuted Choice 1: 64 → 56 bits, dropping the 8 parity bits.",
  detail: `## PC-1 — Permuted Choice 1 (64 → 56)

Drops the 8 parity bits (key positions 8, 16, 24, 32, 40, 48, 56, 64 — never
referenced by the table) and reorders the surviving 56 bits into the two
28-bit halves C₀ (bits 1..28) and D₀ (bits 29..56). This is the only place
the parity bits are discarded; everything downstream works on the 56-bit
C‖D register.`,
  references: ["FIPS 46-3 §5 (Table PC-1)"],
};

const NARR_ROTATE = (round: number, shift: number): StepDocumentation => ({
  name: `Round ${round}: rotate C, D left by ${shift}`,
  summary: `Left-rotate both 28-bit halves by ${shift} bit${shift === 1 ? "" : "s"}.`,
  detail: `## Round ${round} — rotate C and D left by ${shift}

Both 28-bit halves of the key register rotate left by ${shift} bit${
    shift === 1 ? "" : "s"
  } (the FIPS shift schedule uses 1 for rounds 1, 2, 9, 16 and 2 otherwise).
The halves never mix — the rotation is the only inter-round movement of key
material. The 16 shifts sum to 28, so after round 16 the register has cycled
all the way back to C₀ ‖ D₀.`,
  references: ["FIPS 46-3 §5 (per-round left shifts)"],
});

const NARR_PC2 = (round: number): StepDocumentation => ({
  name: `Round ${round}: PC-2 → K${round}`,
  summary: `Permuted Choice 2: select 48 of the 56 C‖D bits as round key K${round}.`,
  detail: `## Round ${round} — PC-2 → K${round} (56 → 48)

Permuted Choice 2 selects 48 of the 56 bits of the freshly-rotated C‖D
register, in a fixed order, as this round's key K${round}. The 8 unselected
bits differ per round (a consequence of the rotation), which is what makes
each round key distinct. The result is 6 bytes (48 bits, MSB-first — 48
bits packs exactly into 6 bytes).`,
  references: ["FIPS 46-3 §5 (Table PC-2)"],
});

// ─── Builder ──────────────────────────────────────────────────────────────────

const DES_ROUND_KEY_COUNT = 16;
const DES_HALF_BITS = 28;

/**
 * Build the decomposed DES key schedule as a single (default-collapsed)
 * `key-schedule` group. Writes `aux["roundKey.0..15"]` via the
 * `des.publish-round-keys@1` tail — byte-identical to the legacy
 * `des.key-schedule@1` monolith.
 *
 * Takes no parameters: DES has no key-size variant (the 64-bit master key
 * always yields 16 round keys). The FIPS tables (PC-1, PC-2) and the shift
 * schedule are baked into the leaf params as fresh copies, so the spec is
 * self-contained for save/load and the user can pedagogically edit them.
 */
export function buildDesKeyScheduleNative(): StepNode {
  const children: StepNode[] = [];

  // ── Master-key load (8 raw bytes from aux). ───────────────────────────────
  children.push({
    kind: "step",
    id: ks("load-key"),
    type: "aux-load-bytes@1",
    params: { auxName: "key", byteLength: 8 },
    narrationOverride: NARR_LOAD_KEY,
  });

  // ── PC-1: 64 → 56 bits (drop parity, form C₀ ‖ D₀). ───────────────────────
  children.push({
    kind: "step",
    id: ks("pc1"),
    type: "des.bit-permute@1",
    params: { table: [...DES_PC1], outBits: 56 },
    portInputs: { input: port(ks("load-key"), "output") },
    narrationOverride: NARR_PC1,
  });

  // ── 16 rounds: rotate the C/D halves, then PC-2 → Kᵣ. ─────────────────────
  // The 7-byte C‖D register threads round to round; each round's PC-2 reads
  // the freshly-rotated register and publishes one 6-byte round key.
  const publishInputs: Record<string, PortBinding> = {};
  for (let r = 0; r < DES_ROUND_KEY_COUNT; r++) {
    const shift = DES_SHIFTS[r];
    if (shift === undefined) throw new Error(`buildDesKeyScheduleNative: DES_SHIFTS[${r}] missing`);

    // Rotate both halves. Round 0 seeds from PC-1; later rounds from the
    // previous round's rotated register (the register cycles through all 16).
    const rotateId = ks(`g${r}.rotate`);
    children.push({
      kind: "step",
      id: rotateId,
      type: "des.rotate-halves@1",
      params: { shift, halfBits: DES_HALF_BITS },
      portInputs: {
        input: r === 0 ? port(ks("pc1"), "output") : port(ks(`g${r - 1}.rotate`), "output"),
      },
      narrationOverride: NARR_ROTATE(r + 1, shift),
    });

    // PC-2: select 48 bits of the rotated C‖D as round key Kᵣ₊₁.
    const pc2Id = ks(`g${r}.pc2`);
    children.push({
      kind: "step",
      id: pc2Id,
      type: "des.bit-permute@1",
      params: { table: [...DES_PC2], outBits: 48 },
      portInputs: { input: port(rotateId, "output") },
      narrationOverride: NARR_PC2(r + 1),
    });
    publishInputs[`key${r}`] = port(pc2Id, "output");
  }

  // ── Publish tail (the one surviving meta): aux["roundKey.0..15"]. ─────────
  children.push({
    kind: "step",
    id: ks("publish"),
    type: "des.publish-round-keys@1",
    params: { outputPrefix: "roundKey", count: DES_ROUND_KEY_COUNT },
    portInputs: publishInputs,
  });

  return {
    kind: "group",
    id: "key-schedule",
    label: "Key Schedule",
    // Default-collapse so the ~50 schedule chips don't wall the canvas on
    // first graph render (same posture as AES/Speck/Serpent decomposed
    // schedules).
    defaultCollapsed: true,
    children,
  };
}
