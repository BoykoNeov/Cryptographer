/**
 * keccak.iota — the ι (iota) step of Keccak-f[1600] (SHA-3, FIPS 202 §3.2.5),
 * 2026-07-13.
 *
 * **What ι does.** XORs a round-specific constant `RC[round]` into lane `(0,0)`
 * (the first 8 bytes of the 200-byte state) and leaves the other 24 lanes
 * untouched:
 *
 * ```
 * A'[0,0] = A[0,0] ⊕ RC[round]
 * ```
 *
 * ι is the ONLY step that differs between the 24 rounds. θ, ρ, π and χ are
 * identical every round, so without ι the whole permutation would be symmetric
 * under lane translations — the round constants (derived from an LFSR, FIPS 202
 * §3.2.5) break that symmetry and stop short-cut / slide attacks.
 *
 * **Why a small custom step, not `xor-with-aux@1`.** `xor-with-aux@1` requires
 * its aux operand to be the SAME length as the whole port input (200 bytes),
 * but ι touches only lane 0 (8 bytes). Rather than pad 24 separate 200-byte
 * round-constant buffers (an ugly constants panel), this step reads ONE shared
 * 192-byte `aux["RC"]` table (24 little-endian 8-byte lanes) and slices lane
 * `round` from it — exactly the SHA-256 `K_t = aux["K"][4t .. +4]` pattern, but
 * fused into a single leaf. Declaring the aux read in `meta.auxReadPorts` is
 * what preserves the `RC → ι` fan-out edge in the graph (all 24 ι leaves read
 * the one RC source), mirroring the key-schedule → AddRoundKey fan-out.
 *
 * **Authoring shape.** Hybrid `kind:"ported"` with `meta.auxReadPorts` and no
 * `legacy` executor — the same shape as `aux-load-bytes@1` / `xor-with-aux@1`.
 * Two input ports: `input` (the 200-byte state, wired via `portInputs`) and
 * `rc` (projected by the runtime from `aux["RC"]`). One `output` port.
 */

import type {
  Json,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

const STATE_BYTES = 200;
const LANE_BYTES = 8;
const RC_LANES = 24;

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  /** Which round (0..23): selects RC lane at offset 8·round. */
  readonly round: number;
  /** Aux key holding the 24-lane round-constant table. Defaults to "RC". */
  readonly auxName: string;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("keccak.iota: params must be an object");
  }
  const p = params as Record<string, Json>;
  const round = p.round;
  if (typeof round !== "number" || !Number.isInteger(round) || round < 0 || round >= RC_LANES) {
    throw new Error(
      `keccak.iota: params.round must be an integer in [0, ${RC_LANES}), got ${String(round)}`,
    );
  }
  const auxName = p.auxName;
  if (auxName !== undefined && typeof auxName !== "string") {
    throw new Error("keccak.iota: params.auxName must be a string when present");
  }
  return { round, auxName: (auxName as string | undefined) ?? "RC" };
};

// ─── Port contract ─────────────────────────────────────────────────────────

export const keccakIotaPortContract: PortContract = {
  inputs: new Map([
    ["input", { layout: "raw", byteLength: STATE_BYTES }],
    ["rc", { layout: "raw", byteLength: RC_LANES * LANE_BYTES }],
  ]),
  outputs: new Map([["output", { layout: "raw", byteLength: STATE_BYTES }]]),
};

// ─── Executor ────────────────────────────────────────────────────────────────

export const keccakIota: PortedExecutor = (inputs, params, _ctx) => {
  const { round } = readParams(params);
  const state = inputs.get("input");
  const rc = inputs.get("rc");
  if (state === undefined) {
    throw new Error("keccak.iota: input port 'input' is not wired (the 200-byte state)");
  }
  if (rc === undefined) {
    throw new Error(
      "keccak.iota: operand port 'rc' not available — the runtime projects aux[params.auxName] (the RC table) onto it; check aux[\"RC\"] is populated by cipherConstants",
    );
  }
  if (state.length !== STATE_BYTES) {
    throw new Error(`keccak.iota: input must be ${STATE_BYTES} bytes, got ${state.length}`);
  }
  const rcOff = round * LANE_BYTES;
  if (rcOff + LANE_BYTES > rc.length) {
    throw new Error(
      `keccak.iota: RC table (${rc.length} bytes) has no lane ${round} at offset ${rcOff}`,
    );
  }
  // Copy the state, then XOR the 8 round-constant bytes into lane (0,0).
  const out = new Uint8Array(state);
  for (let b = 0; b < LANE_BYTES; b++) {
    out[b] = (state[b] as number) ^ (rc[rcOff + b] as number);
  }
  return new Map([["output", out]]);
};

// ─── Projection metadata ──────────────────────────────────────────────────────
//
// `auxReadPorts` fills `inputs.get("rc")` from `aux[params.auxName]` (the RC
// table) BEFORE the executor runs, and records the read in `frame.auxRead` —
// preserving the `RC → ι` graph fan-out. `stateLayout: "bytes"` is the
// defensive default required for any `kind:"ported"` registration carrying
// `meta`; state is NOT threaded (the carried bytes arrive on the `input` PORT).

export const keccakIotaMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  auxReadPorts: (params: Json) => {
    const { auxName } = readParams(params);
    return new Map([["rc", auxName]]);
  },
};

// ─── Doc ──────────────────────────────────────────────────────────────────────

export const keccakIotaDoc: StepDocumentation = {
  name: "ι (iota)",
  summary: "XORs this round's round constant into lane (0,0) — the only per-round difference.",
  detail: `# ι (iota)

The last of Keccak-f's five steps (FIPS 202 §3.2.5). It XORs a **round
constant** into a single lane — lane \`(0,0)\`, the first 8 bytes of the state —
and changes nothing else:

\`\`\`
A'[0,0] = A[0,0] ⊕ RC[round]
\`\`\`

## Why it matters

θ, ρ, π and χ are **identical in every one of the 24 rounds**. If that were the
whole story, the permutation would have a large symmetry an attacker could
exploit (slide and rotational attacks). ι breaks it: each round XORs a
**different** constant, so no two rounds compute the same function.

The constants \`RC[0..23]\` are not arbitrary — each is generated by a linear
feedback shift register (FIPS 202 §3.2.5), a "nothing-up-my-sleeve" derivation
anyone can reproduce, so no hidden structure can be smuggled in through the
round-constant choice. This step reads them from the shared **RC** table and
picks out lane \`round\`.`,
  params: new Map([
    ["round", "Which round this is (0–23); selects the round constant RC[round] from the table."],
    ["auxName", 'Name of the aux slot holding the 24-lane round-constant table. Defaults to "RC".'],
  ]),
  references: ["FIPS 202 §3.2.5 (Keccak ι step and round constants)"],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
