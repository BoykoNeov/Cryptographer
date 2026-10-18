/**
 * ml-dsa.publish — file named values into the aux map so a LOOP BODY can read
 * them. ML-DSA signing, `docs/plans/refactored-petting-tide.md` P4.
 *
 * ## Why this step exists
 *
 * Signing's attempt loop is an `iterate`, and an iterate's body sees exactly
 * two wires from outside: its own `in` block and its `chain`. Everything else
 * an attempt needs — the matrix Â, the transformed secret vectors ŝ1, ŝ2, t̂0,
 * the message digest μ and the per-signature seed ρ″ — is computed ONCE before
 * the loop, and port flow cannot carry it across the loop's boundary. `aux` is
 * the one channel that crosses scopes (it is global), so this step writes each
 * value under a name and the body reads it back with `aux-load-bytes@1`.
 *
 * That is the B-minimal pattern RSA's key-generation tail and the four
 * decomposed key schedules use: the interesting math stays VISIBLE as frames
 * above this step, and the step itself is an identity passthrough whose only
 * job is the `meta.auxWritePorts` mirror. The third time the "port flow stops
 * at a scope" rule has decided an ML-* design, after the CSPRNG seed and the
 * NTT modulus.
 *
 * ## Why not carry them on the chain
 *
 * The chain is the wire the trace exists to show CHANGING from attempt to
 * attempt (the counter κ, the accept flag, the candidate). Riding ~23 KB of
 * values that never change on it would bury the one thing it carries that does.
 *
 * Contract: one input port per name in `params.keys` → identity passthrough to
 * the same-named output ports; `meta.auxWritePorts` mirrors each name to
 * `aux["${outputPrefix}.${name}"]`. The prefix keeps these clear of the
 * editable constants (`q`, `gamma1`, …), which share the same global map.
 *
 * Port-native: no `shapeContract`. `params.keys` sets the port set, so the
 * contract is function-form.
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

const STEP = "ml-dsa.publish";

type Params = {
  readonly outputPrefix: string;
  readonly keys: readonly string[];
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error(`${STEP}: params must be an object`);
  }
  const p = params as Record<string, unknown>;
  if (typeof p.outputPrefix !== "string" || p.outputPrefix.length === 0) {
    throw new Error(`${STEP}: params.outputPrefix must be a non-empty string`);
  }
  if (
    !Array.isArray(p.keys) ||
    p.keys.length === 0 ||
    !p.keys.every((k) => typeof k === "string" && k.length > 0)
  ) {
    throw new Error(`${STEP}: params.keys must be a non-empty array of non-empty strings`);
  }
  if (new Set(p.keys).size !== p.keys.length) {
    throw new Error(`${STEP}: params.keys must not repeat a name`);
  }
  return { outputPrefix: p.outputPrefix, keys: p.keys as string[] };
};

/** Identity passthrough; the runtime's `auxWritePorts` does the publishing. */
export const mlDsaPublish: PortedExecutor = (inputs, params, _ctx) => {
  const { keys } = readParams(params);
  const outputs = new Map<string, Uint8Array>();
  for (const name of keys) {
    const v = inputs.get(name);
    if (!(v instanceof Uint8Array)) {
      throw new Error(`${STEP}: missing required input port "${name}"`);
    }
    outputs.set(name, v);
  }
  return outputs;
};

// Polymorphic widths: Â is 16 KB, μ is 64 bytes — the wiring decides.
const RAW: PortShape = { layout: "raw" };

const portMap = (params: Json): ReadonlyMap<string, PortShape> => {
  const { keys } = readParams(params);
  return new Map(keys.map((k) => [k, RAW] as const));
};

export const mlDsaPublishPortContract: PortContract = {
  inputs: portMap,
  outputs: portMap,
};

export const mlDsaPublishMeta: ProjectionMetadata = {
  // Ceremonial — required by the type, never consulted for an aux-only step.
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const { outputPrefix, keys } = readParams(params);
    return new Map(keys.map((k) => [k, `${outputPrefix}.${k}`] as const));
  },
};

export const mlDsaPublishDoc: StepDocumentation = {
  name: "Publish for the attempt loop (ML-DSA)",
  summary:
    "Stores values computed once, before signing's attempt loop, under names the loop's attempts can read.",
  detail: `# Publish for the attempt loop

Signing computes some values **once** and then uses them on **every** attempt:

- the matrix **Â**, expanded from the public seed ρ;
- the secret vectors **ŝ1**, **ŝ2** and **t̂0**, already moved into the
  transformed domain;
- **μ**, the digest of the public key and the message;
- **ρ″**, the seed every attempt's mask is drawn from.

The attempts run inside a loop, and a loop's steps can only be wired to the
loop's own inputs. So this step files each value under a name, and each attempt
reads it back by that name. Nothing is changed: every value comes out exactly as
it went in.

The names carry a prefix so they cannot collide with the editable constants
(\`q\`, \`gamma1\`, …), which are filed the same way.`,
  params: new Map([
    [
      "outputPrefix",
      'Prefix for the stored names. With "ml-dsa.sign", Â is stored as ml-dsa.sign.A.',
    ],
    ["keys", "The names this step stores, one input and one output port each."],
  ]),
  references: ["FIPS 204 Algorithm 7 (ML-DSA.Sign_internal), lines 1–8"],
};
