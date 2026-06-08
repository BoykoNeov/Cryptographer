/**
 * RSA publish-key-params — the meta-bearing aux-publish tail of the
 * "Key Generation" group (RSA Phase 2, `docs/plans/shimmying-booping-moth.md`).
 *
 * **Why this step exists.** Phase 1 built RSA flat (no groups), so the
 * computed `n`/`d` fanned out PORT-TO-PORT to the exponentiation ladder —
 * every key-gen leaf was a top-level sibling of every rung. Phase 2 wraps the
 * key-gen leaves in a collapsible group for pedagogical structure ("here is
 * key generation; here is exponentiation"). That re-introduces the group-scope
 * wall: a group walks its children in an isolated `nodeOutputs` map, so a rung
 * OUTSIDE the group can no longer reference `port("n")` INSIDE it. `aux` is the
 * only channel that crosses a group boundary (it is global), so this tail
 * publishes the finished key parameters into `aux` and the ladder reads them
 * back via top-level `aux-load-bytes@1` leaves.
 *
 * This is the exact **B-minimal** pattern the four decomposed key schedules
 * use (`aes`/`speck`/`serpent`/`des.publish-round-keys@1`): the interesting
 * math (n = p·q, φ = (p−1)(q−1), d = e⁻¹ mod φ) stays VISIBLE as port-native
 * frames above this tail; the tail is a pure identity passthrough whose only
 * job is the `meta.auxWritePorts` mirror into the global aux map.
 *
 * **Why a dedicated RSA step, not reuse a publish-round-keys sibling.** The
 * sibling tails publish INDEXED round keys (`key0`…`keyN` → `roundKey.0…N`).
 * RSA's exports are NAMED, not indexed — the public modulus `n`, the public
 * exponent `e`, and the private exponent `d` — and the "public key (n,e) /
 * private key (n,d)" split is itself the RSA lesson. Welding an indexed
 * `*.publish-round-keys@1` step into every saved RSA document's JSON would
 * also be cross-domain coupling in the persisted spec.
 *
 * **What it publishes.** Strictly only `n` and `d` MUST cross the wall (`e` is
 * a `cipherConstant`, already materialized into `aux["e"]` before the walk, so
 * the encrypt ladder could read it directly). It re-publishes `e` anyway so
 * the tail names the complete key material in one place — the encrypt ladder
 * reads `aux["${prefix}.e"]`, the decrypt ladder reads `aux["${prefix}.d"]`,
 * and `aux["${prefix}.n"]` is the modulus for every rung either way.
 *
 * Contract: 3 input ports `n`, `e`, `d` (wired from the key-gen leaves) →
 * identity passthrough to the same-named output ports; `meta.auxWritePorts`
 * mirrors `name → aux[${outputPrefix}.${name}]`. No state ports (aux-only —
 * the carried block, the message bytes, passes through untouched).
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

/** The three named key parameters RSA exports across the group wall. */
const KEY_PARAM_PORTS = ["n", "e", "d"] as const;

type Params = {
  readonly outputPrefix: string;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("rsa.publish-key-params: params must be an object");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.outputPrefix !== "string" || p.outputPrefix.length === 0) {
    throw new Error("rsa.publish-key-params: params.outputPrefix must be a non-empty string");
  }
  return { outputPrefix: p.outputPrefix };
};

/**
 * Identity passthrough: read each key parameter off its input port and re-emit
 * it on the same-named output port. The runtime's `meta.auxWritePorts` step
 * then mirrors every output port into `aux[${outputPrefix}.${name}]`.
 */
export const publishKeyParams: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const outputs = new Map<string, Uint8Array>();
  for (const name of KEY_PARAM_PORTS) {
    const v = inputs.get(name);
    if (!(v instanceof Uint8Array)) {
      throw new Error(
        `rsa.publish-key-params: input port "${name}" must carry a key parameter (wire from the key-gen leaves: n, load-e, d)`,
      );
    }
    outputs.set(name, v);
  }
  return outputs;
};

// ─── Port contract ──────────────────────────────────────────────────────────
// Both sides expose the same three named ports. `byteLength` ABSENT —
// polymorphic, matching the publish-round-keys siblings: the RSA working width
// `W` lives in the spec builder, not this step, and the runtime's port-length
// coercion aligns the actual values either way.

const KEY_PARAM_PORT_SHAPE: PortShape = { layout: "raw" };

const keyParamPortMap = (): ReadonlyMap<string, PortShape> => {
  const m = new Map<string, PortShape>();
  for (const name of KEY_PARAM_PORTS) m.set(name, KEY_PARAM_PORT_SHAPE);
  return m;
};

export const publishKeyParamsPortContract: PortContract = {
  inputs: keyParamPortMap,
  outputs: keyParamPortMap,
};

// ─── Projection metadata (the one meta in the decomposed key generation) ────
// Aux-only: no `stateInputPort` / `stateOutputPort` — the carried block (the
// message bytes) is preserved across the call. `auxWritePorts` maps each
// output port to its `aux[${outputPrefix}.${name}]` key, so the top-level
// `aux-load-bytes@1` loaders that feed the exponentiation ladder read the
// computed n / e / d back out across the group boundary.

export const publishKeyParamsMeta: ProjectionMetadata = {
  // Ceremonial — required by the type but never consulted for an aux-only step.
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const p = readParams(params);
    const bindings = new Map<string, string>();
    for (const name of KEY_PARAM_PORTS) bindings.set(name, `${p.outputPrefix}.${name}`);
    return bindings;
  },
};

// ─── Documentation ────────────────────────────────────────────────────────────

export const publishKeyParamsDoc: StepDocumentation = {
  name: "Publish key parameters (RSA)",
  summary:
    "Write the derived RSA key parameters (modulus n, public exponent e, private exponent d) into the aux map.",
  detail: `## Publish key parameters (RSA)

The tail of the "Key Generation" group. The leaves above this step have
already computed the modulus \`n = p·q\`, Euler's totient \`φ(n) =
(p−1)(q−1)\`, and the private exponent \`d = e⁻¹ mod φ(n)\` as visible
port-native frames; this leaf takes the finished parameters on its input
ports \`n\`, \`e\`, \`d\` and publishes them into the aux map as
\`\${outputPrefix}.n\`, \`\${outputPrefix}.e\`, \`\${outputPrefix}.d\`
(typically \`rsa.n\`, \`rsa.e\`, \`rsa.d\`).

## Why a publish step is needed

Key generation lives inside a collapsible group. A group walks its children
in an isolated scope, so the exponentiation ladder OUTSIDE the group cannot
wire a port directly to \`n\` or \`d\` INSIDE it. The aux map is global — it
is the one channel that crosses the group boundary — so this tail mirrors the
key parameters into aux, and the ladder reads them back via top-level
\`aux-load-bytes@1\` loaders. The carried state (the message bytes) passes
through this step untouched; the work product lives entirely in the aux map.

## The public / private key split

This step is where RSA's two keys become concrete:

- **Public key** = (n, e) — used to encrypt: \`c = mᵉ mod n\`.
- **Private key** = (n, d) — used to decrypt: \`m = cᵈ mod n\`.

The modulus \`n\` is shared by both. The encrypt ladder reads
\`\${outputPrefix}.e\`; the decrypt ladder reads \`\${outputPrefix}.d\`. (Only
\`n\` and \`d\` strictly need to cross the group wall — \`e\` is an editable
constant already in aux — but publishing all three names the complete key
material in one place.)`,
  params: new Map([
    [
      "outputPrefix",
      'Prefix for the key-parameter aux entries. With "rsa", outputs are rsa.n, rsa.e, rsa.d.',
    ],
  ]),
  references: [
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};
