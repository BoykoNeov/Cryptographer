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
 * exponent `e`, the private exponent `d` — and welding an indexed
 * `*.publish-round-keys@1` step into every saved RSA document's JSON would be
 * cross-domain coupling in the persisted spec.
 *
 * **Each direction exports exactly the key its ladder consumes** (`keys`
 * param). Encryption exports the **public key** `{n, e}`; decryption exports
 * the **private key** `{n, d}` — so the "public key (n, e) / private key
 * (n, d)" split that IS the RSA lesson becomes concrete, AND no aux value is
 * written-but-unread (publishing all three would mirror `rsa.d` in encrypt,
 * which nothing reads → an `unused-write` warning glyph on the default spec).
 * `d` is still computed + narrated in the group for both directions; in
 * encrypt its output simply goes unconsumed downstream (as in flat Phase 1 —
 * port outputs, unlike aux writes, draw no validator warning).
 *
 * Contract: one input port per name in `params.keys` (wired from the key-gen
 * leaves) → identity passthrough to the same-named output ports;
 * `meta.auxWritePorts` mirrors `name → aux[${outputPrefix}.${name}]`. No state
 * ports (aux-only — the carried block, the message bytes, passes through
 * untouched).
 *
 * **Version note.** `keys` was added (replacing the original fixed `n`/`e`/`d`
 * triple) within the same unreleased cycle this step type first shipped — no
 * saved document can reference the old shape, so `@1` is amended rather than
 * bumped to `@2`.
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

type Params = {
  readonly outputPrefix: string;
  /** The named key parameters this instance publishes (e.g. ["n", "e"]). */
  readonly keys: readonly string[];
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("rsa.publish-key-params: params must be an object");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.outputPrefix !== "string" || p.outputPrefix.length === 0) {
    throw new Error("rsa.publish-key-params: params.outputPrefix must be a non-empty string");
  }
  // `keys` is REQUIRED with no default: the set of published keys is
  // direction-specific (public {n,e} vs private {n,d}), so a default would
  // either re-introduce the unused-write warning or export the wrong key.
  if (
    !Array.isArray(p.keys) ||
    p.keys.length === 0 ||
    !p.keys.every((k) => typeof k === "string" && k.length > 0)
  ) {
    throw new Error(
      'rsa.publish-key-params: params.keys must be a non-empty array of non-empty strings (the named key parameters to publish, e.g. ["n", "e"])',
    );
  }
  return { outputPrefix: p.outputPrefix, keys: p.keys as string[] };
};

/**
 * Identity passthrough: read each published key parameter off its input port
 * and re-emit it on the same-named output port. The runtime's
 * `meta.auxWritePorts` step then mirrors every output port into
 * `aux[${outputPrefix}.${name}]`.
 */
export const publishKeyParams: PortedExecutor = (inputs, params, _ctx) => {
  const { keys } = readParams(params);
  const outputs = new Map<string, Uint8Array>();
  for (const name of keys) {
    const v = inputs.get(name);
    if (!(v instanceof Uint8Array)) {
      throw new Error(
        `rsa.publish-key-params: input port "${name}" must carry a key parameter (wire it from the key-gen leaves: n, load-e, or d)`,
      );
    }
    outputs.set(name, v);
  }
  return outputs;
};

// ─── Port contract ──────────────────────────────────────────────────────────
// One port per published key. `byteLength` ABSENT — polymorphic, matching the
// publish-round-keys siblings: the RSA working width `W` lives in the spec
// builder, not this step, and the runtime's port-length coercion aligns the
// actual values either way. Function form because the port SET varies with
// `params.keys`.

const KEY_PARAM_PORT_SHAPE: PortShape = { layout: "raw" };

const keyParamPortMap = (params: Json): ReadonlyMap<string, PortShape> => {
  const { keys } = readParams(params);
  const m = new Map<string, PortShape>();
  for (const name of keys) m.set(name, KEY_PARAM_PORT_SHAPE);
  return m;
};

export const publishKeyParamsPortContract: PortContract = {
  inputs: keyParamPortMap,
  outputs: keyParamPortMap,
};

// ─── Projection metadata (the one meta in the decomposed key generation) ────
// Aux-only: no `stateInputPort` / `stateOutputPort` — the carried block (the
// message bytes) is preserved across the call. `auxWritePorts` maps each
// published key to its `aux[${outputPrefix}.${name}]` key, so the top-level
// `aux-load-bytes@1` loaders that feed the exponentiation ladder read the
// computed parameters back out across the group boundary.

export const publishKeyParamsMeta: ProjectionMetadata = {
  // Ceremonial — required by the type but never consulted for an aux-only step.
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const { outputPrefix, keys } = readParams(params);
    const bindings = new Map<string, string>();
    for (const name of keys) bindings.set(name, `${outputPrefix}.${name}`);
    return bindings;
  },
};

// ─── Documentation ────────────────────────────────────────────────────────────

export const publishKeyParamsDoc: StepDocumentation = {
  name: "Publish key parameters (RSA)",
  summary:
    "Write this direction's RSA key material (the modulus n + the active exponent) into the aux map.",
  detail: `## Publish key parameters (RSA)

The last step of the "Key Generation" group. The steps above it have already
computed the modulus \`n = p·q\`, Euler's totient \`φ(n) = (p−1)(q−1)\`, and the
private exponent \`d = e⁻¹ mod φ(n)\`. This step collects the key values this
direction needs and stores them under names — \`rsa.n\`, \`rsa.e\`, \`rsa.d\` —
so the encryption or decryption that follows can look them up. It does not
change the message; it only files the key material away.

## The public / private key split

Each direction publishes exactly the key its ladder uses:

- **Encrypt** publishes the **public key** \`{n, e}\` → \`c = mᵉ mod n\`.
- **Decrypt** publishes the **private key** \`{n, d}\` → \`m = cᵈ mod n\`.

The modulus \`n\` is shared by both. Publishing only the key each direction
actually uses is the public/private split made concrete. The private exponent
\`d\` is still derived and shown in the key-generation group even when
encrypting — it just isn't used on that side.`,
  params: new Map([
    [
      "outputPrefix",
      'Prefix for the key-parameter aux entries. With "rsa", outputs are rsa.<name>.',
    ],
    [
      "keys",
      'The named key parameters this instance publishes. Encrypt → ["n", "e"] (public key); decrypt → ["n", "d"] (private key).',
    ],
  ]),
  references: [
    "Rivest, Shamir, Adleman 1978 — A Method for Obtaining Digital Signatures and Public-Key Cryptosystems",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};
