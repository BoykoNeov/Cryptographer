/**
 * ML-DSA-44 key generation + verification AS SHIPPED SPECS (P3 of
 * `docs/plans/refactored-petting-tide.md`).
 *
 * `tests/ml-dsa-44-oracle.test.ts` already proved the P2 steps compose into
 * FIPS 204's algorithms when called directly. This file proves the SPEC does —
 * the node tree `buildMlDsa44VerifySpec` emits, run through the real runtime,
 * with every value reaching every step along a wire the builder chose. That is
 * a different claim, and its failures are different: a port bound to the wrong
 * source, a constant loaded in the wrong scope, two bodies sharing an id.
 *
 * What is checked, strongest first:
 *
 * 1. **Key generation's checkpoints**, read off the trace inside the collapsed
 *    group: ρ (pins H and the ‖ k ‖ l separator), the 2560-byte `sk` (pins
 *    ExpandS, Power2Round and the packers) and the 1312-byte `pk` (pins ExpandA
 *    and the matrix product) — Node 24's bytes, for three seeds.
 * 2. **Verification against two other implementations**: every Node-made and
 *    noble-made signature in the fixture verifies 1, and every signature Node
 *    rejects verifies 0 — for the REASON Node rejects it, read off the
 *    verdict's own input ports, not only its output byte.
 * 3. **The over-norm signature**: a candidate the signer threw away because z
 *    came out too large, packed anyway. Its challenge and hint are consistent,
 *    so the norm check is the ONLY thing that can reject it — the one case that
 *    makes that check load-bearing in verification.
 * 4. **Perturbations, run not assumed**: each rewires one edge of the shipped
 *    spec the wrong way and asserts the failure signature the tests above would
 *    show.
 *
 * Not perturbed here: ExpandA's index order. ExpandA is a monolith, so its
 * byte order is not a spec-level edge; `tests/ml-dsa-44-oracle.test.ts` pins it
 * with a runnable transpose perturbation (ρ and s1/s2 stay green, t1/tr/t0
 * break).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  MLDSA_HINT_ID,
  MLDSA_KEYGEN_ID,
  MLDSA_PK_ID,
  MLDSA_RECOMPUTED_ID,
  MLDSA_SEEDS_ID,
  MLDSA_SIG_SPLIT_ID,
  MLDSA_SK_ID,
  MLDSA_VERDICT_ID,
  MLDSA_Z_NORM_ID,
  ML_DSA_44_DEFAULT_MESSAGE,
  ML_DSA_44_DEFAULT_SEED,
  ML_DSA_44_DEFAULT_SIGNATURE,
  ML_DSA_44_PK_BYTES,
  ML_DSA_44_SIG_BYTES,
  ML_DSA_44_SK_BYTES,
  type MlDsaVerifyOptions,
  buildMlDsa44VerifySpec,
} from "@/ciphers/ml-dsa-44";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, PortBinding, StepNode, TraceFrame } from "@/core/types";
import { challengesMatch, mlDsaVerdict } from "@/steps/ml-dsa-verdict";
import { describe, expect, it } from "vitest";
import FIXTURE from "./fixtures/ml-dsa-44-vectors.json";

const registry = buildDefaultRegistry();

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

type Sig = { message: string; context: string; deterministic: string; nodeRandomized: string };
type Key = { seed: string; pk: string; sk: string; signatures: Sig[] };
const KEYS = FIXTURE.keys as Key[];
const KG = `${MLDSA_KEYGEN_ID}.`;

// ─── Harness ───────────────────────────────────────────────────────────────

type Run = {
  readonly verdict: number;
  readonly frames: ReadonlyMap<string, TraceFrame>;
  /** A leaf's output port by node id. */
  readonly out: (id: string, port?: string) => Uint8Array;
  /** A leaf's input port by node id. */
  readonly in: (id: string, port: string) => Uint8Array;
};

/**
 * Runs are memoized per (spec object, signature): one verification costs
 * ~0.2–0.5 s, almost all of it the two ExpandA calls' incremental SHAKE128, and
 * several tests below ask different questions of the same run.
 */
const memo = new WeakMap<CipherSpec, Map<string, Run>>();
const run = (spec: CipherSpec, signature: Uint8Array): Run => {
  const bySig = memo.get(spec) ?? new Map<string, Run>();
  memo.set(spec, bySig);
  const key = hex(signature);
  const hit = bySig.get(key);
  if (hit !== undefined) return hit;
  const fresh = runUncached(spec, signature);
  bySig.set(key, fresh);
  return fresh;
};

const runUncached = (spec: CipherSpec, signature: Uint8Array): Run => {
  const trace = runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: signature },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");
  const frames = new Map(trace.frames.map((f) => [f.stepId, f]));
  const pick = (id: string, side: "portInputs" | "portOutputs", name: string) => {
    const v = frames.get(id)?.[side]?.get(name);
    if (!(v instanceof Uint8Array)) throw new Error(`no ${side} ${name} on ${id}`);
    return v;
  };
  const verdict = trace.finalState.bytes;
  expect(verdict.length).toBe(1);
  return {
    verdict: verdict[0] as number,
    frames,
    out: (id, name = "output") => pick(id, "portOutputs", name),
    in: (id, name) => pick(id, "portInputs", name),
  };
};

/** One spec per fixture (key, message), shared so the run memo can hit. */
const specs = new Map<Sig, CipherSpec>();
const specFor = (k: Key, s: Sig, extra?: MlDsaVerifyOptions): CipherSpec => {
  const build = () =>
    buildMlDsa44VerifySpec({
      seed: unhex(k.seed),
      message: unhex(s.message),
      context: unhex(s.context),
      ...extra,
    });
  if (extra !== undefined) return build();
  const cached = specs.get(s) ?? build();
  specs.set(s, cached);
  return cached;
};

const walk = (nodes: readonly StepNode[], visit: (n: StepNode) => void): void => {
  for (const n of nodes) {
    visit(n);
    if (n.kind !== "step") walk(n.children, visit);
  }
};

/** Rebind one input port of one node in a copy of the spec — a perturbation. */
const rebind = (spec: CipherSpec, id: string, portName: string, to: PortBinding): CipherSpec => {
  let hit = false;
  const map = (nodes: readonly StepNode[]): StepNode[] =>
    nodes.map((n) => {
      if (n.kind === "step") {
        if (n.id !== id) return n;
        hit = true;
        return { ...n, portInputs: { ...n.portInputs, [portName]: to } };
      }
      return { ...n, children: map(n.children) };
    });
  const steps = map(spec.steps);
  if (!hit) throw new Error(`perturbation target ${id} not found`);
  return { ...spec, steps };
};

/** One bit flipped at `byte`. */
const flip = (sig: Uint8Array, byte: number): Uint8Array => {
  const out = new Uint8Array(sig);
  out[byte] = (out[byte] as number) ^ 0x01;
  return out;
};

const DEFAULT_KEY = KEYS[FIXTURE.p3.defaultPair.keyIndex] as Key;

// ─── Structure ─────────────────────────────────────────────────────────────

describe("the shipped verification spec's structure", () => {
  const spec = buildMlDsa44VerifySpec();

  it("every node id is unique across the whole tree, group children included", () => {
    // The flat trace keys frames by step id, so a duplicate does not throw —
    // it silently breaks the scrubber and the graph (K-PKE P3's lesson).
    const seen = new Map<string, number>();
    walk(spec.steps, (n) => seen.set(n.id, (seen.get(n.id) ?? 0) + 1));
    const dupes = [...seen].filter(([, n]) => n > 1).map(([id]) => id);
    expect(dupes).toEqual([]);
    expect(seen.size).toBeGreaterThan(60);
  });

  it("key generation is ONE default-collapsed group, and every node inside it is prefixed", () => {
    const groups = spec.steps.filter((n) => n.kind === "group");
    expect(groups.map((g) => g.id)).toEqual([MLDSA_KEYGEN_ID]);
    const group = groups[0];
    if (group?.kind !== "group") throw new Error("unreachable");
    expect(group.defaultCollapsed).toBe(true);
    walk(group.children, (n) => expect(n.id.startsWith(KG), n.id).toBe(true));
  });

  it("the editable constants are the five P2 names, four bytes each", () => {
    const c = spec.cipherConstants ?? {};
    expect(Object.keys(c).sort()).toEqual(["beta", "gamma1", "gamma2", "omega", "q"]);
    for (const v of Object.values(c)) expect(v.length).toBe(4);
  });

  it("widths match FIPS 204 Table 2 for ML-DSA-44", () => {
    expect(ML_DSA_44_PK_BYTES).toBe(1312);
    expect(ML_DSA_44_SK_BYTES).toBe(2560);
    expect(ML_DSA_44_SIG_BYTES).toBe(2420);
  });

  it("narration overrides use only markup the description panel renders", () => {
    // markdown.tsx supports neither pipe tables nor single-star italics; both
    // show up as raw punctuation. The P2 ban covers registry docs only.
    let checked = 0;
    walk(spec.steps, (n) => {
      if (n.kind !== "step" || n.narrationOverride === undefined) return;
      const detail = n.narrationOverride.detail;
      expect(detail, `${n.id}: pipe table`).not.toMatch(/^\|.*\|$/m);
      expect(detail.replace(/\*\*/g, ""), `${n.id}: single-star italic`).not.toMatch(
        /(?<![\w*])\*[A-Za-z][^*\n]*\*(?![\w*])/,
      );
      checked++;
    });
    expect(checked).toBeGreaterThanOrEqual(10);
  });
});

// ─── Key generation checkpoints ────────────────────────────────────────────

describe("key generation inside the spec = Node's keys, checkpoint by checkpoint", () => {
  for (const k of KEYS) {
    it(`seed ${k.seed.slice(0, 8)}…: ρ, then sk, then pk`, () => {
      const s = k.signatures[0] as Sig;
      const r = run(specFor(k, s), unhex(s.deterministic));
      const pk = unhex(k.pk);
      // ρ first: it depends only on H(ξ ‖ k ‖ l).
      expect(hex(r.out(`${KG}${MLDSA_SEEDS_ID}`, "output0"))).toBe(hex(pk.subarray(0, 32)));
      expect(hex(r.out(`${KG}${MLDSA_SK_ID}`))).toBe(k.sk);
      expect(hex(r.out(`${KG}${MLDSA_PK_ID}`))).toBe(k.pk);
      // And the pair leaves the group in FIPS's order.
      expect(hex(r.out("keypair", "output0"))).toBe(k.pk);
      expect(hex(r.out("keypair", "output1"))).toBe(k.sk);
    });
  }
});

// ─── Verification against the fixture ──────────────────────────────────────

describe("verification agrees with Node and noble", () => {
  for (const [ki, k] of KEYS.entries()) {
    for (const [si, s] of k.signatures.entries()) {
      it(`key ${ki}, message ${si}${s.context ? " (with context)" : ""}: both signatures verify 1`, () => {
        const spec = specFor(k, s);
        expect(run(spec, unhex(s.nodeRandomized)).verdict).toBe(1);
        expect(run(spec, unhex(s.deterministic)).verdict).toBe(1);
      });
    }
  }

  it("the defaults are the fixture's P3 pair, and the default signature verifies", () => {
    const d = FIXTURE.p3.defaultPair;
    expect(hex(ML_DSA_44_DEFAULT_SEED)).toBe(DEFAULT_KEY.seed);
    expect(hex(ML_DSA_44_DEFAULT_MESSAGE)).toBe(d.message);
    expect(d.context).toBe("");
    expect(hex(ML_DSA_44_DEFAULT_SIGNATURE)).toBe(d.deterministic);
    expect(run(buildMlDsa44VerifySpec(), ML_DSA_44_DEFAULT_SIGNATURE).verdict).toBe(1);
  });

  it("each malformed signature is refused for Node's reason, read off the verdict's inputs", () => {
    const k = KEYS[FIXTURE.malformed.keyIndex] as Key;
    const s = k.signatures[FIXTURE.malformed.signatureIndex] as Sig;
    const spec = specFor(k, s);
    for (const c of FIXTURE.malformed.cases) {
      const r = run(spec, unhex(c.signature));
      expect(r.verdict, c.name).toBe(c.nodeVerifies ? 1 : 0);
      const hintValid = r.in(MLDSA_VERDICT_ID, "hintValid")[0];
      // Assert on the INPUT the verdict saw, so a verdict that ignored the hint
      // flag (and still said 0 because the zeroed hint breaks the challenge)
      // cannot pass.
      if (c.name === "unmodified" || c.name === "flip-ctilde-bit") {
        expect(hintValid, c.name).toBe(1);
      } else {
        expect(hintValid, c.name).toBe(0);
        expect(r.out(MLDSA_HINT_ID, "valid")[0], c.name).toBe(0);
      }
    }
    const flipped = FIXTURE.malformed.cases.find((c) => c.name === "flip-ctilde-bit");
    if (flipped === undefined) throw new Error("fixture lost its flip-ctilde-bit case");
    const r = run(spec, unhex(flipped.signature));
    expect(r.in(MLDSA_VERDICT_ID, "normOk")[0]).toBe(1);
    expect(
      challengesMatch(r.in(MLDSA_VERDICT_ID, "challenge"), r.in(MLDSA_VERDICT_ID, "recomputed")),
    ).toBe(false);
  });

  it("a one-bit flip in c̃, in z and in h each verifies 0", () => {
    const spec = buildMlDsa44VerifySpec();
    const sig = ML_DSA_44_DEFAULT_SIGNATURE;
    const zStart = 32;
    const hStart = 32 + 4 * 576;
    for (const [name, at] of [
      ["c̃", 5],
      ["z", zStart + 100],
      ["h (a position byte)", hStart],
    ] as const) {
      expect(run(spec, flip(sig, at)).verdict, name).toBe(0);
    }
  });

  it("the same signature under the wrong context verifies 0 — the M′ prefix is load-bearing", () => {
    const k = KEYS[0] as Key;
    const s = k.signatures[2] as Sig; // signed with context "app-ctx"
    expect(s.context).not.toBe("");
    const spec = specFor(k, s, { context: new Uint8Array(0) });
    expect(run(spec, unhex(s.deterministic)).verdict).toBe(0);
  });

  it("an edited message verifies 0", () => {
    const spec = buildMlDsa44VerifySpec({ message: new TextEncoder().encode("Hello, world?") });
    expect(run(spec, ML_DSA_44_DEFAULT_SIGNATURE).verdict).toBe(0);
  });
});

describe("the over-norm signature: only the bound on z can reject it", () => {
  const over = unhex(FIXTURE.p3.overNorm.signature);
  const spec = buildMlDsa44VerifySpec();

  it("Node and noble both reject it (recorded in the fixture)", () => {
    expect(FIXTURE.p3.overNorm.nodeVerifies).toBe(false);
    expect(FIXTURE.p3.overNorm.nobleVerifies).toBe(false);
  });

  it("verifies 0 with a well-formed hint and a MATCHING challenge — the norm flag alone", () => {
    const r = run(spec, over);
    expect(r.verdict).toBe(0);
    expect(r.out(MLDSA_HINT_ID, "valid")[0]).toBe(1);
    expect(r.out(MLDSA_Z_NORM_ID)[0]).toBe(0);
    expect(hex(r.out(MLDSA_RECOMPUTED_ID))).toBe(hex(r.out(MLDSA_SIG_SPLIT_ID, "output0")));
  });
});

// ─── Perturbations: each failure signature, run ────────────────────────────

describe("perturbations of the shipped spec, and the test that catches each", () => {
  const k = KEYS[1] as Key;
  const s = k.signatures[0] as Sig;

  it("hashing ξ without ‖ k ‖ l (the round-3 draft) breaks ρ itself", () => {
    const spec = rebind(specFor(k, s), `${KG}h`, "input", { node: MLDSA_KEYGEN_ID, port: "in" });
    const r = run(spec, unhex(s.deterministic));
    expect(hex(r.out(`${KG}${MLDSA_SEEDS_ID}`, "output0"))).not.toBe(k.pk.slice(0, 64));
    expect(r.verdict).toBe(0);
  });

  it("comparing c̃ with itself still accepts every good signature — only a NEGATIVE case catches it", () => {
    const base = buildMlDsa44VerifySpec();
    const spec = rebind(base, MLDSA_VERDICT_ID, "recomputed", {
      node: MLDSA_SIG_SPLIT_ID,
      port: "output0",
    });
    expect(run(spec, ML_DSA_44_DEFAULT_SIGNATURE).verdict).toBe(1);
    expect(run(spec, flip(ML_DSA_44_DEFAULT_SIGNATURE, 5)).verdict).toBe(1);
  });

  it("dropping the norm flag is caught by the over-norm case and by nothing else here", () => {
    // Feed normOk from the hint's valid flag, which is 1 for every
    // well-formed signature.
    const spec = rebind(buildMlDsa44VerifySpec(), MLDSA_VERDICT_ID, "normOk", {
      node: MLDSA_HINT_ID,
      port: "valid",
    });
    expect(run(spec, unhex(FIXTURE.p3.overNorm.signature)).verdict).toBe(1);
    expect(run(spec, flip(ML_DSA_44_DEFAULT_SIGNATURE, 5)).verdict).toBe(0);
  });

  it("dropping the hint flag leaves the output byte 0 — so the test must read the verdict's INPUT", () => {
    const mk = KEYS[FIXTURE.malformed.keyIndex] as Key;
    const ms = mk.signatures[FIXTURE.malformed.signatureIndex] as Sig;
    const spec = rebind(specFor(mk, ms), MLDSA_VERDICT_ID, "hintValid", {
      node: MLDSA_Z_NORM_ID,
      port: "output",
    });
    const bad = FIXTURE.malformed.cases.find((c) => c.name === "count-above-omega");
    if (bad === undefined) throw new Error("fixture lost its count-above-omega case");
    const r = run(spec, unhex(bad.signature));
    expect(r.verdict).toBe(0); // the zeroed hint still breaks the challenge…
    expect(r.in(MLDSA_VERDICT_ID, "hintValid")[0]).toBe(1); // …which is what the guard reads
  });
});

// ─── The verdict step itself ───────────────────────────────────────────────

describe("ml-dsa.verdict@1", () => {
  const c = new Uint8Array(32).fill(7);
  const exec = (ports: Record<string, Uint8Array>) =>
    mlDsaVerdict(new Map(Object.entries(ports)), {}, {} as never).get("output")?.[0];

  it("is valid only when all three conditions hold (truth table)", () => {
    for (const hint of [0, 1]) {
      for (const norm of [0, 1]) {
        for (const same of [false, true]) {
          const recomputed = same ? new Uint8Array(c) : flip(c, 31);
          const got = exec({
            challenge: c,
            recomputed,
            normOk: new Uint8Array([norm]),
            hintValid: new Uint8Array([hint]),
          });
          expect(got, `hint=${hint} norm=${norm} same=${same}`).toBe(
            hint === 1 && norm === 1 && same ? 1 : 0,
          );
        }
      }
    }
  });

  it("refuses mismatched challenge widths and flags that are not one 0/1 byte", () => {
    const ok = { normOk: new Uint8Array([1]), hintValid: new Uint8Array([1]) };
    expect(() => exec({ challenge: c, recomputed: c.subarray(1), ...ok })).toThrow(/same width/);
    expect(() =>
      exec({ challenge: c, recomputed: c, normOk: new Uint8Array([2]), hintValid: ok.hintValid }),
    ).toThrow(/one-byte flag/);
    expect(() =>
      exec({ challenge: c, recomputed: c, normOk: ok.normOk, hintValid: new Uint8Array([1, 1]) }),
    ).toThrow(/one-byte flag/);
  });
});
