/**
 * K-PKE (FIPS 203 §5) — known-answer tests. ML-KEM P3,
 * `docs/plans/unified-stargazing-quasar.md`.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ORACLE
 *
 * Node 24's OpenSSL, captured as `tests/fixtures/ml-kem-768-seed-vectors.json`
 * because CI runs Node 22, which has no ML-KEM at all. P2 closed believing this
 * oracle did not exist — `generateKeyPairSync`'s `seed` option is silently
 * ignored on v24.14.1 — but importing a hand-assembled PKCS#8 carrying the seed
 * arm of the `PrivateKey` CHOICE is deterministic, so we choose the seed rather
 * than being handed one.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THREE CHECKPOINTS, IN THIS ORDER — the reason KeyGen is its own spec
 *
 * The expanded `dk` decomposes as §7.1's `dk_PKE ‖ ek ‖ H(ek) ‖ z`, so the
 * fixture pins the SECRET half as well as the public one. That turns one
 * end-to-end comparison into three, and each failure names its own cause:
 *
 *   1. the last 32 bytes of `ek` are ρ  →  pins G, and the `‖ k` byte
 *   2. `dk_PKE`                          →  pins the PRF, the counter ORDER,
 *                                           the CBD sampler, and NTT(s)
 *   3. the first 1152 bytes of `ek`      →  pins SampleNTT, the matrix index
 *                                           order, e, and Â∘ŝ + ê
 *
 * Concretely: a swapped s/e counter pair leaves (1) green and fails (2); a
 * transposed matrix index leaves (1) AND (2) green and fails (3). Both were
 * confirmed by running them, not by reasoning about them — see the perturbation
 * section at the bottom.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * ENCRYPT AND DECRYPT HAVE A DIRECT ORACLE TOO, VIA THE FO LOOP
 *
 * The fixture's encapsulations are ML-KEM's, not K-PKE's — `crypto.encapsulate`
 * picks its own message, so there is no seed→(m, r)→c row to compare against.
 * The re-encryption loop recovers one anyway, entirely from what is stored:
 *
 *     m′       = our K-PKE.Decrypt(dk_PKE, c)
 *     (K′, r′) = G(m′ ‖ H(ek))            ← computed here, not by a spec
 *     c′       = our K-PKE.Encrypt(ek, m′, r′)
 *
 * `c′ === c` pins Decrypt against OpenSSL's Encrypt AND Encrypt against it, and
 * `K′ === sharedSecret` pins G. Round-trip is ranked last, as always: a pair of
 * matched-wrong implementations passes it.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  CIPHERTEXT_BYTES,
  DK_BYTES,
  EK_BYTES,
  KPKE_DK_ID,
  buildKPkeDecryptSpec,
  buildKPkeEncryptSpec,
  buildKPkeKeyGenSpec,
} from "@/ciphers/k-pke";
import { sha3_256, sha3_512 } from "@/ciphers/keccak-compute";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";
import FIXTURE from "./fixtures/ml-kem-768-seed-vectors.json";

// ─── Harness ──────────────────────────────────────────────────────────────

const registry = buildDefaultRegistry();

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

type Run = {
  readonly output: Uint8Array;
  /** Every leaf's primary output, keyed by node id — how the KAT reaches
   *  `dk_PKE`, which is produced but is not the spec's single output. */
  readonly byNode: ReadonlyMap<string, Uint8Array>;
};

const run = (spec: CipherSpec, input: Uint8Array): Run => {
  const trace = runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: input },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");

  const byNode = new Map<string, Uint8Array>();
  for (const frame of trace.frames) {
    const out = frame.portOutputs?.get("output");
    if (out !== undefined) byNode.set(frame.stepId, out);
  }
  return { output: trace.finalState.bytes, byNode };
};

const nodeOutput = (r: Run, id: string): Uint8Array => {
  const value = r.byNode.get(id);
  if (value === undefined) {
    throw new Error(`no frame produced an "output" port for node "${id}"`);
  }
  return value;
};

/** Deep-clone a spec so a perturbation cannot leak into the next test. */
const clone = (spec: CipherSpec): CipherSpec => structuredClone(spec) as CipherSpec;

/** Walk every node, including inside groups and iterates. */
const walk = (nodes: readonly StepNode[], visit: (n: StepNode) => void): void => {
  for (const n of nodes) {
    visit(n);
    if (n.kind !== "step") walk(n.children, visit);
  }
};

// ─── 1. Key generation, checkpoint by checkpoint ──────────────────────────

describe("K-PKE.KeyGen against Node 24's ML-KEM", () => {
  const spec = buildKPkeKeyGenSpec();

  // One run per fixture seed, reused by all three checkpoints below: the spec
  // is ~520 nodes and six transforms, so running it eighteen times per
  // assertion would be wasteful for no extra coverage.
  const runs = FIXTURE.vectors.map((v) => ({
    label: v.label,
    expected: v,
    actual: run(spec, unhex(v.seed).slice(0, 32)),
  }));

  describe("checkpoint 1 — ρ, which pins G and the ‖ k byte", () => {
    for (const { label, expected, actual } of runs) {
      it(`seed "${label}" derives the right public seed`, () => {
        // The last 32 bytes of ek ARE ρ, copied in unchanged. If the `‖ 3` were
        // missing — the FIPS 203 draft's spelling — this alone would fail, and
        // nothing downstream could be trusted.
        expect(hex(actual.output.slice(-32))).toBe(expected.ek.slice(-64));
      });
    }
  });

  describe("checkpoint 2 — dk_PKE, which pins the PRF, the counters, CBD and NTT(s)", () => {
    for (const { label, expected, actual } of runs) {
      it(`seed "${label}" derives the right secret key`, () => {
        const dk = nodeOutput(actual, KPKE_DK_ID);
        expect(dk).toHaveLength(DK_BYTES);
        expect(hex(dk)).toBe(expected.dkPke);
      });
    }
  });

  describe("checkpoint 3 — the whole ek, which pins the matrix and Â∘ŝ + ê", () => {
    for (const { label, expected, actual } of runs) {
      it(`seed "${label}" derives the right public key`, () => {
        expect(actual.output).toHaveLength(EK_BYTES);
        expect(hex(actual.output)).toBe(expected.ek);
      });
    }
  });

  it("agrees with H(ek) as the oracle itself computed it", () => {
    // Ties our ek to the digest OpenSSL stored beside it inside the expanded
    // decapsulation key — a third party's opinion of the same bytes.
    for (const { expected, actual } of runs) {
      expect(hex(sha3_256(actual.output))).toBe(expected.hEk);
    }
  });

  it("gives the same ek for two seeds that differ only in z", () => {
    // §7.1's split, asserted. `z` feeds implicit rejection and NOTHING else, so
    // two seeds sharing d must produce identical public AND secret K-PKE halves.
    // The fixture carries such a pair specifically so this is checkable.
    const byD = new Map<string, { label: string; ek: string; dk: string }[]>();
    for (const { label, expected, actual } of runs) {
      const d = expected.seed.slice(0, 64);
      const entry = { label, ek: hex(actual.output), dk: hex(nodeOutput(actual, KPKE_DK_ID)) };
      byD.set(d, [...(byD.get(d) ?? []), entry]);
    }
    const shared = [...byD.values()].filter((group) => group.length > 1);
    expect(shared.length, "fixture should carry a d-sharing pair").toBeGreaterThan(0);
    for (const group of shared) {
      const first = group[0] as { ek: string; dk: string };
      for (const other of group.slice(1)) {
        expect(other.ek).toBe(first.ek);
        expect(other.dk).toBe(first.dk);
      }
    }
  });
});

// ─── 2. Encrypt and Decrypt, through the FO re-encryption loop ────────────

describe("K-PKE.Encrypt and K-PKE.Decrypt against Node 24's ciphertexts", () => {
  /** ML-KEM's own derivation, run here so the specs can be checked with it. */
  const deriveKR = (m: Uint8Array, ek: Uint8Array): { k: Uint8Array; r: Uint8Array } => {
    const g = sha3_512(Uint8Array.from([...m, ...sha3_256(ek)]));
    return { k: g.slice(0, 32), r: g.slice(32, 64) };
  };

  const vectorFor = (label: string) => {
    const v = FIXTURE.vectors.find((x) => x.label === label);
    if (v === undefined) throw new Error(`no fixture vector "${label}"`);
    return v;
  };

  for (const enc of FIXTURE.encaps) {
    const v = vectorFor(enc.label);
    const ek = unhex(v.ek);
    const dk = unhex(v.dkPke);
    const c = unhex(enc.ciphertext);

    describe(`encapsulation under "${enc.label}"`, () => {
      // Decrypt first: everything else is derived from what it recovers.
      const m = run(buildKPkeDecryptSpec(dk), c).output;

      it("recovers a 32-byte message from OpenSSL's ciphertext", () => {
        expect(m).toHaveLength(32);
      });

      it("re-derives the shared secret OpenSSL reported", () => {
        // If Decrypt returned the wrong message this fails, because K is a hash
        // OF the message. So this is a real check on Decrypt, not on G.
        expect(hex(deriveKR(m, ek).k)).toBe(enc.sharedSecret);
      });

      it("re-encrypts to OpenSSL's ciphertext byte for byte", () => {
        // THE assertion of this section. Encrypt is pinned against a ciphertext
        // it did not produce, using randomness it did not choose — the strongest
        // check available without a published K-PKE vector.
        const { r } = deriveKR(m, ek);
        const cPrime = run(buildKPkeEncryptSpec(ek, r), m).output;
        expect(cPrime).toHaveLength(CIPHERTEXT_BYTES);
        expect(hex(cPrime)).toBe(enc.ciphertext);
      });
    });
  }
});

// ─── 3. Round trip — ranked LAST, on purpose ──────────────────────────────

describe("round trip", () => {
  // A pair of matched-wrong implementations passes this, exactly as CFB's
  // round-trip test documents. It is here to catch a plumbing regression on
  // messages the oracle does not cover, not to establish correctness.
  const v = FIXTURE.vectors[0] as { seed: string; ek: string; dkPke: string };
  const ek = unhex(v.ek);
  const dk = unhex(v.dkPke);

  const MESSAGES: readonly [string, Uint8Array][] = [
    ["all zero", new Uint8Array(32)],
    ["all ones", new Uint8Array(32).fill(0xff)],
    ["one bit set", Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 1 : 0))],
    ["counting", Uint8Array.from({ length: 32 }, (_, i) => i)],
  ];

  for (const [label, m] of MESSAGES) {
    it(`recovers a ${label} message`, () => {
      const r = new Uint8Array(32).fill(0x5a);
      const c = run(buildKPkeEncryptSpec(ek, r), m).output;
      expect(hex(run(buildKPkeDecryptSpec(dk), c).output)).toBe(hex(m));
    });
  }

  it("survives noise: two different r values give different ciphertexts for one message", () => {
    // The property that makes this an encryption scheme rather than an
    // encoding. Without fresh randomness per message it would be deterministic
    // and trivially distinguishable.
    const m = MESSAGES[3]?.[1] as Uint8Array;
    const c1 = run(buildKPkeEncryptSpec(ek, new Uint8Array(32).fill(1)), m).output;
    const c2 = run(buildKPkeEncryptSpec(ek, new Uint8Array(32).fill(2)), m).output;
    expect(hex(c1)).not.toBe(hex(c2));
    // …and both still decrypt to the same message.
    expect(hex(run(buildKPkeDecryptSpec(dk), c1).output)).toBe(hex(m));
    expect(hex(run(buildKPkeDecryptSpec(dk), c2).output)).toBe(hex(m));
  });
});

// ─── 4. Perturbation — run, not assumed ───────────────────────────────────

/**
 * Each of these is a wrong version that is entirely self-consistent, and the
 * point of recording them is the SHAPE of each failure: which checkpoint stays
 * green tells you where to look.
 *
 * `feedback` from two earlier plans applies — MT19937's masked shift and OFB's
 * untrimmed feedback were both perturbations that turned out to be no-ops for
 * reasons worth knowing. So each assertion below names the checkpoint that must
 * survive, not merely "something changed".
 */
describe("perturbation", () => {
  const v = FIXTURE.vectors[0] as { seed: string; ek: string; dkPke: string };
  const d = unhex(v.seed).slice(0, 32);

  it("dropping the ‖ k byte breaks ρ, and therefore everything", () => {
    // The FIPS 203 draft's spelling. Fails at checkpoint 1 — the earliest
    // possible point, which is what makes that checkpoint worth having.
    const spec = clone(buildKPkeKeyGenSpec());
    walk(spec.steps, (n) => {
      if (n.kind === "step" && n.id === "k-byte") {
        (n.params as Record<string, unknown>).bytes = [];
      }
    });
    expect(hex(run(spec, d).output.slice(-32))).not.toBe(v.ek.slice(-64));
  });

  it("swapping the s and e counters leaves ρ correct and breaks the secret key", () => {
    // The failure signature checkpoint 2 exists to catch. Both key halves are
    // still perfectly self-consistent — this key pair encrypts and decrypts its
    // own messages — it simply is not the key pair that seed defines.
    const spec = clone(buildKPkeKeyGenSpec());
    walk(spec.steps, (n) => {
      if (n.kind !== "step" || n.type !== "constant-load@1") return;
      if (n.id.startsWith("s.") && n.id.endsWith(".ctr")) {
        const i = Number(n.id.slice(2, 3));
        (n.params as Record<string, unknown>).bytes = [3 + i];
      }
      if (n.id.startsWith("e.") && n.id.endsWith(".ctr")) {
        const i = Number(n.id.slice(2, 3));
        (n.params as Record<string, unknown>).bytes = [i];
      }
    });
    const r = run(spec, d);
    expect(hex(r.output.slice(-32)), "ρ must survive — it is upstream").toBe(v.ek.slice(-64));
    expect(hex(nodeOutput(r, KPKE_DK_ID))).not.toBe(v.dkPke);
  });

  it("transposing the matrix index bytes leaves ρ AND the secret key correct", () => {
    // The subtlest of the three, and the reason checkpoint 3 is not redundant.
    // Nothing about `s` depends on the matrix, so the secret key is untouched;
    // only the public key moves.
    const spec = clone(buildKPkeKeyGenSpec());
    walk(spec.steps, (n) => {
      if (n.kind !== "step" || n.type !== "constant-load@1") return;
      if (!n.id.startsWith("A.") || !n.id.endsWith(".idx")) return;
      const bytes = (n.params as Record<string, unknown>).bytes as number[];
      (n.params as Record<string, unknown>).bytes = [bytes[1], bytes[0]];
    });
    const r = run(spec, d);
    expect(hex(r.output.slice(-32)), "ρ must survive").toBe(v.ek.slice(-64));
    expect(hex(nodeOutput(r, KPKE_DK_ID)), "the secret key must survive").toBe(v.dkPke);
    expect(hex(r.output), "but the public key must not").not.toBe(v.ek);
  });

  it("using η = 3 for the noise leaves ρ correct and breaks the secret key", () => {
    // ML-KEM-512's η₁, applied to -768. A transposed parameter-table row.
    const spec = clone(buildKPkeKeyGenSpec());
    walk(spec.steps, (n) => {
      if (n.kind !== "step") return;
      if (n.type === "ml-kem.prf@1" || n.type === "zq-cbd@1") {
        (n.params as Record<string, unknown>).eta = 3;
      }
    });
    const r = run(spec, d);
    expect(hex(r.output.slice(-32)), "ρ must survive").toBe(v.ek.slice(-64));
    expect(hex(nodeOutput(r, KPKE_DK_ID))).not.toBe(v.dkPke);
  });

  it("an element-wise product instead of the base-case multiply breaks ek only", () => {
    // The classic first mistake with a transform: `∘` looks element-wise and is
    // not, because this transform stops at 128 degree-1 polynomials. Simulated
    // by neutralising γ to 1, which is what "multiply the pairs as if X² = 1"
    // amounts to.
    const base = buildKPkeKeyGenSpec();
    const spec: CipherSpec = {
      ...base,
      cipherConstants: {
        ...base.cipherConstants,
        gamma: new Uint8Array(256).map((_, i) => (i % 2 === 0 ? 0 : 1)),
      },
    };
    const r = run(spec, d);
    expect(hex(nodeOutput(r, KPKE_DK_ID)), "the secret key must survive").toBe(v.dkPke);
    expect(hex(r.output)).not.toBe(v.ek);
  });
});

// ─── 5. Node ids, which collide SILENTLY ──────────────────────────────────

/**
 * Six embedded transforms in KeyGen and seven in Encrypt, each contributing ~66
 * nodes, alongside ~120 of their own. The flat trace keys every frame by
 * `stepId`, so two nodes sharing an id do not throw — they produce a trace with
 * duplicate keys, which takes out the scrubber, frame preservation and the graph
 * derivation with no error message at all.
 *
 * `tests/ntt-3329-256-kat.test.ts` asserts the same property over two synthetic
 * `buildNttGroup` calls. That checks the helper; this checks the thing actually
 * shipped, where the transforms are mixed in with everything else and the
 * near-misses live (`t.0` is both the dot-product prefix of `t.0.mul0` and the
 * final add — confusing, and deliberately confirmed non-colliding).
 */
describe("every shipped K-PKE spec has globally distinct node ids", () => {
  const v = FIXTURE.vectors[0] as { ek: string; dkPke: string };

  const specs: readonly [string, CipherSpec][] = [
    ["keygen", buildKPkeKeyGenSpec()],
    ["encrypt", buildKPkeEncryptSpec(unhex(v.ek), new Uint8Array(32).fill(3))],
    ["decrypt", buildKPkeDecryptSpec(unhex(v.dkPke))],
  ];

  for (const [label, spec] of specs) {
    it(`${label} repeats no id`, () => {
      const ids: string[] = [];
      walk(spec.steps, (n) => ids.push(n.id));
      const duplicates = ids.filter((id, i) => ids.indexOf(id) !== i);
      expect(duplicates, `duplicated ids in the ${label} spec`).toEqual([]);
      // A floor: if the walk stopped at the top level it would find no
      // duplicates and prove nothing. KeyGen alone is ~485 nodes.
      expect(ids.length).toBeGreaterThan(280);
    });
  }
});
