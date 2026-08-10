/**
 * ML-KEM-768 known-answer tests (FIPS 203 §7).
 * `docs/plans/unified-stargazing-quasar.md`, P4.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ORACLE, AND WHY IT REACHES FURTHER THAN P3'S
 *
 * `tests/fixtures/ml-kem-768-seed-vectors.json`, captured from Node 24's
 * OpenSSL because CI runs Node 22. P3 used its key-generation half; this file
 * uses the rest, and the rest is what makes it a KEM test rather than a
 * lattice-arithmetic test:
 *
 *   - `ciphertext`      — an encapsulation OpenSSL produced under a key of ours.
 *   - `sharedSecret`    — what OpenSSL says that ciphertext decapsulates to.
 *   - `rejectedSharedSecret` — what it decapsulates to after ONE BIT is flipped.
 *
 * That last field is the strongest assertion available in P4 and the reason the
 * fixture was built the way it was. Implicit rejection is invisible to every
 * round-trip test — a wrong-but-consistent implementation returns a wrong-but-
 * consistent decoy and nothing complains — so the only way to check it is
 * against somebody else's bytes.
 *
 * **The corruption is `c[0] ^= 0x01`.** The fixture records the flag
 * `corruptedCiphertextFlipsByte0` but NOT the value, and the value matters: a
 * different flip decapsulates to a different decoy, which reads as a broken
 * implementation. It is `0x01` in the harvest script, and it is spelled out
 * here so the next reader does not have to rediscover it (this test's author
 * did, by trying `0xff` first and getting a mismatch that looked like a bug).
 *
 * ──────────────────────────────────────────────────────────────────────────
 * RANKED BY WHAT DISCRIMINATES
 *
 *   1. The key-generation checkpoints (`ek`, `dk_PKE`, `H(ek)`), which localise
 *      any failure before the KEM layer is even reached.
 *   2. Decapsulating OpenSSL's ciphertext to OpenSSL's shared secret. This pins
 *      the whole chain at once: a wrong K-PKE decryption gives a wrong `m′`,
 *      which gives a wrong `(K′, r′)`, which fails the re-encryption check and
 *      returns a decoy — so agreement here is not a coincidence.
 *   3. **Implicit rejection**, against `rejectedSharedSecret`.
 *   4. §7.1's `d ‖ z` split, asserted through our own specs on a seed pair that
 *      shares `d`: identical keys, identical secret for a valid ciphertext, and
 *      DIFFERENT secrets for a corrupted one.
 *   5. Perturbations, each pinning the failure signature of a published fact
 *      whose wrong version is self-consistent.
 *   6. Round trip, LAST, as always.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  MLKEM_DK_SPLIT_ID,
  MLKEM_KEYPAIR_ID,
  MLKEM_KR_ID,
  MLKEM_REENCRYPT_ID,
  MLKEM_REJECTION_ID,
  MLKEM_SELECT_ID,
  ML_KEM_CIPHERTEXT_BYTES,
  ML_KEM_DEFAULT_CIPHERTEXT,
  ML_KEM_DEFAULT_MESSAGE,
  ML_KEM_DEFAULT_SEED,
  ML_KEM_DEFAULT_SHARED_SECRET,
  ML_KEM_DK_BYTES,
  ML_KEM_EK_BYTES,
  buildMlKemDecapsSpec,
  buildMlKemEncapsSpec,
} from "@/ciphers/ml-kem-768";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";
import FIXTURE from "./fixtures/ml-kem-768-seed-vectors.json";

const registry = buildDefaultRegistry();

/**
 * `Uint8Array<ArrayBufferLike>` rather than the bare `Uint8Array` used in most
 * of the suite. A trace frame's port maps carry the wider form, and mixing the
 * two produces a wall of `SharedArrayBuffer is not assignable` noise, so this
 * file names it once. It is also why `hex` formats by hand instead of going
 * through `Buffer.from`, whose overloads reject the wider type.
 */
type Bytes = Uint8Array<ArrayBufferLike>;

const hex = (b: Bytes): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
// Copied into a freshly allocated array rather than wrapping the `Buffer`:
// every constructor overload that takes one yields the WIDER
// `Uint8Array<ArrayBufferLike>`, which the spec builders' plain `Uint8Array`
// parameters then reject.
const unhex = (s: string): Uint8Array => {
  const buf = Buffer.from(s, "hex");
  const out = new Uint8Array(buf.length);
  out.set(buf);
  return out;
};

/** The fixture's corruption, spelled out — see the header. */
const flipFirstBit = (c: Uint8Array): Uint8Array => {
  const out = c.slice();
  out[0] = ((out[0] as number) ^ 0x01) & 0xff;
  return out;
};

type Run = {
  readonly output: Bytes;
  /** Every port of every leaf, keyed by node id. */
  readonly byNode: ReadonlyMap<string, ReadonlyMap<string, Bytes>>;
};

const run = (spec: CipherSpec, input: Uint8Array): Run => {
  const trace = runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: input },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");
  const byNode = new Map<string, ReadonlyMap<string, Bytes>>();
  for (const frame of trace.frames) {
    if (frame.portOutputs !== undefined) byNode.set(frame.stepId, new Map(frame.portOutputs));
  }
  return { output: trace.finalState.bytes, byNode };
};

const nodePort = (r: Run, id: string, portName: string): Bytes => {
  const value = r.byNode.get(id)?.get(portName);
  if (value === undefined) throw new Error(`no "${portName}" port on node "${id}"`);
  return value;
};

/** Deep-clone so a perturbation cannot leak into the next test. */
const clone = (spec: CipherSpec): CipherSpec => structuredClone(spec) as CipherSpec;

/** Walk every node, including inside groups and iterates. */
const walk = (nodes: readonly StepNode[], visit: (n: StepNode) => void): void => {
  for (const n of nodes) {
    visit(n);
    if (n.kind !== "step") walk(n.children, visit);
  }
};

const vectorFor = (label: string) => {
  const v = FIXTURE.vectors.find((x) => x.label === label);
  if (v === undefined) throw new Error(`no fixture vector "${label}"`);
  return v;
};

// ─── 0. The defaults are the fixture's, not invented ──────────────────────

describe("the app's defaults are somebody else's test vector", () => {
  it("the default seed is the fixture's `counting` vector", () => {
    expect(hex(ML_KEM_DEFAULT_SEED)).toBe(vectorFor("counting").seed);
  });

  it("the default ciphertext is OpenSSL's encapsulation under that seed", () => {
    const enc = FIXTURE.encaps.find((e) => e.label === "counting");
    expect(enc?.ciphertext).toBe(hex(ML_KEM_DEFAULT_CIPHERTEXT));
    // So the very first Run in the decapsulation direction reproduces a shared
    // secret a different implementation reported. The constant naming it is not
    // read by the app; this is what keeps it honest.
    expect(enc?.sharedSecret).toBe(ML_KEM_DEFAULT_SHARED_SECRET);
  });

  it("the first Run in the decapsulation direction lands on that secret", () => {
    const r = run(buildMlKemDecapsSpec(), ML_KEM_DEFAULT_CIPHERTEXT);
    expect(hex(r.output)).toBe(ML_KEM_DEFAULT_SHARED_SECRET);
  });
});

// ─── 1–3. Per encapsulation vector: keys, agreement, rejection ────────────

describe("ML-KEM-768 against Node 24's OpenSSL", () => {
  for (const enc of FIXTURE.encaps) {
    const v = vectorFor(enc.label);

    describe(`under the "${enc.label}" seed`, () => {
      const seed = unhex(v.seed);
      const valid = run(buildMlKemDecapsSpec(seed), unhex(enc.ciphertext));

      // ── 1. Key generation, inside the collapsed group ──────────────────
      //
      // Checked first because every later failure would be downstream of these,
      // and a failure that names its own cause is the whole reason the fixture
      // stores the halves separately.

      it("derives OpenSSL's encapsulation key from the seed", () => {
        expect(hex(nodePort(valid, MLKEM_KEYPAIR_ID, "output0"))).toBe(v.ek);
      });

      it("assembles dk as dk_PKE ‖ ek ‖ H(ek) ‖ z, at FIPS 203 §7.1's offsets", () => {
        // Asserted through the PARSE, not the assembly: these are the four
        // values decapsulation actually reads, so an offset error shows up here
        // rather than in a concatenation that happens to be self-consistent.
        expect(hex(nodePort(valid, MLKEM_DK_SPLIT_ID, "output0"))).toBe(v.dkPke);
        expect(hex(nodePort(valid, MLKEM_DK_SPLIT_ID, "output1"))).toBe(v.ek);
        expect(hex(nodePort(valid, MLKEM_DK_SPLIT_ID, "output2"))).toBe(v.hEk);
        expect(hex(nodePort(valid, MLKEM_DK_SPLIT_ID, "output3"))).toBe(v.seed.slice(64));
      });

      // ── 2. The shared secret ───────────────────────────────────────────

      it("decapsulates OpenSSL's ciphertext to OpenSSL's shared secret", () => {
        expect(hex(valid.output)).toBe(enc.sharedSecret);
      });

      it("re-encrypts to the ciphertext it was given, byte for byte", () => {
        // The check itself, made visible. If this held only approximately the
        // select would reject and the assertion above would still fail — but it
        // would fail without saying WHY, and this is the why.
        expect(hex(nodePort(valid, MLKEM_REENCRYPT_ID, "output"))).toBe(enc.ciphertext);
      });

      // ── 3. Implicit rejection ──────────────────────────────────────────

      // One run, three claims. Each decapsulation here costs ~0.8 s of real
      // work, so runs are hoisted and shared rather than repeated per
      // assertion — the whole suite runs 312 files in parallel and this file is
      // heavy enough to starve the timeout-sensitive jsdom tests if it is
      // careless.
      const rejected = run(buildMlKemDecapsSpec(seed), flipFirstBit(unhex(enc.ciphertext)));

      it("returns OpenSSL's DECOY secret for a ciphertext with one bit flipped", () => {
        expect(hex(rejected.output)).toBe(enc.rejectedSharedSecret);
        // Two things a "different secret" assertion alone would not catch: that
        // it is not the real one, and that it is not the decoy of some OTHER
        // ciphertext.
        expect(hex(rejected.output)).not.toBe(enc.sharedSecret);
      });

      it("returns a secret rather than throwing, which is the entire design", () => {
        // The run above already completed, which IS the assertion — a throw
        // would have taken the whole describe block down before any test ran.
        // Stated explicitly because it is the design decision, not a detail.
        expect(rejected.output.length).toBe(32);
      });
    });
  }
});

// ─── 4. §7.1's d ‖ z split, through our own specs ─────────────────────────

describe("z generates nothing and rejects everything", () => {
  // The fixture asserts this property of ITS OWN bytes; this asserts it of the
  // shipped specs, which is a different claim. Two seeds agreeing on d and
  // differing on z must be indistinguishable until a ciphertext fails.
  const zeroZ = unhex(vectorFor("shared-d/zero-z").seed);
  const ffZ = unhex(vectorFor("shared-d/ff-z").seed);
  const c = unhex(FIXTURE.sharedDCross.ciphertext);

  const underZero = run(buildMlKemDecapsSpec(zeroZ), c);
  const underFf = run(buildMlKemDecapsSpec(ffZ), c);

  it("produces identical key pairs from the two seeds", () => {
    expect(hex(nodePort(underZero, MLKEM_KEYPAIR_ID, "output0"))).toBe(
      hex(nodePort(underFf, MLKEM_KEYPAIR_ID, "output0")),
    );
    expect(hex(nodePort(underZero, MLKEM_DK_SPLIT_ID, "output0"))).toBe(
      hex(nodePort(underFf, MLKEM_DK_SPLIT_ID, "output0")),
    );
  });

  it("decapsulates a VALID ciphertext identically under both", () => {
    expect(hex(underZero.output)).toBe(hex(underFf.output));
    expect(hex(underZero.output)).toBe(FIXTURE.sharedDCross.validUnderZeroZ);
    expect(hex(underFf.output)).toBe(FIXTURE.sharedDCross.validUnderFfZ);
  });

  it("but decapsulates a CORRUPTED one differently, because that path reads z", () => {
    const corrupted = flipFirstBit(c);
    const rejZero = run(buildMlKemDecapsSpec(zeroZ), corrupted);
    const rejFf = run(buildMlKemDecapsSpec(ffZ), corrupted);
    expect(hex(rejZero.output)).toBe(FIXTURE.sharedDCross.rejectedUnderZeroZ);
    expect(hex(rejFf.output)).toBe(FIXTURE.sharedDCross.rejectedUnderFfZ);
    expect(hex(rejZero.output)).not.toBe(hex(rejFf.output));
  });
});

// ─── 5. Perturbations — the failure signatures, pinned ────────────────────

describe("published facts whose wrong versions are self-consistent", () => {
  const seed = unhex(vectorFor("counting").seed);
  const enc = FIXTURE.encaps.find((e) => e.label === "counting");
  if (enc === undefined) throw new Error("no `counting` encapsulation");
  const c = unhex(enc.ciphertext);
  const corrupted = flipFirstBit(c);

  /** Rebind one input port of one node. */
  const rewire = (
    spec: CipherSpec,
    nodeId: string,
    portName: string,
    source: { node: string; port: string },
  ): CipherSpec => {
    const copy = clone(spec);
    let found = false;
    walk(copy.steps, (n) => {
      if (n.id !== nodeId || n.kind !== "step") return;
      found = true;
      (n as { portInputs?: Record<string, unknown> }).portInputs = {
        ...(n.portInputs ?? {}),
        [portName]: source,
      };
    });
    if (!found) throw new Error(`no node "${nodeId}" to rewire`);
    return copy;
  };

  it("J(z ‖ c) takes the RECEIVED ciphertext, never the re-encryption", () => {
    // The wrong version is invisible on a valid ciphertext — the two are equal
    // by definition when the check passes — so this is exactly the kind of bug
    // a round trip cannot see. It bites only on the rejection path.
    //
    // **Writing it required moving two nodes, and that is itself a finding.**
    // `j-in` sits before the re-encryption in spec order, and the runtime's
    // same-scope wiring is forward-only: binding it to `re.c` where it stands
    // throws `references upstream node 're.c' which has no recorded outputs`.
    // So the mistake cannot be made by a one-line slip — an author would have to
    // relocate the rejection KDF past the check first. A weak guard, but a real
    // one, and worth knowing before trusting the ordering elsewhere.
    const copy = clone(buildMlKemDecapsSpec(seed));
    const moved = copy.steps.filter((n) => n.id === "j-in" || n.id === MLKEM_REJECTION_ID);
    const rest = copy.steps.filter((n) => n.id !== "j-in" && n.id !== MLKEM_REJECTION_ID);
    const selectAt = rest.findIndex((n) => n.id === MLKEM_SELECT_ID);
    const reordered: CipherSpec = {
      ...copy,
      steps: [...rest.slice(0, selectAt), ...moved, ...rest.slice(selectAt)],
    };
    const wrong = rewire(reordered, "j-in", "input1", {
      node: MLKEM_REENCRYPT_ID,
      port: "output",
    });

    expect(hex(run(wrong, c).output), "valid ciphertext: no observable change").toBe(
      enc.sharedSecret,
    );
    expect(hex(run(wrong, corrupted).output), "corrupted: the decoy is now wrong").not.toBe(
      enc.rejectedSharedSecret,
    );
  });

  it("G's FIRST half is the shared secret and its second is the randomness", () => {
    // Swapping them keeps decapsulation entirely self-consistent — it would
    // still re-encrypt, still compare, still return a stable secret — and agree
    // with no other implementation on either the ciphertext or the key.
    const wrong = rewire(buildMlKemDecapsSpec(seed), MLKEM_SELECT_ID, "shared", {
      node: MLKEM_KR_ID,
      port: "output1",
    });
    expect(hex(run(wrong, c).output)).not.toBe(enc.sharedSecret);
  });

  it("the dk parse offsets are load-bearing, and getting them wrong is SILENT", () => {
    // Shift the split by one byte. K-PKE decryption cannot fail, so nothing
    // throws: every ciphertext simply decapsulates to a decoy. That is the
    // behaviour a correct implementation has for a FORGED ciphertext, which is
    // why this failure mode is worth pinning rather than trusting to noticing.
    const copy = clone(buildMlKemDecapsSpec(seed));
    walk(copy.steps, (n) => {
      if (n.id === MLKEM_DK_SPLIT_ID && n.kind === "step") {
        (n as { params: Record<string, unknown> }).params = {
          widths: [ML_KEM_DK_BYTES - ML_KEM_EK_BYTES - 63, ML_KEM_EK_BYTES, 32, 31],
        };
      }
    });
    let out: Bytes | null = null;
    expect(() => {
      out = run(copy, c).output;
    }, "a wrong parse must not throw — that is the point").not.toThrow();
    expect(out).not.toBeNull();
    expect(hex(out as unknown as Bytes)).not.toBe(enc.sharedSecret);
  });
});

// ─── 6. Round trip, last ──────────────────────────────────────────────────

describe("encapsulation and decapsulation agree", () => {
  // Ranked last on purpose: two matched-wrong implementations pass this, and
  // here they are not even two implementations — both directions share the same
  // key generation and the same K-PKE encryption code. What it does check is
  // that the FO wiring composes: encapsulation's K reaches decapsulation
  // through nothing but the 1088 bytes it emitted.
  const encaps = run(buildMlKemEncapsSpec(), ML_KEM_DEFAULT_MESSAGE);

  it("encapsulation emits a full-width ciphertext", () => {
    expect(encaps.output.length).toBe(ML_KEM_CIPHERTEXT_BYTES);
  });

  it("decapsulating it recovers the shared secret encapsulation settled on", () => {
    const K = nodePort(encaps, MLKEM_KR_ID, "output0");
    expect(hex(run(buildMlKemDecapsSpec(), encaps.output).output)).toBe(hex(K));
  });

  it("and one flipped bit of that ciphertext yields the decoy instead", () => {
    const K = nodePort(encaps, MLKEM_KR_ID, "output0");
    const rejected = run(buildMlKemDecapsSpec(), flipFirstBit(encaps.output));
    expect(hex(rejected.output)).not.toBe(hex(K));
    // Determinism — the same bad ciphertext always yielding the same decoy, so
    // that retrying tells an attacker nothing — is not re-asserted with a
    // second run here. It is already pinned four times over: every
    // `rejectedSharedSecret` above is a value OpenSSL computed on a different
    // machine and we reproduced.
  });
});
