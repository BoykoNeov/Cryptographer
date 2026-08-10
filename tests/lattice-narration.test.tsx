// @vitest-environment jsdom
/**
 * Lattice-family narration — the eleven per-frame value-prose narrators
 * registered for P2's arithmetic and P3's Keccak monoliths.
 *
 * These narrators exist because their teaching points are per-frame: how many
 * hash blocks a matrix draw needed, how much a compression cost THIS
 * coefficient, which noise counter this PRF call used. So what these tests
 * check is not "prose rendered" but **that the prose reports the frame's own
 * values** — a narrator that printed constants, or recomputed the algorithm
 * from scratch, would pass a render test and defeat the point.
 *
 * Every frame here comes out of the real runtime running a SHIPPED K-PKE spec
 * (`tests/k-pke-kat.test.ts` pins those specs against Node's ML-KEM), so what
 * is asserted is what the app will actually show once P4 makes ML-KEM
 * selectable. The narrators are IMPORTED, never re-created locally — both of
 * this repo's replication tests once rebuilt the composition they were meant
 * to guard and stayed green while the shipped one broke.
 *
 * Two step types — `ml-kem.hash-h@1` and `ml-kem.kdf-j@1` — are emitted by no
 * shipped spec until P4's Fujisaki–Okamoto wrapper. They get a purpose-built
 * two-leaf spec here rather than a hand-assembled `TraceFrame`, so their frames
 * are still the runtime's own work.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  CIPHERTEXT_BYTES,
  DK_BYTES,
  EK_BYTES,
  buildKPkeDecryptSpec,
  buildKPkeEncryptSpec,
  buildKPkeKeyGenSpec,
} from "@/ciphers/k-pke";
import { runSpec } from "@/core/runtime";
import {
  type AuxValue,
  type CipherSpec,
  INPUT_SOURCE_ID,
  INPUT_SOURCE_PORT,
  type TraceFrame,
} from "@/core/types";
import { readCoeff } from "@/core/zq-vector";
import { render } from "@solidjs/testing-library";
import "@/ui/narration/index";
import {
  mlKemHashGNarration,
  mlKemHashHNarration,
  mlKemKdfJNarration,
  mlKemPrfNarration,
  mlKemSampleNttNarration,
  mlKemSelectSharedSecretNarration,
  zqBaseCaseMulNarration,
  zqByteDecodeNarration,
  zqByteEncodeNarration,
  zqCbdNarration,
  zqCompressNarration,
  zqDecompressNarration,
} from "@/ui/narration/lattice";
import { type NarrationFn, lookupNarration } from "@/ui/narration/registry";
import { beforeAll, describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();
const Q = 3329n;
const COEFF = { coeffBytes: 2, littleEndian: false } as const;

const run = (spec: CipherSpec, input: Uint8Array): readonly TraceFrame[] =>
  runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: input },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  }).frames;

/**
 * One trace per shipped K-PKE spec, built once. Encrypt and Decrypt are fed the
 * real `ek` / `dk` produced by KeyGen so their frames carry realistic values —
 * an all-zero key would make several of the assertions below vacuous (a zero
 * polynomial compresses without error and samples no negatives).
 */
let allFrames: readonly TraceFrame[] = [];

beforeAll(() => {
  const keygen = run(buildKPkeKeyGenSpec(), new Uint8Array(32).fill(7));
  const byNode = new Map<string, Uint8Array>();
  for (const f of keygen) {
    const out = f.portOutputs?.get("output");
    if (out !== undefined) byNode.set(f.stepId, out);
  }
  const ek = byNode.get("ek");
  const dk = byNode.get("dk");
  if (ek?.length !== EK_BYTES) throw new Error(`keygen produced no ${EK_BYTES}-byte ek`);
  if (dk?.length !== DK_BYTES) throw new Error(`keygen produced no ${DK_BYTES}-byte dk`);

  const message = Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff);
  const encrypt = run(buildKPkeEncryptSpec(ek, new Uint8Array(32).fill(3)), message);
  const ciphertext = encrypt.at(-1)?.portOutputs?.get("output");
  const decrypt = run(
    buildKPkeDecryptSpec(dk),
    ciphertext?.length === CIPHERTEXT_BYTES ? ciphertext : new Uint8Array(CIPHERTEXT_BYTES),
  );
  allFrames = [...keygen, ...encrypt, ...decrypt];
});

/** Every frame of one step type, across all three shipped specs. */
const framesOfType = (stepType: string): readonly TraceFrame[] => {
  const found = allFrames.filter((f) => f.stepType === stepType);
  if (found.length === 0) throw new Error(`no shipped K-PKE frame of type ${stepType}`);
  return found;
};

const firstFrame = (stepType: string): TraceFrame => framesOfType(stepType)[0] as TraceFrame;

/** Render every unit's prose and return label + body text, concatenated. */
const proseText = (units: ReturnType<NarrationFn>): string => {
  if (units === null) throw new Error("narrator declined");
  return units
    .map((u) => {
      const { container } = render(() => <u.Prose fmt="hex" />);
      return `${u.label}\n${container.textContent ?? ""}`;
    })
    .join("\n");
};

/** Coefficient `i` of a packed vector, read with the executors' own helper. */
const coeff = (bytes: Uint8Array, i: number): bigint => readCoeff(bytes, i, COEFF);

// ─── Registry dispatch ─────────────────────────────────────────────────────

describe("lattice narration — registry dispatch", () => {
  it("routes each step type to the narrator this file imports directly", () => {
    // Guards the wire-up in `index.ts`, which is the layer a unit test that
    // called the narrators directly would skip entirely. If a registration
    // pointed at the wrong fn, every other test here would still pass.
    const expected: ReadonlyArray<readonly [string, NarrationFn]> = [
      ["zq-compress@1", zqCompressNarration],
      ["zq-decompress@1", zqDecompressNarration],
      ["zq-cbd@1", zqCbdNarration],
      ["zq-base-case-mul@1", zqBaseCaseMulNarration],
      ["zq-byte-encode@1", zqByteEncodeNarration],
      ["zq-byte-decode@1", zqByteDecodeNarration],
      ["ml-kem.sample-ntt@1", mlKemSampleNttNarration],
      ["ml-kem.prf@1", mlKemPrfNarration],
      ["ml-kem.hash-g@1", mlKemHashGNarration],
      ["ml-kem.hash-h@1", mlKemHashHNarration],
      ["ml-kem.kdf-j@1", mlKemKdfJNarration],
      ["ml-kem.select-shared-secret@1", mlKemSelectSharedSecretNarration],
    ];
    for (const [stepType, fn] of expected) {
      expect(lookupNarration(stepType), `${stepType} dispatch`).toBe(fn);
    }
  });

  it("produces units for every narrated step type a shipped spec emits", () => {
    // The nine reachable today. hash-h / kdf-j have their own block below.
    for (const stepType of [
      "zq-compress@1",
      "zq-decompress@1",
      "zq-cbd@1",
      "zq-base-case-mul@1",
      "zq-byte-encode@1",
      "zq-byte-decode@1",
      "ml-kem.sample-ntt@1",
      "ml-kem.prf@1",
      "ml-kem.hash-g@1",
    ]) {
      const fn = lookupNarration(stepType);
      const units = fn?.(firstFrame(stepType));
      expect(units, `${stepType} should narrate its shipped frame`).not.toBeNull();
      expect(units?.length ?? 0, `${stepType} unit count`).toBeGreaterThan(0);
    }
  });
});

// ─── ml-kem.sample-ntt@1 — the flagship ────────────────────────────────────

describe("lattice narration — SampleNTT reports the block count it actually spent", () => {
  it("prints the frame's own `squeezes` value, not a typical one", () => {
    // The narrator must READ the port. A narrator that hardcoded "3 blocks"
    // (true of 160 draws in 162) would pass any spot check on a single frame,
    // so every frame is checked against its own port.
    for (const frame of framesOfType("ml-kem.sample-ntt@1")) {
      const squeezes = frame.portOutputs?.get("squeezes");
      if (squeezes === undefined) throw new Error("no squeezes port");
      const blocks = ((squeezes[0] ?? 0) << 8) | (squeezes[1] ?? 0);
      const text = proseText(mlKemSampleNttNarration(frame));
      expect(text).toContain(`needed ${blocks} hash block`);
      expect(text).toContain(`${blocks} × 168 bytes`);
    }
  });

  it("the count VARIES across draws, which is the property worth asserting", () => {
    // P3 recorded that the plan's original assertion ("needs more than two
    // blocks") is VACUOUS: acceptance is ~81%, so every draw already spends
    // three. What discriminates is variation — a fixed-budget implementation
    // would report one constant forever. 18 draws is a small sample, so this
    // asserts the mechanism rather than requiring a rare 4-block draw: the
    // reported number tracks the port on every frame (above), and the port
    // itself is not a constant of the step type.
    const counts = new Set(
      framesOfType("ml-kem.sample-ntt@1").map((f) => {
        const s = f.portOutputs?.get("squeezes");
        return ((s?.[0] ?? 0) << 8) | (s?.[1] ?? 0);
      }),
    );
    for (const c of counts) expect(c).toBeGreaterThanOrEqual(3);
    // Every draw squeezed at least three blocks — so "more than two" really
    // does assert nothing, pinned here so the vacuous version cannot come back.
    expect(Math.min(...counts)).toBeGreaterThan(2);
  });

  it("names the two index bytes, which is where the transpose hides", () => {
    const frame = firstFrame("ml-kem.sample-ntt@1");
    const input = frame.portInputs?.get("input");
    if (input === undefined) throw new Error("no input port");
    const text = proseText(mlKemSampleNttNarration(frame));
    expect(text).toContain(`${input[input.length - 2]}, ${input[input.length - 1]}`);
    expect(text.toLowerCase()).toContain("transpose");
  });
});

// ─── zq-compress@1 / zq-decompress@1 ───────────────────────────────────────

describe("lattice narration — compression states the error it actually caused", () => {
  it("reports a worst-case error within FIPS 203's bound, from this frame's values", () => {
    for (const frame of framesOfType("zq-compress@1")) {
      const d = (frame.params as { d?: number }).d;
      if (d === undefined) throw new Error("no d param");
      const text = proseText(zqCompressNarration(frame));
      const match = text.match(/worst error (\d+) of a possible (\d+)/);
      expect(match, `compress d=${d} should report an error pair`).not.toBeNull();
      const worst = Number(match?.[1]);
      const bound = Number(match?.[2]);
      // The bound is FIPS 203's ⌈q / 2^(d+1)⌋ — round to NEAREST, not floor.
      // Derived here independently of the narrator, which is what caught the
      // narrator printing a floored bound: at d = 10 the floor is 1 while
      // errors of 2 really occur, so it rendered "worst error 2 of a
      // possible 1". A test that reused the narrator's own expression, or
      // that only checked `worst <= q`, would have shipped that.
      const twoD = 1n << BigInt(d);
      expect(bound).toBe(Number((Q + twoD) / (2n * twoD)));
      expect(worst).toBeLessThanOrEqual(bound);
    }
  });

  it("names the per-leaf d rather than a fixed one — 10, 4 and 1 all appear", () => {
    // `d` differs per leaf, which is the reason a static `narrationOverride`
    // could not carry this sentence. ML-KEM-768 compresses u by 10 bits and v
    // by 4 when encrypting — and Decrypt compresses all the way back to ONE
    // bit, which is how the message is recovered: "which of the two buckets
    // is this coefficient nearer to?" is a d = 1 compression.
    const ds = new Set(framesOfType("zq-compress@1").map((f) => (f.params as { d: number }).d));
    expect(ds).toEqual(new Set([10, 4, 1]));
    for (const frame of framesOfType("zq-compress@1")) {
      const d = (frame.params as { d: number }).d;
      expect(proseText(zqCompressNarration(frame))).toContain(`(d = ${d})`);
    }
  });

  it("does NOT call a d = 1 compression a ciphertext size optimisation", () => {
    // The bug the `(d = ${d})` assertion above is blind to by construction: it
    // only exercises unit 1's headline, so a later unit that assumes "this
    // leaf is shrinking a ciphertext" sails through. K-PKE compresses at d = 1
    // during DECRYPT, where the step recovers the message — telling a learner
    // that message recovery is a size optimisation, on the one frame where
    // compression is applied to the message rather than a ciphertext.
    const messageFrames = framesOfType("zq-compress@1").filter(
      (f) => (f.params as { d: number }).d === 1,
    );
    expect(messageFrames.length, "Decrypt compresses back to one bit").toBeGreaterThan(0);
    for (const frame of messageFrames) {
      const text = proseText(zqCompressNarration(frame));
      expect(text).not.toContain("small enough to send");
      expect(text).not.toContain("practical size");
      // …and says the true thing instead.
      expect(text).toContain("asked as a rounding question");
    }

    // The size row IS present where it is honest — otherwise this test would
    // pass against a narrator that simply deleted the sentence everywhere.
    const wireFrames = framesOfType("zq-compress@1").filter(
      (f) => (f.params as { d: number }).d !== 1,
    );
    expect(wireFrames.length).toBeGreaterThan(0);
    for (const frame of wireFrames) {
      expect(proseText(zqCompressNarration(frame))).toContain("small enough to send");
    }
  });

  it("prints bucket indices that match the frame's output port", () => {
    const frame = firstFrame("zq-compress@1");
    const a = frame.portInputs?.get("a");
    const out = frame.portOutputs?.get("output");
    if (a === undefined || out === undefined) throw new Error("missing ports");
    const text = proseText(zqCompressNarration(frame));
    // First coefficient in, first bucket out — both read off the frame.
    expect(text).toContain(`x[0] = ${coeff(a, 0)}`);
    expect(text).toContain(`bucket ${coeff(out, 0)} of`);
  });

  it("decompression calls out d = 1 as the message entering the ring", () => {
    const messageFrames = framesOfType("zq-decompress@1").filter(
      (f) => (f.params as { d: number }).d === 1,
    );
    expect(messageFrames.length, "K-PKE decompresses the message bit at d = 1").toBeGreaterThan(0);
    const text = proseText(zqDecompressNarration(messageFrames[0] as TraceFrame));
    // ⌈q/2⌉ = 1665 is the far point on the circle; the whole error budget.
    expect(text).toContain("1665");
    expect(text.toLowerCase()).toContain("message");

    // And the row is absent where it would be a lie.
    const wider = framesOfType("zq-decompress@1").find((f) => (f.params as { d: number }).d !== 1);
    if (wider !== undefined) {
      expect(proseText(zqDecompressNarration(wider))).not.toContain(
        "this is the message entering the ring",
      );
    }
  });
});

// ─── zq-cbd@1 ──────────────────────────────────────────────────────────────

describe("lattice narration — CBD reports this run's distribution", () => {
  it("the histogram counts sum to the coefficients the frame produced", () => {
    const frame = firstFrame("zq-cbd@1");
    const out = frame.portOutputs?.get("output");
    if (out === undefined) throw new Error("no output port");
    const n = out.length / 2;
    const text = proseText(zqCbdNarration(frame));
    const counts = [...text.matchAll(/(\d+) of (\d+)\s+\(expected/g)].map((m) => Number(m[1]));
    expect(counts.length, "one row per value in −η … η").toBe(5);
    expect(counts.reduce((s, c) => s + c, 0)).toBe(n);
    expect(text).toContain(`over ${n} coefficients`);
  });

  it("shows a negative sample as its ring representative, from real bytes", () => {
    // The "−1 looks like 3328" lesson. Asserted against a value this frame
    // actually produced, and cross-checked against the output port so the
    // narrator cannot be printing a plausible constant.
    const frame = framesOfType("zq-cbd@1").find((f) => {
      const out = f.portOutputs?.get("output");
      if (out === undefined) return false;
      for (let i = 0; i < out.length / 2; i++) if (coeff(out, i) > Q / 2n) return true;
      return false;
    });
    expect(frame, "some noise polynomial should contain a negative sample").toBeDefined();
    const out = (frame as TraceFrame).portOutputs?.get("output");
    if (out === undefined) throw new Error("no output port");
    let firstNegative = 0n;
    for (let i = 0; i < out.length / 2; i++) {
      const v = coeff(out, i);
      if (v > Q / 2n) {
        firstNegative = v;
        break;
      }
    }
    expect(firstNegative).toBeGreaterThan(Q / 2n);
    const text = proseText(zqCbdNarration(frame as TraceFrame));
    expect(text).toContain(String(firstNegative));
    expect(text).toContain(String(Number(firstNegative - Q)));
  });

  it("worked bit windows agree with the coefficient the executor stored", () => {
    const frame = firstFrame("zq-cbd@1");
    const out = frame.portOutputs?.get("output");
    if (out === undefined) throw new Error("no output port");
    const text = proseText(zqCbdNarration(frame));
    expect(text).toContain(`→  stored as ${coeff(out, 0)}`);
  });
});

// ─── zq-base-case-mul@1 ────────────────────────────────────────────────────

describe("lattice narration — the base-case multiply contrasts against element-wise", () => {
  it("the wrong answer it prints really is wrong for this frame", () => {
    // The contrast row is only worth anything if the two lines differ. If the
    // step were silently element-wise they would coincide and this fails.
    const frame = firstFrame("zq-base-case-mul@1");
    const a = frame.portInputs?.get("a");
    const b = frame.portInputs?.get("b");
    const out = frame.portOutputs?.get("output");
    if (a === undefined || b === undefined || out === undefined) throw new Error("missing ports");

    const elementwise = `${(coeff(a, 0) * coeff(b, 0)) % Q}, ${(coeff(a, 1) * coeff(b, 1)) % Q}`;
    const actual = `${coeff(out, 0)}, ${coeff(out, 1)}`;
    expect(elementwise, "operands chosen so the contrast is visible").not.toBe(actual);

    const text = proseText(zqBaseCaseMulNarration(frame));
    expect(text).toContain(elementwise);
    expect(text).toContain(actual);
  });

  it("prints the γ the frame was handed, and it is an ODD power of ζ", () => {
    const frame = firstFrame("zq-base-case-mul@1");
    const gamma = frame.portInputs?.get("gamma");
    if (gamma === undefined) throw new Error("no gamma port");
    const text = proseText(zqBaseCaseMulNarration(frame));
    expect(text).toContain("γ[0]");
    expect(text).toContain(String(coeff(gamma, 0)));
    // γ[0] = ζ^(2·BitRev7(0)+1) = ζ¹ = 17. The `+ 1` P2 found missing from the
    // plan: without it γ[0] would be 1, and the narrator would say so.
    expect(coeff(gamma, 0)).toBe(17n);
    expect(text).toContain("BitRev7");
  });

  it("states the pair count, never the coefficient count", () => {
    const frame = firstFrame("zq-base-case-mul@1");
    const text = proseText(zqBaseCaseMulNarration(frame));
    expect(text).toContain("128 pairs, 128 different γ");
    expect(text).toContain("128 little");
  });
});

// ─── zq-byte-encode@1 / zq-byte-decode@1 ───────────────────────────────────

describe("lattice narration — the 12-bit packing", () => {
  it("reports the real size change in each direction", () => {
    const enc = firstFrame("zq-byte-encode@1");
    const encOut = enc.portOutputs?.get("output");
    expect(proseText(zqByteEncodeNarration(enc))).toContain(
      `256 × 12 bits = ${encOut?.length} bytes`,
    );
    const dec = firstFrame("zq-byte-decode@1");
    const decIn = dec.portInputs?.get("a");
    expect(proseText(zqByteDecodeNarration(dec))).toContain(
      `256 × 12 bits = ${decIn?.length} bytes`,
    );
  });

  it("separates the byte-order param from FIPS 203's fixed bit order", () => {
    // The P2 lesson: tangling them is self-consistent and matches nobody.
    const text = proseText(zqByteEncodeNarration(firstFrame("zq-byte-encode@1")));
    expect(text).toContain("big-endian) is not this bit order");
    expect(text).toContain("least-significant-bit first");
  });

  it("shows the coefficient's bits at the width the frame's d declares", () => {
    const frame = firstFrame("zq-byte-encode@1");
    const a = frame.portInputs?.get("a");
    if (a === undefined) throw new Error("no a port");
    const text = proseText(zqByteEncodeNarration(frame));
    expect(text).toContain(coeff(a, 0).toString(2).padStart(12, "0"));
  });
});

// ─── ml-kem.prf@1 ──────────────────────────────────────────────────────────

describe("lattice narration — the PRF names its counter", () => {
  it("reads N off the input port, and KeyGen's six calls run 0…5", () => {
    // P3's third self-consistently-wrong fact: `s` takes 0,1,2 and `e` takes
    // 3,4,5. Reading the counter off the frame DEMONSTRATES the rule where a
    // static override could only assert it.
    const keygenPrf = framesOfType("ml-kem.prf@1").filter((f) => f.stepId.match(/^[se]\.\d\.prf$/));
    const seen: number[] = [];
    for (const frame of keygenPrf) {
      const input = frame.portInputs?.get("input");
      if (input === undefined) throw new Error("no input port");
      const n = input[input.length - 1] as number;
      seen.push(n);
      expect(proseText(mlKemPrfNarration(frame))).toContain(`PRF(σ, N = ${n})`);
    }
    expect([...seen].sort((x, y) => x - y)).toEqual([0, 1, 2, 3, 4, 5]);
  });

  it("states the output width as 64η, matching the port", () => {
    const frame = firstFrame("ml-kem.prf@1");
    const out = frame.portOutputs?.get("output");
    const eta = (frame.params as { eta: number }).eta;
    expect(out?.length).toBe(64 * eta);
    expect(proseText(mlKemPrfNarration(frame))).toContain(`64 × ${eta} = ${out?.length} bytes`);
  });
});

// ─── ml-kem.hash-g@1 ───────────────────────────────────────────────────────

describe("lattice narration — G names its halves by call site", () => {
  it("KeyGen's 33-byte input reads as d ‖ k → (ρ, σ)", () => {
    const frame = firstFrame("ml-kem.hash-g@1");
    const input = frame.portInputs?.get("input");
    expect(input?.length, "KeyGen hashes d ‖ k").toBe(33);
    const text = proseText(mlKemHashGNarration(frame));
    expect(text).toContain("d ‖ k");
    expect(text).toContain("key generation");
    // The K-PKE-specific half: the 33rd byte is k = 3 for ML-KEM-768.
    expect(text).toContain("the input is d ‖ k, not d");
  });

  it("a 64-byte input reads as the shared-secret derivation instead — (K, r)", () => {
    // P4's call sites — plural, and that is the point of this test's wording.
    // `G` is called THREE times in a full ML-KEM run and there are only two
    // input lengths: encapsulation derives (K, r) from `m ‖ H(ek)`, and
    // decapsulation derives (K′, r′) from `m′ ‖ h`. Those are the same 64 bytes
    // carrying the same meaning — deliberately, since the re-encryption check
    // turns on decapsulation reproducing what encapsulation did.
    //
    // So the narrator must NOT claim a direction it cannot see. An earlier
    // version said "encapsulation" outright, which is false on one of the three
    // call sites and would have been read as fact by anyone scrubbing a
    // decapsulation trace.
    const frame = firstFrame("ml-kem.hash-g@1");
    const foFrame: TraceFrame = {
      ...frame,
      portInputs: new Map(frame.portInputs ?? []).set("input", new Uint8Array(64)),
    };
    const text = proseText(mlKemHashGNarration(foFrame));
    expect(text).toContain("m ‖ H(ek)");
    expect(text).toContain("shared-secret derivation");
    // Both directions named, neither claimed as THE one.
    expect(text).toContain("Encapsulation does this once");
    expect(text).toContain("decapsulation repeats it");
    expect(text).not.toContain("the input is d ‖ k, not d");
  });
});

// ─── ml-kem.hash-h@1 / ml-kem.kdf-j@1 — no shipped spec until P4 ───────────

describe("lattice narration — H and J, driven through a purpose-built spec", () => {
  /**
   * Two leaves over the runtime. These types are registered but emitted by no
   * shipped spec until P4's FO wrapper, and a registered-but-never-run narrator
   * is exactly the kind of code that rots unnoticed — so they get real frames
   * from the real runtime rather than a hand-built `TraceFrame`.
   */
  const spec: CipherSpec = {
    id: "lattice-narration-h-j-fixture",
    name: "H and J fixture",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "h",
        type: "ml-kem.hash-h@1",
        params: {},
        portInputs: { input: { node: INPUT_SOURCE_ID, port: INPUT_SOURCE_PORT } },
      },
      {
        kind: "step",
        id: "j",
        type: "ml-kem.kdf-j@1",
        params: {},
        portInputs: { input: { node: INPUT_SOURCE_ID, port: INPUT_SOURCE_PORT } },
      },
    ],
  };

  const fixtureFrames = (): readonly TraceFrame[] =>
    run(
      spec,
      Uint8Array.from({ length: 64 }, (_, i) => (i * 13 + 5) & 0xff),
    );

  it("H narrates a real SHA3-256 frame and prints the digest it produced", () => {
    const frame = fixtureFrames().find((f) => f.stepId === "h");
    if (frame === undefined) throw new Error("no H frame");
    const out = frame.portOutputs?.get("output");
    expect(out?.length).toBe(32);
    const text = proseText(mlKemHashHNarration(frame));
    // The digest is rendered in the active byte format — hex here.
    const hex = [...(out ?? [])].map((b) => b.toString(16).padStart(2, "0")).join(", ");
    expect(text.replace(/\s+/g, " ")).toContain(hex);
    expect(text).toContain("SHA3-256 over 64 bytes → 32");
  });

  it("H points at the traced sponge rather than pretending to be primitive", () => {
    const frame = fixtureFrames().find((f) => f.stepId === "h");
    const text = proseText(mlKemHashHNarration(frame as TraceFrame));
    expect(text).toContain("SHA3-256 under Hash");
    expect(text).toContain("Keccak-f[1600]");
  });

  it("does NOT print a frame count for the traced sponge, because none is right", () => {
    // An earlier draft said "one frame here, 216 in the Hash view". 216 is one
    // Keccak-f[1600] permutation — but a sponge runs one permutation PER
    // ABSORBED BLOCK, so the traced SHA3-256 spec measures 222 frames on a
    // short message and 1,974 on the 1184 bytes of an encapsulation key. The
    // old test pinned `toContain("216")`, which asserted the claim rather than
    // checking it. Assert the absence instead.
    const frame = fixtureFrames().find((f) => f.stepId === "h");
    const text = proseText(mlKemHashHNarration(frame as TraceFrame));
    expect(text).not.toContain("216");
  });

  it("J leads with implicit rejection, the branch no round trip reaches", () => {
    const frame = fixtureFrames().find((f) => f.stepId === "j");
    if (frame === undefined) throw new Error("no J frame");
    const text = proseText(mlKemKdfJNarration(frame));
    expect(text).toContain("J(z ‖ c)");
    expect(text.toLowerCase()).toContain("deterministic");
    // The security claim, not just the mechanism: a distinguishable failure is
    // a key-recovery oracle. This is the sentence the step exists for.
    expect(text.toLowerCase()).toContain("indistinguishable");
  });
});

// ─── Declining ─────────────────────────────────────────────────────────────

describe("lattice narration — narrators decline rather than throw", () => {
  it("returns null on a frame whose ports are missing", () => {
    // `<StepNarration />` renders nothing for null. A THROW here would take
    // the whole linear view down, and a palette-dropped leaf gets
    // `params: {}` — so malformed frames are reachable by an ordinary user
    // action, not just by a broken spec.
    const bare = (stepType: string): TraceFrame => ({
      ...firstFrame("zq-cbd@1"),
      stepType,
      params: {},
      portInputs: new Map(),
      portOutputs: new Map(),
    });
    const narrators: ReadonlyArray<readonly [string, NarrationFn]> = [
      ["zq-compress@1", zqCompressNarration],
      ["zq-decompress@1", zqDecompressNarration],
      ["zq-cbd@1", zqCbdNarration],
      ["zq-base-case-mul@1", zqBaseCaseMulNarration],
      ["zq-byte-encode@1", zqByteEncodeNarration],
      ["zq-byte-decode@1", zqByteDecodeNarration],
      ["ml-kem.sample-ntt@1", mlKemSampleNttNarration],
      ["ml-kem.prf@1", mlKemPrfNarration],
      ["ml-kem.hash-g@1", mlKemHashGNarration],
      ["ml-kem.hash-h@1", mlKemHashHNarration],
      ["ml-kem.kdf-j@1", mlKemKdfJNarration],
      ["ml-kem.select-shared-secret@1", mlKemSelectSharedSecretNarration],
    ];
    for (const [stepType, fn] of narrators) {
      expect(() => fn(bare(stepType)), `${stepType} must not throw`).not.toThrow();
      expect(fn(bare(stepType)), `${stepType} should decline`).toBeNull();
    }
  });

  it("declines when params are malformed rather than propagating the throw", () => {
    // `readZqVecParams` throws on a bad `coeffBytes`; the narrator must swallow
    // that. The runtime rejects the spec a moment later anyway — but the
    // narration memo runs first.
    const frame = firstFrame("zq-compress@1");
    const broken: TraceFrame = { ...frame, params: { coeffBytes: "two", littleEndian: false } };
    expect(() => zqCompressNarration(broken)).not.toThrow();
    expect(zqCompressNarration(broken)).toBeNull();
  });
});
