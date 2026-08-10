/**
 * Lattice-family per-frame value-prose narrators (2026-08-10).
 *
 * Eleven narrators covering every step type introduced by P2 (the lattice
 * arithmetic) and P3 (K-PKE) of `docs/plans/unified-stargazing-quasar.md`.
 * They are keyed on lattice-ONLY step types, so no other algorithm's linear
 * view is touched.
 *
 * ## Why these eleven and not the other three
 *
 * The discriminating question is the one `truncate-to-reference@1` was decided
 * on: **does the teaching point change frame to frame?** If a static per-node
 * `narrationOverride` can say it, it does not need a narrator.
 *
 * Every step here answers yes, and several answer it emphatically:
 *
 *   - `ml-kem.sample-ntt@1` is the only step in the app whose *cost* depends on
 *     the value rather than the size. How many hash blocks a draw needed is
 *     unknowable until it has run, and the executor publishes the count on a
 *     port precisely so this row can read it.
 *   - `zq-compress@1` / `zq-decompress@1` throw information away, and how much
 *     is per-coefficient. Their `d` also differs per leaf — 10 and 4 for the two
 *     ciphertext halves, 1 for the message — so even the headline sentence
 *     changes between frames of the same step type.
 *   - `zq-cbd@1`'s distribution is a property of the bytes it was handed, and
 *     the "a sampled −1 appears as 3328" surprise is only convincing when the
 *     3328 on screen is one this run actually produced.
 *   - `zq-base-case-mul@1` contrasts what it computed against what element-wise
 *     multiplication *would* have computed, from the same operands.
 *
 * The three `zq-vec-*@1` steps are deliberately NOT here — they are on
 * `NARRATION_NO_OP_ALLOWLIST` instead. See the rationale on that constant.
 *
 * ## The one derived value, flagged
 *
 * `zqCompressNarration` reconstructs each bucket's centre in order to state the
 * rounding error. That formula is the sibling step's, not this frame's, and the
 * frame exposes no port carrying it — the same "display convenience" the
 * MT19937 twist narrator makes for its splice `y`. It is safe for the same
 * reason: both the coefficient that went in and the bucket that came out are
 * printed beside the reconstruction, so a reader can check the arithmetic
 * rather than take it on faith. Everything else in this file is read straight
 * off the frame's own ports.
 *
 * Coefficients are read with `readCoeff` from `core/zq-vector.ts` — the very
 * function the executors use — so the prose cannot disagree with the executor
 * about where one coefficient ends and the next begins.
 */

import type { ByteFormat } from "@/core/format";
import type { Json } from "@/core/types";
import { type ZqVecParams, readCoeff, readZqVecParams } from "@/core/zq-vector";
import { Index } from "solid-js";
import { formatBytes } from "../components/byte-row";
import type { NarrationFn, NarrationUnit } from "./registry";

// ─── Shared helpers ────────────────────────────────────────────────────────

/**
 * `readZqVecParams` throws on a malformed params object. A narrator must
 * DECLINE (return null) rather than throw — a throw inside the units memo
 * would take the whole linear view down on a spec the runtime itself rejects
 * a moment later. Every entry point funnels through this.
 */
const safeVecParams = (params: Json, step: string): ZqVecParams | null => {
  try {
    return readZqVecParams(params, step);
  } catch {
    return null;
  }
};

/** Read an integer param, or null when absent/malformed (narrators decline). */
const intParam = (params: Json, key: string): number | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>)[key];
  return typeof v === "number" && Number.isInteger(v) ? v : null;
};

/** Every coefficient of a packed vector, as bigints. */
const coeffs = (bytes: Uint8Array, p: ZqVecParams): bigint[] => {
  const n = Math.floor(bytes.length / p.coeffBytes);
  const out: bigint[] = [];
  for (let i = 0; i < n; i++) out.push(readCoeff(bytes, i, p));
  return out;
};

/** The modulus port, as a bigint — or null when it is missing or zero. */
const modulusOf = (frame: { portInputs?: ReadonlyMap<string, Uint8Array> }, p: ZqVecParams) => {
  const m = frame.portInputs?.get("modulus");
  if (!(m instanceof Uint8Array) || m.length === 0) return null;
  const q = readCoeff(m, 0, p);
  return q > 0n ? q : null;
};

/**
 * A small labelled list. Shares `twofish-word-list` with the MT19937 and
 * Twofish narrators — an unstyled `<ol>` today, but keeping one class name
 * means a future style reaches all of them at once.
 */
const ValueList = (props: { items: { label: string; text: string }[] }) => (
  <ol class="twofish-word-list">
    <Index each={props.items}>
      {(it) => (
        <li>
          <code>
            {it().label} = {it().text}
          </code>
        </li>
      )}
    </Index>
  </ol>
);

/** Bytes rendered in the active format. */
const Bytes = (props: { bytes: Uint8Array; fmt: ByteFormat }) => (
  <code>{formatBytes(props.bytes, props.fmt)}</code>
);

/** `n` rendered with thousands separators, for the size sentences. */
const num = (n: number): string => n.toLocaleString("en-US");

// ─── zq-compress@1 ─────────────────────────────────────────────────────────

/**
 * Compression is the only lossy operation in ML-KEM. The rows show the bucket
 * each coefficient landed in and the error that cost on THIS frame.
 *
 * **`d` is read off the frame, and the third row FORKS on it.** K-PKE compresses
 * at `d = 10` and `d = 4` to shrink a ciphertext for the wire — but also at
 * `d = 1` in Decrypt, where the step is *recovering the message* and has nothing
 * to do with size. An earlier draft printed the size sentence unconditionally
 * and so told a learner that message recovery was a ciphertext optimisation, on
 * the one frame where compression is applied to the message. Any row added here
 * must be checked against all three widths.
 */
export const zqCompressNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "zq-compress@1");
  if (!p) return null;
  const d = intParam(frame.params, "d");
  const a = frame.portInputs?.get("a");
  const out = frame.portOutputs?.get("output");
  if (d === null || !(a instanceof Uint8Array) || !(out instanceof Uint8Array)) return null;
  const q = modulusOf(frame, p);
  if (q === null) return null;

  const xs = coeffs(a, p);
  const ys = coeffs(out, p);
  if (xs.length === 0 || ys.length !== xs.length) return null;

  const twoD = 1n << BigInt(d);
  const buckets = Number(twoD);

  // The bucket CENTRE each index decompresses back to — the sibling step's
  // formula, re-derived here because no port carries it. Both operands are
  // printed beside it (see the file header).
  const centre = (y: bigint): bigint => ((2n * q * y + twoD) / (2n * twoD)) % q;
  /** Distance on the circle: a coefficient near q is near 0, not far from it. */
  const ringDistance = (u: bigint, v: bigint): bigint => {
    const raw = (((u - v) % q) + q) % q;
    return raw > q - raw ? q - raw : raw;
  };

  let worst = 0n;
  for (let i = 0; i < xs.length; i++) {
    const e = ringDistance(xs[i] as bigint, centre(ys[i] as bigint));
    if (e > worst) worst = e;
  }
  // FIPS 203's error bound is ⌈q / 2^(d+1)⌋ where ⌈·⌋ is ROUND TO NEAREST, not
  // a floor. The difference is not cosmetic: at d = 10 the floor gives 1 while
  // errors of 2 genuinely occur, so a floored bound renders the nonsense
  // "worst error 2 of a possible 1". Add half the denominator, then divide.
  const bound = (q + twoD) / (2n * twoD);

  const sample = Math.min(4, xs.length);
  const rows = Array.from({ length: sample }, (_, i) => ({
    label: `x[${i}] = ${xs[i]}`,
    text: `bucket ${ys[i]} of ${buckets}  →  decompresses to ${centre(ys[i] as bigint)}  (off by ${ringDistance(xs[i] as bigint, centre(ys[i] as bigint))})`,
  }));

  const units: NarrationUnit[] = [];

  units.push({
    key: "buckets",
    label: `1 — ${num(xs.length)} coefficients onto ${num(buckets)} buckets (d = ${d})`,
    Prose: () => (
      <div>
        <p>
          Each coefficient is a number in <code>0 … {String(q - 1n)}</code>. Compression rescales it
          onto <code>2^{d}</code> = {num(buckets)} buckets and keeps only the bucket number,
          rounding to nearest with ties up:
        </p>
        <p>
          <code>
            y = round(2^{d} / q · x) mod 2^{d}
          </code>
        </p>
        <ValueList items={rows} />
        <p>
          The <code>d</code> above is read from this step, not fixed for the algorithm — ML-KEM-768
          compresses the two halves of a ciphertext by different amounts (10 bits and 4), and the
          message bit by all but one.
        </p>
      </div>
    ),
  });

  units.push({
    key: "error",
    label: `2 — the information thrown away: worst error ${worst} of a possible ${bound}`,
    Prose: () => (
      <div>
        <p>
          Nothing else in this family loses information. The transform is exact, the arithmetic is
          exact, the inverse recovers its input byte for byte. This step does not: {num(buckets)}{" "}
          buckets cannot represent {String(q)} values, so the original coefficient is gone and only
          the bucket survives.
        </p>
        <p>
          Decompressing returns the <strong>centre</strong> of the bucket, which is the closest
          guess available. Across the {num(xs.length)} coefficients on this frame the furthest any
          one moved was <strong>{String(worst)}</strong>, against a worst case of{" "}
          <code>
            ⌈q / 2^{d + 1}⌋ = {String(bound)}
          </code>{" "}
          (rounded to nearest, which is how FIPS 203 writes it).
        </p>
        <p>
          That number is the one every correctness argument in FIPS 203 rests on. Decryption works
          because the noise deliberately added to a ciphertext stays smaller than half a bucket — so
          rounding the low bits away rounds the noise away with them.
        </p>
      </div>
    ),
  });

  // The third row depends on WHY this leaf is compressing, and there are two
  // reasons in K-PKE. At d = 10 / 4 it is shrinking a ciphertext for the wire.
  // At d = 1 it is Decrypt asking "which of the two buckets is this nearer to?"
  // — the step that RECOVERS the message. Printing the size sentence there
  // would tell a learner that message recovery is a size optimisation, on the
  // one frame where compression is applied to the message rather than to a
  // ciphertext. Mirrors the d = 1 arm in `zqDecompressNarration`.
  if (d === 1) {
    units.push({
      key: "decode",
      label: "3 — d = 1: this is the decryption, asked as a rounding question",
      Prose: () => (
        <div>
          <p>
            Two buckets, so every coefficient becomes a single bit: is it nearer to <code>0</code>{" "}
            or nearer to <code>{String((q + 1n) / 2n)}</code>? That question <em>is</em> the
            decryption. The message was planted at those two maximally distant points, and
            everything the scheme did in between — the noise, the compression of the ciphertext, the
            approximate recovery — moved each coefficient by less than a quarter of the circle.
          </p>
          <p>
            So the errors this step normally introduces are, here, the errors it{" "}
            <strong>removes</strong>. Rounding to the nearer of two points discards exactly the
            accumulated noise, which is why the bound in the row above is the number the whole
            construction is built around: while every coefficient stays within{" "}
            <code>{String((q + 1n) / 4n)}</code> or so of where it started, every bit comes back
            exactly.
          </p>
        </div>
      ),
    });
    return units;
  }

  units.push({
    key: "size",
    label: "3 — this is why a lattice ciphertext is small enough to send",
    Prose: () => (
      <div>
        <p>
          A coefficient needs 12 bits to store exactly. After this step it needs <code>{d}</code>.
          On this frame that is {num(xs.length)} × 12 = {num(xs.length * 12)} bits down to{" "}
          {num(xs.length * d)}.
        </p>
        <p>
          Here compression is being applied to a ciphertext, which is the case it exists for: it is
          not a space optimisation bolted on afterwards, it is the step that makes the ciphertext a
          practical size, and what lets the rest of the design tolerate it is the error bound above.
          (The same step also runs at <code>d = 1</code> during decryption, for an entirely
          different reason — there it recovers the message rather than shrinking anything.)
        </p>
      </div>
    ),
  });

  return units;
};

// ─── zq-decompress@1 ───────────────────────────────────────────────────────

/**
 * The partner that is not an inverse. At `d = 1` this is also where a message
 * bit physically enters the ring, so the narrator calls that case out by name.
 */
export const zqDecompressNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "zq-decompress@1");
  if (!p) return null;
  const d = intParam(frame.params, "d");
  const a = frame.portInputs?.get("a");
  const out = frame.portOutputs?.get("output");
  if (d === null || !(a instanceof Uint8Array) || !(out instanceof Uint8Array)) return null;
  const q = modulusOf(frame, p);
  if (q === null) return null;

  const ys = coeffs(a, p);
  const xs = coeffs(out, p);
  if (ys.length === 0 || xs.length !== ys.length) return null;

  const twoD = 1n << BigInt(d);
  const buckets = Number(twoD);
  const half = (q + 1n) / 2n;

  const sample = Math.min(4, ys.length);
  const rows = Array.from({ length: sample }, (_, i) => ({
    label: `y[${i}] = ${ys[i]}`,
    text: `→ ${xs[i]}`,
  }));

  const units: NarrationUnit[] = [];

  units.push({
    key: "centres",
    label: `1 — ${num(buckets)} bucket indices back to coefficients (d = ${d})`,
    Prose: () => (
      <div>
        <p>
          Each bucket index is turned back into a ring coefficient by the mirror formula, again
          rounding to nearest with ties up:
        </p>
        <p>
          <code>x = round(q / 2^{d} · y)</code>
        </p>
        <ValueList items={rows} />
        <p>
          Here the ties are <strong>real</strong>. <code>q = {String(q)}</code> is odd and{" "}
          <code>2^{d}</code> is even, so a decompression can land exactly halfway between two
          integers where a compression never can — which is why the obvious wrong implementation,
          plain integer division, passes every tie-focused test written against the other direction.
        </p>
      </div>
    ),
  });

  units.push({
    key: "not-inverse",
    label: "2 — not the inverse of compression, and it cannot be",
    Prose: () => (
      <div>
        <p>
          Compressing and then decompressing does not return the original coefficient — it returns
          the centre of whichever bucket the original fell in. The pair is not an inverse in either
          composition order that matters here, and no implementation could make it one:{" "}
          {num(buckets)} buckets simply do not hold {String(q)} distinct values.
        </p>
        <p>
          What <em>does</em> hold is the other order: decompress then compress recovers the bucket
          index exactly, as long as <code>2^d ≤ q</code>. At <code>d = 12</code> even that fails, by
          pigeonhole — 4096 indices through {String(q)} values — which is exactly why FIPS 203
          defines the pair for <code>d &lt; 12</code> only and gives the uncompressed case its own
          encoding instead.
        </p>
      </div>
    ),
  });

  if (d === 1) {
    units.push({
      key: "message-bit",
      label: `3 — d = 1: this is the message entering the ring (0 or ${String(half)})`,
      Prose: () => (
        <div>
          <p>
            At <code>d = 1</code> there are two buckets, and a coefficient becomes either{" "}
            <code>0</code> or <code>{String(half)}</code> — zero, or as far from zero as it is
            possible to get on a circle of {String(q)} points. This frame is where each bit of the
            256-bit message physically becomes a polynomial coefficient.
          </p>
          <p>
            Pushing the two values maximally apart is what buys the error tolerance: decryption
            recovers the bit by asking which of the two it is nearer to, so every noise term added
            along the way has almost <code>q/4</code> of room before a bit can flip. Compressing
            back to one bit is precisely that question.
          </p>
        </div>
      ),
    });
  }

  return units;
};

// ─── zq-cbd@1 ──────────────────────────────────────────────────────────────

/**
 * The one step that turns randomness into a ring element. Three rows: the bit
 * windows worked through, the negative-looking values named, and the histogram
 * this run actually produced against the binomial it should match.
 */
export const zqCbdNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "zq-cbd@1");
  if (!p) return null;
  const eta = intParam(frame.params, "eta");
  const a = frame.portInputs?.get("a");
  const out = frame.portOutputs?.get("output");
  if (eta === null || eta < 1 || !(a instanceof Uint8Array) || !(out instanceof Uint8Array)) {
    return null;
  }
  const q = modulusOf(frame, p);
  if (q === null) return null;

  const vs = coeffs(out, p);
  if (vs.length === 0) return null;

  /** Bit `k` of the input stream, least significant bit of each byte first. */
  const bit = (k: number): number => ((a[k >> 3] ?? 0) >> (k & 7)) & 1;
  /** The signed value a ring element stands for: q−1 means −1, not q−1. */
  const signed = (v: bigint): number => Number(v > q / 2n ? v - q : v);

  // First few coefficients, with the two bit windows that produced them.
  const sample = Math.min(4, vs.length);
  const rows = Array.from({ length: sample }, (_, i) => {
    const base = i * 2 * eta;
    const xBits = Array.from({ length: eta }, (_, j) => bit(base + j));
    const yBits = Array.from({ length: eta }, (_, j) => bit(base + eta + j));
    const x = xBits.reduce((s, b) => s + b, 0);
    const y = yBits.reduce((s, b) => s + b, 0);
    return {
      label: `coefficient ${i}`,
      text: `bits ${xBits.join("")} (${x} set) − bits ${yBits.join("")} (${y} set) = ${x - y}   →  stored as ${vs[i]}`,
    };
  });

  // The histogram this frame produced, over the full range −η … η.
  const counts = new Map<number, number>();
  for (const v of vs) counts.set(signed(v), (counts.get(signed(v)) ?? 0) + 1);
  const total = vs.length;
  // Binomial(2η, ½) shifted to be centred on zero: C(2η, k+η) / 2^(2η).
  const choose = (n: number, k: number): number => {
    let r = 1;
    for (let i = 0; i < k; i++) r = (r * (n - i)) / (i + 1);
    return Math.round(r);
  };
  const histRows = Array.from({ length: 2 * eta + 1 }, (_, idx) => {
    const v = idx - eta;
    const seen = counts.get(v) ?? 0;
    const expected = (choose(2 * eta, v + eta) / 2 ** (2 * eta)) * total;
    return {
      label: `${v > 0 ? `+${v}` : v}`,
      text: `${seen} of ${total}   (expected ≈ ${expected.toFixed(1)})`,
    };
  });

  const negatives = vs.filter((v) => signed(v) < 0);
  const firstNegative = negatives[0];

  const units: NarrationUnit[] = [];

  units.push({
    key: "windows",
    label: `1 — ${2 * eta} bits become one small number (η = ${eta})`,
    Prose: (props) => (
      <div>
        <p>
          Everything else in the lattice family rearranges numbers deterministically. This is the
          one step that turns random bytes into a polynomial — and specifically into one whose
          values are <strong>small</strong>.
        </p>
        <p>
          It reads <code>2η = {2 * eta}</code> bits per coefficient, counts the one-bits in the
          first half, and subtracts the count from the second half. The bit stream runs
          least-significant bit of each byte first:
        </p>
        <ValueList items={rows} />
        <p>Input to this frame ({a.length} bytes, from the pseudorandom function above):</p>
        <p>
          <Bytes bytes={a.subarray(0, Math.min(8, a.length))} fmt={props.fmt} />
          {a.length > 8 ? " …" : ""}
        </p>
      </div>
    ),
  });

  units.push({
    key: "negatives",
    label: `2 — ${negatives.length} of ${total} came out negative, and they look enormous`,
    Prose: () => (
      <div>
        <p>
          A difference of two counts is in <code>−η … η</code>, so half of these values are
          negative. There are no negative numbers in <code>Z_q</code>, so <code>−v</code> is written
          as <code>q − v</code>
          {firstNegative !== undefined ? (
            <>
              {" "}
              — on this frame a <code>{signed(firstNegative)}</code> is stored as{" "}
              <strong>{String(firstNegative)}</strong>
            </>
          ) : null}
          .
        </p>
        <p>
          This is the thing about the step a reader reliably misreads. A freshly sampled noise
          polynomial looks full of enormous numbers when in fact every one of them is tiny — small
          meaning close to zero <em>going around the circle</em>, which is the only sense of small
          the ring knows. An implementation that clamped these, or took an absolute value, would
          still pass every range check and would destroy the distribution's centre.
        </p>
      </div>
    ),
  });

  units.push({
    key: "distribution",
    label: `3 — the distribution this run produced, over ${total} coefficients`,
    Prose: () => (
      <div>
        <p>
          Counting bits in two windows and subtracting gives a little triangle centred on zero — the
          difference of two Binomial(η, ½) draws:
        </p>
        <ValueList items={histRows} />
        <p>
          Both halves of the scheme hang on this shape, pulling in opposite directions. Security
          needs the noise large enough that "secret times matrix, plus noise" is indistinguishable
          from pure randomness. Correctness needs it small enough to round away in the compression
          step. <code>η</code> is the single number balancing the two, which is why it is editable
          here.
        </p>
      </div>
    ),
  });

  return units;
};

// ─── zq-base-case-mul@1 ────────────────────────────────────────────────────

/**
 * Multiplying transformed polynomials is not element-wise. The narrator makes
 * that concrete by computing what element-wise WOULD have produced for pair 0
 * from the same operands, beside what the step actually produced.
 */
export const zqBaseCaseMulNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "zq-base-case-mul@1");
  if (!p) return null;
  const a = frame.portInputs?.get("a");
  const b = frame.portInputs?.get("b");
  const gamma = frame.portInputs?.get("gamma");
  const out = frame.portOutputs?.get("output");
  if (![a, b, gamma, out].every((v) => v instanceof Uint8Array)) return null;
  const q = modulusOf(frame, p);
  if (q === null) return null;

  const as = coeffs(a as Uint8Array, p);
  const bs = coeffs(b as Uint8Array, p);
  const gs = coeffs(gamma as Uint8Array, p);
  const os = coeffs(out as Uint8Array, p);
  const pairs = Math.floor(as.length / 2);
  if (pairs === 0 || gs.length < pairs || os.length < 2 * pairs) return null;

  const a0 = as[0] as bigint;
  const a1 = as[1] as bigint;
  const b0 = bs[0] as bigint;
  const b1 = bs[1] as bigint;
  const g0 = gs[0] as bigint;

  const units: NarrationUnit[] = [];

  units.push({
    key: "pair-0",
    label: "1 — pair 0 in full: five multiplications, not one",
    Prose: () => (
      <div>
        <p>
          A transformed polynomial here is not {num(as.length)} numbers — it is {num(pairs)} little
          degree-1 polynomials. Pair 0 is <code>a₀ + a₁X</code> times <code>b₀ + b₁X</code>, worked
          out in the ring <code>Z_q[X]/(X² − γ₀)</code>:
        </p>
        <ValueList
          items={[
            { label: "a₀, a₁", text: `${a0}, ${a1}` },
            { label: "b₀, b₁", text: `${b0}, ${b1}` },
            { label: "γ₀", text: `${g0}` },
            {
              label: "constant term",
              text: `a₀b₀ + a₁b₁γ₀ = ${a0}·${b0} + ${a1}·${b1}·${g0} ≡ ${os[0]}`,
            },
            {
              label: "X term",
              text: `a₀b₁ + a₁b₀ = ${a0}·${b1} + ${a1}·${b0} ≡ ${os[1]}`,
            },
          ]}
        />
        <p>
          The <code>X²</code> that ordinary multiplication would leave behind does not survive:{" "}
          <code>X² = γ₀</code> in this ring, so the <code>a₁b₁</code> term folds back down into the
          constant carrying a factor of <code>γ₀</code> with it. Five multiplications per pair.
        </p>
      </div>
    ),
  });

  units.push({
    key: "not-elementwise",
    label: "2 — what element-wise would have given, from the same numbers",
    Prose: () => (
      <div>
        <p>
          In an ordinary transform you multiply spectra element by element, and that is the whole
          point of having transformed them. Here it is simply wrong, and it is the classic first
          mistake. For pair 0 the two answers are:
        </p>
        <ValueList
          items={[
            { label: "element-wise (wrong)", text: `${(a0 * b0) % q}, ${(a1 * b1) % q}` },
            { label: "this step", text: `${os[0]}, ${os[1]}` },
          ]}
        />
        <p>
          The cause is one missing root of unity. <code>q − 1 = {String(q - 1n)}</code> has only 2⁸
          as its power-of-two part, so there is a 256th root of unity modulo <code>q</code> but no
          512th one — the transform cannot split all the way down to constants and stops one level
          short, at pairs. The step breaks its family's <code>zq-vec-</code> naming on purpose, so
          that a reader meets this fact in the palette rather than after debugging it.
        </p>
      </div>
    ),
  });

  units.push({
    key: "gamma",
    label: `3 — ${num(pairs)} pairs, ${num(pairs)} different γ`,
    Prose: () => (
      <div>
        <p>
          Each pair lives in its <em>own</em> ring, so each needs its own <code>γ</code>. They are
          not powers of one another in sequence: <code>γ[i] = ζ^(2·BitRev7(i) + 1)</code>, an{" "}
          <strong>odd</strong> power of the same ζ the transform's butterflies consume.
        </p>
        <ValueList
          items={Array.from({ length: Math.min(4, pairs) }, (_, i) => ({
            label: `γ[${i}]`,
            text: `${gs[i]}`,
          }))}
        />
        <p>
          Dropping the <code>+ 1</code> from that exponent is a real and self-consistent wrong
          answer — it yields <code>1, {String(q - 1n)}, 1729, …</code> in place of the true table,
          and every test that only checks a round trip stays green. Consecutive entries here are
          negatives of each other, which is a free way to check a table against the published one.
        </p>
      </div>
    ),
  });

  return units;
};

// ─── zq-byte-encode@1 / zq-byte-decode@1 ───────────────────────────────────

/** Shared body: the two directions differ only in which side is the vector. */
const packingUnits = (opts: {
  readonly d: number;
  readonly p: ZqVecParams;
  readonly q: bigint;
  readonly vector: Uint8Array;
  readonly packed: Uint8Array;
  readonly encoding: boolean;
}): readonly NarrationUnit[] => {
  const { d, p, q, vector, packed, encoding } = opts;
  const vs = coeffs(vector, p);
  const n = vs.length;

  const sample = Math.min(2, n);
  const rows = Array.from({ length: sample }, (_, i) => ({
    label: `coefficient ${i} = ${vs[i]}`,
    text: `${(vs[i] as bigint).toString(2).padStart(d, "0")} (${d} bits, written low bit first)`,
  }));

  const units: NarrationUnit[] = [];

  units.push({
    key: "bits",
    label: `1 — ${d} bits per coefficient, ${encoding ? "packed into" : "unpacked from"} a bit stream`,
    Prose: (props) => (
      <div>
        <p>
          Every coefficient elsewhere in this trace travels in a comfortable{" "}
          <code>{p.coeffBytes}</code>-byte slot — easy to read, and wasteful on a wire:{" "}
          <code>q = {String(q)}</code> needs twelve bits, not sixteen.
        </p>
        <ValueList items={rows} />
        <p>
          The stream is filled least-significant bit first, of the coefficient and of each byte, so
          coefficients straddle byte boundaries. At <code>d = 12</code> two coefficients occupy
          exactly three bytes.
        </p>
        <p>
          {encoding ? "Packed output" : "Packed input"} ({packed.length} bytes):{" "}
          <Bytes bytes={packed.subarray(0, Math.min(6, packed.length))} fmt={props.fmt} />
          {packed.length > 6 ? " …" : ""}
        </p>
      </div>
    ),
  });

  units.push({
    key: "not-bit-order",
    label: `2 — the byte-order setting (${p.littleEndian ? "little" : "big"}-endian) is not this bit order`,
    Prose: () => (
      <div>
        <p>
          Two independent orderings are in play here and they are easy to tangle. The{" "}
          <code>littleEndian</code> parameter describes the bytes <em>within one coefficient</em> in
          the unpacked vector, and so decides which <em>numbers</em> get read. The bit stream above
          is FIPS 203's, is least-significant-bit first, and is not a setting at all.
        </p>
        <p>
          Confusing the two produces an encoding that is perfectly consistent with itself, round
          trips cleanly, and matches nothing anyone else produces.
        </p>
      </div>
    ),
  });

  units.push({
    key: "size",
    label: `3 — ${num(n)} × ${d} bits = ${num(packed.length)} bytes`,
    Prose: () => (
      <div>
        <p>
          Packing {num(n)} coefficients at {d} bits each turns {num(n * p.coeffBytes)} bytes into{" "}
          {num(packed.length)}. Across the three polynomials of an ML-KEM-768 encapsulation key that
          is what makes it <strong>1184</strong> bytes rather than 1568.
        </p>
        <p>
          This is part of the data format, not an optimisation — the packed form is what actually
          gets transmitted. It is kept deliberately separate from the compression step: compressing
          loses information and packing does not, and a trace that fused them would let a reader
          blame the loss on the wrong step.
        </p>
      </div>
    ),
  });

  return units;
};

/** 12-bit dense packing, vector → bytes. */
export const zqByteEncodeNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "zq-byte-encode@1");
  if (!p) return null;
  const d = intParam(frame.params, "d");
  const a = frame.portInputs?.get("a");
  const out = frame.portOutputs?.get("output");
  if (d === null || !(a instanceof Uint8Array) || !(out instanceof Uint8Array)) return null;
  const q = modulusOf(frame, p);
  if (q === null || a.length === 0) return null;
  return packingUnits({ d, p, q, vector: a, packed: out, encoding: true });
};

/** 12-bit dense packing, bytes → vector. */
export const zqByteDecodeNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "zq-byte-decode@1");
  if (!p) return null;
  const d = intParam(frame.params, "d");
  const a = frame.portInputs?.get("a");
  const out = frame.portOutputs?.get("output");
  if (d === null || !(a instanceof Uint8Array) || !(out instanceof Uint8Array)) return null;
  const q = modulusOf(frame, p);
  if (q === null || out.length === 0) return null;
  return packingUnits({ d, p, q, vector: out, packed: a, encoding: false });
};

// ─── ml-kem.sample-ntt@1 ───────────────────────────────────────────────────

/** Two bytes, big-endian, from the `squeezes` port. */
const readSqueezeCount = (bytes: Uint8Array): number => ((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0);

/** SHAKE128's rate, in bytes — the size of one squeeze. */
const SHAKE128_RATE = 168;

/**
 * The flagship narrator. This is the only step in the app whose COST depends on
 * the value rather than the size, and the executor publishes the block count on
 * a port precisely so this row can read it rather than recompute it.
 */
export const mlKemSampleNttNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "ml-kem.sample-ntt@1");
  if (!p) return null;
  const input = frame.portInputs?.get("input");
  const out = frame.portOutputs?.get("output");
  const squeezes = frame.portOutputs?.get("squeezes");
  if (!(input instanceof Uint8Array) || !(out instanceof Uint8Array)) return null;
  if (!(squeezes instanceof Uint8Array) || squeezes.length < 2) return null;
  const q = modulusOf(frame, p);
  if (q === null) return null;

  const blocks = readSqueezeCount(squeezes);
  if (blocks < 1) return null;
  const accepted = Math.floor(out.length / p.coeffBytes);
  const bytesAvailable = blocks * SHAKE128_RATE;
  const candidatesAvailable = Math.floor(SHAKE128_RATE / 3) * 2 * blocks;
  const acceptRate = (Number(q) / 4096) * 100;

  // The last two bytes of the 34-byte seed are the matrix indices. Which order
  // they carry is KeyGen-vs-Encrypt (the byte swap IS the transpose), so the
  // narrator names both rather than guessing which spec it is in.
  const idxA = input[input.length - 2];
  const idxB = input[input.length - 1];

  const units: NarrationUnit[] = [];

  units.push({
    key: "squeezes",
    label: `1 — this draw needed ${blocks} hash block${blocks === 1 ? "" : "s"}`,
    Prose: () => (
      <div>
        <p>
          Generating one matrix entry means squeezing SHAKE128 and throwing away every candidate too
          large for the ring. How much output that needs depends on the output itself — so this is
          the only step in the app whose cost varies with the <em>value</em> rather than the size.
        </p>
        <ValueList
          items={[
            {
              label: "blocks squeezed",
              text: `${blocks} × ${SHAKE128_RATE} bytes = ${num(bytesAvailable)} bytes`,
            },
            { label: "candidates those bytes carry", text: `${num(candidatesAvailable)}` },
            { label: "coefficients accepted", text: `${num(accepted)}` },
          ]}
        />
        <p>
          Scrub to another entry of the matrix and this count may differ. That variability is the
          point: it is measured, not budgeted.
        </p>
      </div>
    ),
  });

  units.push({
    key: "rejection",
    label: `2 — three bytes carry two 12-bit candidates, ~${acceptRate.toFixed(1)}% accepted`,
    Prose: () => (
      <div>
        <p>
          The stream is read three bytes at a time and split into two 12-bit numbers — the low
          nibble of the middle byte belongs to the first, the high nibble to the second. A 12-bit
          number runs to 4095, but the ring only reaches <code>{String(q - 1n)}</code>, so a
          candidate of <code>{String(q)}</code> or more is <strong>discarded</strong> rather than
          reduced.
        </p>
        <p>
          Reducing them instead would be the tempting shortcut and it would bias the result: values
          below <code>4096 − {String(q)}</code> would come up twice as often as the rest. Rejection
          is what keeps the matrix uniform, and uniformity is what the security argument assumes.
        </p>
        <p>
          About {acceptRate.toFixed(1)}% of candidates survive, so {num(accepted)} coefficients need
          roughly {Math.ceil(accepted / (Number(q) / 4096))} candidates — usually three blocks, and
          sometimes four.
        </p>
      </div>
    ),
  });

  units.push({
    key: "loop-condition",
    label: "3 — the loop asks “have I got enough?”, never “have I used my quota?”",
    Prose: () => (
      <div>
        <p>
          The condition driving this step is the <strong>accepted</strong> count. Everything else —
          bytes read, blocks squeezed — falls out of it.
        </p>
        <p>
          Inverting that is a real bug rather than a stylistic difference. A fixed byte budget large
          enough to work almost every time would silently produce a short polynomial the rest of the
          time, and a public key built from it would be wrong in a way no round trip on the same
          machine could detect.
        </p>
      </div>
    ),
  });

  units.push({
    key: "already-transformed",
    label: "4 — the output is already in the transformed domain",
    Prose: (props) => (
      <div>
        <p>
          Nothing transforms this polynomial afterwards. The 12-bit values coming off the hash are
          taken directly as the coefficients of <code>Â</code> — the matrix is <em>defined</em> to
          be whatever the hash says, in the domain where multiplication is cheap.
        </p>
        <p>
          That is only sound because the transform is a bijection: a uniformly random element of the
          transformed domain is the transform of a uniformly random ring element. It also means the
          matrix never has to be transmitted — both parties regenerate it from the 32-byte seed{" "}
          <code>ρ</code>, which is the other half of why the key is small.
        </p>
        <p>
          Seed for this entry ({input.length} bytes — <code>ρ</code> followed by two index bytes{" "}
          <code>
            {idxA}, {idxB}
          </code>
          ):
        </p>
        <p>
          <Bytes bytes={input.subarray(0, Math.min(8, input.length))} fmt={props.fmt} /> …
        </p>
        <p>
          Which way round those two index bytes go is the difference between the matrix and its
          transpose — key generation uses one order and encryption the other, and swapping them
          produces a scheme that encrypts happily and decrypts to noise.
        </p>
      </div>
    ),
  });

  return units;
};

// ─── ml-kem.prf@1 ──────────────────────────────────────────────────────────

/**
 * The counter byte rides the INPUT (`σ ‖ N`) rather than a param, so the frame
 * carries which noise polynomial this is. That makes the "0,1,2 then 3,4,5"
 * rule demonstrable rather than assertable, which is why this one earns a
 * narrator over a static per-node override.
 */
export const mlKemPrfNarration: NarrationFn = (frame) => {
  const input = frame.portInputs?.get("input");
  const out = frame.portOutputs?.get("output");
  if (!(input instanceof Uint8Array) || !(out instanceof Uint8Array)) return null;
  if (input.length < 2) return null;
  const eta = intParam(frame.params, "eta");
  if (eta === null) return null;

  const n = input[input.length - 1] as number;
  const seed = input.subarray(0, input.length - 1);

  const units: NarrationUnit[] = [];

  units.push({
    key: "call",
    label: `1 — PRF(σ, N = ${n}) → ${out.length} bytes`,
    Prose: (props) => (
      <div>
        <p>
          One SHAKE256 call over <code>σ ‖ N</code>: a {seed.length}-byte secret seed with a single
          counter byte appended, squeezed for <code>64η = {out.length}</code> bytes. Those bytes are
          the input to the sampler below, which turns them into one noise polynomial.
        </p>
        <ValueList
          items={[
            { label: "N (this call)", text: `${n}` },
            { label: "η", text: `${eta}` },
            { label: "output length", text: `64 × ${eta} = ${out.length} bytes` },
          ]}
        />
        <p>
          <code>σ</code> ={" "}
          <Bytes bytes={seed.subarray(0, Math.min(8, seed.length))} fmt={props.fmt} /> …
        </p>
      </div>
    ),
  });

  units.push({
    key: "counter",
    label: "2 — the counter is the only thing separating six noise polynomials",
    Prose: () => (
      <div>
        <p>
          Key generation draws six noise polynomials from <strong>one</strong> seed <code>σ</code>:
          three for the secret <code>s</code> and three for the error <code>e</code>. Every one of
          those calls hands SHAKE256 the same 32 bytes. The counter is the entire difference.
        </p>
        <p>
          It runs <code>0, 1, 2</code> for <code>s</code> and then <code>3, 4, 5</code> for{" "}
          <code>e</code>, and it must not restart. Restarting it makes <code>e</code> a copy of{" "}
          <code>s</code> — a key that still generates, still encrypts and still decrypts, while the
          "error" meant to hide the secret <em>is</em> the secret. Everything downstream stays
          green; only the security is gone.
        </p>
      </div>
    ),
  });

  return units;
};

// ─── ml-kem.hash-g@1 / hash-h@1 / kdf-j@1 ──────────────────────────────────

/**
 * `G` splits its 64-byte output into two 32-byte halves that mean different
 * things at different call sites. The narrator distinguishes them by input
 * length rather than by guessing — 33 bytes is `d ‖ k` in key generation,
 * 64 is `m ‖ H(ek)` in encapsulation.
 */
export const mlKemHashGNarration: NarrationFn = (frame) => {
  const input = frame.portInputs?.get("input");
  const out = frame.portOutputs?.get("output");
  if (!(input instanceof Uint8Array) || !(out instanceof Uint8Array) || out.length !== 64) {
    return null;
  }
  const first = out.subarray(0, 32);
  const second = out.subarray(32);
  // 33 bytes is `d ‖ k` (key generation); 64 is `m ‖ H(ek)` (encapsulation).
  const keygen = input.length === 33;
  const names = keygen ? ["ρ", "σ"] : ["K", "r"];

  const units: NarrationUnit[] = [];

  units.push({
    key: "halves",
    label: `1 — one SHA3-512 call, two 32-byte halves (${names[0]} and ${names[1]})`,
    Prose: (props) => (
      <div>
        <p>
          <code>G</code> is SHA3-512 and produces 64 bytes, which are always cut in half. The halves
          mean different things at different call sites, and this one is{" "}
          {keygen ? (
            <>
              <strong>key generation</strong>: <code>ρ</code> is public and seeds the matrix,{" "}
              <code>σ</code> is secret and seeds all six noise polynomials
            </>
          ) : (
            <>
              <strong>encapsulation</strong>: <code>K</code> is the shared secret and <code>r</code>{" "}
              is the randomness the encryption is then run with
            </>
          )}
          .
        </p>
        <ValueList
          items={[{ label: `input (${input.length} bytes)`, text: keygen ? "d ‖ k" : "m ‖ H(ek)" }]}
        />
        <p>
          <code>{names[0]}</code> = <Bytes bytes={first.subarray(0, 8)} fmt={props.fmt} /> …
        </p>
        <p>
          <code>{names[1]}</code> = <Bytes bytes={second.subarray(0, 8)} fmt={props.fmt} /> …
        </p>
        <p>
          The split lives outside this step on purpose: one hash call, two consumers, and a visible
          cut between them beats a step that quietly returns a pair.
        </p>
      </div>
    ),
  });

  if (keygen) {
    units.push({
      key: "domain-byte",
      label: "2 — the input is d ‖ k, not d",
      Prose: () => (
        <div>
          <p>
            The 33rd byte is <code>k</code>, the number of polynomials in the module — 3 for
            ML-KEM-768. Appending it means the same 32-byte seed produces different keys at
            different parameter sets, so a seed can never be replayed across them.
          </p>
          <p>
            It is a late addition to the standard, and dropping it is the kind of error that is
            self-consistent end to end: keys generate, encapsulation and decapsulation agree, and
            only a comparison against someone else's implementation shows anything wrong.
          </p>
        </div>
      ),
    });
  }

  return units;
};

/** `H` — SHA3-256, used to bind a ciphertext to the key it was made for. */
export const mlKemHashHNarration: NarrationFn = (frame) => {
  const input = frame.portInputs?.get("input");
  const out = frame.portOutputs?.get("output");
  if (!(input instanceof Uint8Array) || !(out instanceof Uint8Array) || out.length !== 32) {
    return null;
  }

  return [
    {
      key: "digest",
      label: `1 — SHA3-256 over ${num(input.length)} bytes → 32`,
      Prose: (props) => (
        <div>
          <p>
            <code>H</code> is plain SHA3-256. Its usual job here is <code>H(ek)</code>: a 32-byte
            stand-in for the {num(input.length)}-byte encapsulation key, small enough to hash
            alongside a message.
          </p>
          <p>
            <Bytes bytes={out} fmt={props.fmt} />
          </p>
          <p>
            Folding the public key into the hash is what ties a ciphertext to one specific key. It
            is also stored inside the private key rather than recomputed, so decapsulation does not
            have to re-derive it on every use.
          </p>
        </div>
      ),
    },
    {
      key: "one-frame",
      // Deliberately NOT a frame count. One Keccak-f[1600] is 216 frames, but a
      // sponge is pad + one permutation PER ABSORBED BLOCK + squeeze, so the
      // number depends on the input: the traced SHA3-256 spec measures 222
      // frames on a short message and 1,974 on the 1184 bytes of an
      // encapsulation key. No single figure is right, so none is printed.
      label: "2 — one frame here, a few hundred per block in the Hash view",
      Prose: () => (
        <div>
          <p>
            This is a full sponge: pad, then twenty-four rounds of the Keccak-f[1600] permutation
            for every {num(136)}-byte block absorbed, then squeeze. It collapses to a single frame
            because ML-KEM calls a hash roughly seventeen times per key generation, and drawn out in
            full that is thousands of nodes of hashing before a single polynomial coefficient has
            been multiplied.
          </p>
          <p>
            The code behind it drives the same nine step executors the traced SHA3-256 spec emits,
            so the collapsed version cannot drift from the one you can watch. Select SHA3-256 under
            Hash to see every round.
          </p>
        </div>
      ),
    },
  ];
};

/**
 * `J` — the implicit-rejection KDF. Its whole reason for existing is the branch
 * no round-trip test ever reaches, so the narrator leads with that.
 */
export const mlKemKdfJNarration: NarrationFn = (frame) => {
  const input = frame.portInputs?.get("input");
  const out = frame.portOutputs?.get("output");
  if (!(input instanceof Uint8Array) || !(out instanceof Uint8Array)) return null;

  const z = input.subarray(0, Math.min(32, input.length));

  return [
    {
      key: "rejection",
      label: "1 — the shared secret for a ciphertext that failed its check",
      Prose: (props) => (
        <div>
          <p>
            Decapsulation re-encrypts what it just decrypted and compares. If the result does not
            match the ciphertext it was given, it does <strong>not</strong> report an error — it
            returns <code>J(z ‖ c)</code>, a different but perfectly deterministic key.
          </p>
          <p>
            <code>z</code> = <Bytes bytes={z.subarray(0, 8)} fmt={props.fmt} /> … (32 secret bytes
            stored in the private key for exactly this purpose)
          </p>
        </div>
      ),
    },
    {
      key: "why-silent",
      label: "2 — why silence, rather than an error",
      Prose: () => (
        <div>
          <p>
            An attacker who can submit ciphertexts and learn whether each one decrypted cleanly can
            recover the private key, one query at a time. That attack is what separates the
            encryption scheme underneath from the key-exchange wrapping it — the scheme itself is
            only secure against someone who watches, never against someone who asks.
          </p>
          <p>
            So a malformed ciphertext must be indistinguishable from a good one. It yields a key
            that is wrong, stable, and unpredictable without <code>z</code>, and the sender simply
            finds that the two sides disagree. This is the branch that every round-trip test misses,
            and it is the whole difference between the two.
          </p>
        </div>
      ),
    },
  ];
};
