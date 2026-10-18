/**
 * ML-DSA per-frame value-prose narrators — P2 of
 * `docs/plans/refactored-petting-tide.md`.
 *
 * Keyed on `ml-dsa.*` step types (plus the generic `zq-inf-norm-below@1`), so
 * no other algorithm's linear view is touched. The same test decided every
 * entry as it decided the ML-KEM ones in `lattice.tsx`: **does the teaching
 * point change frame to frame?** For these it does —
 *
 *   - a norm check's verdict, and how far over or under the bound it landed,
 *     is the whole point of a rejection, and only this frame knows it;
 *   - how many coefficients hit Decompose's wrap-round case, or needed a hint,
 *     depends on the values;
 *   - the worked example is always a coefficient THIS run produced.
 *
 * `zq-vec-mul@1` is deliberately NOT here: like its three element-wise
 * siblings it is 256 identical products per frame, and sits on the allowlist.
 *
 * Every value is read off the frame's own ports with the executors' codec
 * (`readCoeff`) and the executors' arithmetic (`core/ml-dsa-arith.ts`), so the
 * prose cannot disagree with the step about what was computed.
 */

import { decompose, modPm } from "@/core/ml-dsa-arith";
import type { TraceFrame } from "@/core/types";
import { Bytes, ValueList, coeffs, intParam, modulusOf, num, safeVecParams } from "./lattice";
import type { NarrationFn } from "./registry";

// ─── Shared helpers ────────────────────────────────────────────────────────

/** A scalar input port (γ2, a bound, ω) as a number, or null. */
const scalarOf = (frame: TraceFrame, name: string): number | null => {
  const bytes = frame.portInputs?.get(name);
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 6) return null;
  let v = 0;
  for (const b of bytes) v = v * 256 + b;
  return v;
};

/** A vector port as numbers, or null. */
const vecOf = (
  ports: ReadonlyMap<string, Uint8Array> | undefined,
  name: string,
  p: NonNullable<ReturnType<typeof safeVecParams>>,
): number[] | null => {
  const bytes = ports?.get(name);
  if (!(bytes instanceof Uint8Array)) return null;
  return coeffs(bytes, p).map(Number);
};

/** A residue read as the signed number it stands for. */
const signed = (v: number, q: number): number => modPm(v, q);

/** `−5` with a real minus sign, thousands separated. */
const sNum = (v: number): string => (v < 0 ? `−${num(-v)}` : num(v));

// ─── zq-inf-norm-below@1 ───────────────────────────────────────────────────

/**
 * The verdict leads, because in signing this frame IS the reason an attempt
 * was thrown away or kept. The second row shows the coefficient responsible,
 * in both its wire form and its signed form — the "q − 5 is small" surprise is
 * only convincing on a value this run produced.
 */
export const zqInfNormBelowNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "zq-inf-norm-below@1");
  if (!p) return null;
  const qb = modulusOf(frame, p);
  const bound = scalarOf(frame, "bound");
  const a = vecOf(frame.portInputs, "a", p);
  const flag = frame.portOutputs?.get("output");
  if (qb === null || bound === null || a === null || !(flag instanceof Uint8Array)) return null;
  const q = Number(qb);

  let worstIndex = -1;
  let norm = 0;
  a.forEach((v, i) => {
    const mag = Math.abs(signed(v, q));
    if (mag > norm || worstIndex < 0) {
      norm = mag;
      worstIndex = i;
    }
  });
  const passed = flag[0] === 1;

  const units = [
    {
      key: "verdict",
      label: passed
        ? `1 — small: ‖a‖∞ = ${num(norm)} < ${num(bound)}`
        : `1 — too large: ‖a‖∞ = ${num(norm)} ≥ ${num(bound)}`,
      Prose: () => (
        <div>
          <p>
            The largest of the {num(a.length)} coefficients, measured as a distance from zero, is{" "}
            <code>{num(norm)}</code>. The bound is <code>{num(bound)}</code>, and the test is
            strictly below it.
          </p>
          <p>
            {passed
              ? `It passes, with ${num(bound - norm)} to spare.`
              : norm === bound
                ? "It fails by landing exactly ON the bound — the one value a ≤ test would wrongly let through."
                : `It fails, over by ${num(norm - bound + 1)}.`}{" "}
            In signing, a failure here throws the whole candidate signature away and the signer
            tries again.
          </p>
        </div>
      ),
    },
  ];
  if (worstIndex >= 0) {
    const raw = a[worstIndex] as number;
    const s = signed(raw, q);
    units.push({
      key: "worst",
      label: `2 — the largest is coefficient ${worstIndex}: ${sNum(s)}`,
      Prose: () => (
        <div>
          <p>
            On the wire, coefficient {worstIndex} is <code>{num(raw)}</code>.
            {s < 0
              ? ` That is above (q − 1)/2, so it is really a negative number: ${num(raw)} − ${num(q)} = ${sNum(s)}, which is ${num(-s)} below zero.`
              : " That is below (q − 1)/2, so it reads as itself."}
          </p>
          <p>Distance from zero, either side, is what "small" means here.</p>
        </div>
      ),
    });
  }
  return units;
};

// ─── ml-dsa.power2round@1 ──────────────────────────────────────────────────

export const mlDsaPower2RoundNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "ml-dsa.power2round@1");
  if (!p) return null;
  const d = intParam(frame.params, "d");
  const qb = modulusOf(frame, p);
  const a = vecOf(frame.portInputs, "a", p);
  const high = vecOf(frame.portOutputs, "high", p);
  const low = vecOf(frame.portOutputs, "low", p);
  if (d === null || qb === null || a === null || high === null || low === null) return null;
  if (a.length === 0 || high.length !== a.length || low.length !== a.length) return null;
  const q = Number(qb);
  const totalBits = Math.ceil(Math.log2(q));
  const r = a[0] as number;
  const r1 = high[0] as number;
  const r0 = signed(low[0] as number, q);

  return [
    {
      key: "example",
      label: `1 — coefficient 0: ${num(r)} = ${num(r1)} · 2^${d} ${r0 < 0 ? "−" : "+"} ${num(Math.abs(r0))}`,
      Prose: () => (
        <div>
          <p>
            Each coefficient is rounded to the nearest multiple of <code>2^{d}</code> ={" "}
            {num(2 ** d)}. Coefficient 0 is <code>{num(r)}</code>:
          </p>
          <ValueList
            items={[
              { label: "high part r1", text: num(r1) },
              { label: "low part r0", text: sNum(r0) },
              { label: `r1 · ${num(2 ** d)} + r0`, text: num(r1 * 2 ** d + r0) },
            ]}
          />
          {r0 < 0 ? (
            <p>
              The low part is negative — it rounded UP — so it travels the wire as{" "}
              <code>q − {num(-r0)}</code> = {num(low[0] as number)}.
            </p>
          ) : null}
        </div>
      ),
    },
    {
      key: "size",
      label: `2 — ${totalBits - d} of ${totalBits} bits kept for the public key`,
      Prose: () => (
        <div>
          <p>
            In key generation the high parts are the public key and the low parts stay private. Each
            coefficient needs {totalBits} bits; only the top {totalBits - d} are published, which is
            what shrinks an ML-DSA-44 public key from 2,976 bytes to 1,312.
          </p>
          <p>
            The verifier therefore knows the key only to within those {d} dropped bits, and a
            signature has to carry a hint to make up for it.
          </p>
        </div>
      ),
    },
  ];
};

// ─── ml-dsa.decompose@1 ────────────────────────────────────────────────────

export const mlDsaDecomposeNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "ml-dsa.decompose@1");
  if (!p) return null;
  const qb = modulusOf(frame, p);
  const g2 = scalarOf(frame, "gamma2");
  const a = vecOf(frame.portInputs, "a", p);
  const high = vecOf(frame.portOutputs, "high", p);
  if (qb === null || g2 === null || g2 === 0 || a === null || high === null) return null;
  if (a.length === 0 || high.length !== a.length) return null;
  const q = Number(qb);
  if ((q - 1) % (2 * g2) !== 0) return null;
  const m = (q - 1) / (2 * g2);

  const wrappedIndices: number[] = [];
  a.forEach((r, i) => {
    if (decompose(r, g2, q).wrapped) wrappedIndices.push(i);
  });
  const r = a[0] as number;
  const ex = decompose(r, g2, q);

  return [
    {
      key: "example",
      label: `1 — coefficient 0 is in bucket ${ex.r1} of ${m}, offset ${sNum(ex.r0)}`,
      Prose: () => (
        <div>
          <p>
            The range 0 … q − 1 is cut into {m} buckets, each 2γ2 = {num(2 * g2)} wide. Coefficient
            0 is <code>{num(r)}</code>:
          </p>
          <ValueList
            items={[
              { label: "high bits r1 (bucket)", text: num(ex.r1) },
              { label: "low bits r0 (offset from its centre)", text: sNum(ex.r0) },
            ]}
          />
          <p>A signature commits to the high bits only; the low bits are noise it can drop.</p>
        </div>
      ),
    },
    {
      key: "wrap",
      label:
        wrappedIndices.length === 0
          ? "2 — no coefficient needed the wrap-round fix"
          : `2 — ${num(wrappedIndices.length)} coefficient${wrappedIndices.length === 1 ? "" : "s"} wrapped round to bucket 0`,
      Prose: () => (
        <div>
          <p>
            Values within γ2 of q − 1 are, on this circle, just below zero. They would round to a
            bucket number {m} that does not exist, so they go in bucket 0 with a negative offset.
          </p>
          <p>
            {wrappedIndices.length === 0
              ? `None of the ${num(a.length)} values on this frame was that close to the top.`
              : `On this frame that happened at coefficient${wrappedIndices.length === 1 ? "" : "s"} ${wrappedIndices
                  .slice(0, 6)
                  .join(", ")}${wrappedIndices.length > 6 ? ", …" : ""} — for example ${num(
                  a[wrappedIndices[0] as number] as number,
                )} became bucket 0, offset ${sNum(
                  decompose(a[wrappedIndices[0] as number] as number, g2, q).r0,
                )}.`}
          </p>
        </div>
      ),
    },
  ];
};

// ─── ml-dsa.make-hint@1 / ml-dsa.use-hint@1 ────────────────────────────────

export const mlDsaMakeHintNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "ml-dsa.make-hint@1");
  if (!p) return null;
  const qb = modulusOf(frame, p);
  const g2 = scalarOf(frame, "gamma2");
  const z = vecOf(frame.portInputs, "z", p);
  const r = vecOf(frame.portInputs, "r", p);
  const h = vecOf(frame.portOutputs, "output", p);
  if (qb === null || g2 === null || g2 === 0 || z === null || r === null || h === null) return null;
  if (h.length === 0 || h.length !== r.length || h.length !== z.length) return null;
  const q = Number(qb);
  if ((q - 1) % (2 * g2) !== 0) return null;

  const ones = h.flatMap((b, i) => (b === 1 ? [i] : []));
  const units = [
    {
      key: "count",
      label: `1 — ${num(ones.length)} of ${num(h.length)} coefficients need a hint`,
      Prose: () => (
        <div>
          <p>
            A 1 marks a coefficient whose high bits change when the small correction is added — the
            ones the verifier would otherwise get wrong by one bucket. Here {num(ones.length)} of{" "}
            {num(h.length)} do
            {ones.length > 0
              ? `, at position${ones.length === 1 ? "" : "s"} ${ones.slice(0, 8).join(", ")}${ones.length > 8 ? ", …" : ""}.`
              : "."}
          </p>
          <p>A signature has room for at most ω of them; more and the candidate is thrown away.</p>
        </div>
      ),
    },
  ];
  const i = ones[0];
  if (i !== undefined) {
    const ri = r[i] as number;
    const zi = z[i] as number;
    const before = decompose(ri, g2, q);
    const after = decompose(ri + zi, g2, q);
    units.push({
      key: "example",
      label: `2 — coefficient ${i}: bucket ${before.r1} → ${after.r1}`,
      Prose: () => (
        <div>
          <p>
            Coefficient {i} is <code>{num(ri)}</code>, in bucket {before.r1} at offset{" "}
            {sNum(before.r0)}. Adding the correction <code>{sNum(signed(zi, q))}</code> moves it to
            bucket {after.r1}, so its hint bit is 1.
          </p>
        </div>
      ),
    });
  }
  return units;
};

export const mlDsaUseHintNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "ml-dsa.use-hint@1");
  if (!p) return null;
  const qb = modulusOf(frame, p);
  const g2 = scalarOf(frame, "gamma2");
  const h = vecOf(frame.portInputs, "h", p);
  const r = vecOf(frame.portInputs, "r", p);
  const out = vecOf(frame.portOutputs, "output", p);
  if (qb === null || g2 === null || g2 === 0 || h === null || r === null || out === null)
    return null;
  if (h.length === 0 || h.length !== r.length || out.length !== r.length) return null;
  const q = Number(qb);
  if ((q - 1) % (2 * g2) !== 0) return null;

  let up = 0;
  let down = 0;
  let firstCorrected = -1;
  h.forEach((b, i) => {
    if (b !== 1) return;
    if (firstCorrected < 0) firstCorrected = i;
    if (decompose(r[i] as number, g2, q).r0 > 0) up++;
    else down++;
  });

  const units = [
    {
      key: "count",
      label: `1 — ${num(up + down)} corrected: ${num(up)} up a bucket, ${num(down)} down`,
      Prose: () => (
        <div>
          <p>
            Every coefficient with a hint bit of 1 drifted into a neighbouring bucket on the way to
            the verifier. Its low bits say which neighbour: in the upper half of its bucket means it
            came from the bucket above, otherwise from the one below.
          </p>
          <p>
            Of {num(up + down)} corrections on this frame, {num(up)} moved up and {num(down)} moved
            down. The rest of the {num(h.length)} coefficients pass through unchanged.
          </p>
        </div>
      ),
    },
  ];
  if (firstCorrected >= 0) {
    const ri = r[firstCorrected] as number;
    const d = decompose(ri, g2, q);
    units.push({
      key: "example",
      label: `2 — coefficient ${firstCorrected}: bucket ${d.r1} → ${out[firstCorrected] as number}`,
      Prose: () => (
        <div>
          <p>
            Coefficient {firstCorrected} is <code>{num(ri)}</code>: bucket {d.r1}, offset{" "}
            {sNum(d.r0)}. Its hint is 1 and the offset is {d.r0 > 0 ? "positive" : "not positive"},
            so the intended bucket is {out[firstCorrected] as number}. Buckets wrap: one below 0 is
            the last bucket, and one above the last is 0.
          </p>
        </div>
      ),
    });
  }
  return units;
};

// ─── ml-dsa.hint-count@1 ───────────────────────────────────────────────────

export const mlDsaHintCountNarration: NarrationFn = (frame) => {
  const omega = scalarOf(frame, "omega");
  const flag = frame.portOutputs?.get("output");
  const countPort = frame.portOutputs?.get("count");
  if (omega === null || !(flag instanceof Uint8Array) || !(countPort instanceof Uint8Array)) {
    return null;
  }
  const count = ((countPort[0] ?? 0) << 8) | (countPort[1] ?? 0);
  const passed = flag[0] === 1;
  return [
    {
      key: "verdict",
      label: passed
        ? `1 — fits: ${num(count)} ≤ ω = ${num(omega)}`
        : `1 — too many: ${num(count)} > ω = ${num(omega)}`,
      Prose: () => (
        <div>
          <p>
            The hint marks {num(count)} coefficient{count === 1 ? "" : "s"} for correction. A
            signature stores each one as a position, and has exactly ω = {num(omega)} slots.
          </p>
          <p>
            {passed
              ? count === omega
                ? "That fills every slot — and exactly full is allowed."
                : `That leaves ${num(omega - count)} slot${omega - count === 1 ? "" : "s"} unused.`
              : "It cannot be written down, so the candidate signature is thrown away and the signer tries again."}
          </p>
        </div>
      ),
    },
  ];
};

// ─── ml-dsa.ntt@1 / ml-dsa.intt@1 ──────────────────────────────────────────

/**
 * The cross-reference monoliths. The per-frame facts are how many polynomials
 * went through and what coefficient 0 became; the standing fact — this is one
 * frame of something traced elsewhere — is said in the second row, in the
 * ML-KEM hash narrators' words.
 */
const nttNarration =
  (direction: "forward" | "inverse"): NarrationFn =>
  (frame) => {
    const input = frame.portInputs?.get("input");
    const out = frame.portOutputs?.get("output");
    if (!(input instanceof Uint8Array) || !(out instanceof Uint8Array)) return null;
    if (input.length === 0 || input.length % 1024 !== 0 || out.length !== input.length) return null;
    const p = { coeffBytes: 4, littleEndian: false };
    const polys = input.length / 1024;
    const a0 = Number(coeffs(input.subarray(0, 4), p)[0]);
    const b0 = Number(coeffs(out.subarray(0, 4), p)[0]);
    return [
      {
        key: "count",
        label: `1 — ${polys} polynomial${polys === 1 ? "" : "s"} ${direction === "forward" ? "transformed" : "transformed back"}`,
        Prose: () => (
          <div>
            <p>
              {direction === "forward"
                ? `Each of the ${polys} polynomial${polys === 1 ? "" : "s"} went through all eight layers of the transform on its own. Afterwards, multiplying two of them is one product per coefficient.`
                : `Each of the ${polys} polynomial${polys === 1 ? "" : "s"} went back through the eight layers in reverse, then every coefficient was multiplied by 256⁻¹ = 8,347,681.`}
            </p>
            <ValueList
              items={[
                { label: "coefficient 0 in", text: num(a0) },
                { label: "coefficient 0 out", text: num(b0) },
              ]}
            />
          </div>
        ),
      },
      {
        key: "one-frame",
        label: "2 — one frame here, eight layers under Lattice",
        Prose: () => (
          <div>
            <p>
              This is the whole transform collapsed to one step, because ML-DSA needs about twenty
              of them per signing attempt. Select <b>NTT mod 8380417</b> under <b>Lattice</b> to
              watch the same transform run butterfly by butterfly; the two are tested to agree.
            </p>
          </div>
        ),
      },
    ];
  };

export const mlDsaNttNarration: NarrationFn = nttNarration("forward");
export const mlDsaInttNarration: NarrationFn = nttNarration("inverse");

// ─── ml-dsa.hash-h@1 ───────────────────────────────────────────────────────

/** What a call of a given length is, at ML-DSA's call sites. */
const hashJob = (outBytes: number): string => {
  switch (outBytes) {
    case 128:
      return "the key-seed expansion: ρ (32 bytes), ρ′ (64) and K (32)";
    case 64:
      return "tr, μ or ρ″ — a 64-byte fingerprint of the public key, of the message, or of this signature's randomness";
    case 32:
      return "c̃, the commitment hash a signature carries";
    default:
      return "a length none of ML-DSA's own calls uses";
  }
};

export const mlDsaHashHNarration: NarrationFn = (frame) => {
  const input = frame.portInputs?.get("input");
  const out = frame.portOutputs?.get("output");
  if (!(input instanceof Uint8Array) || !(out instanceof Uint8Array)) return null;
  return [
    {
      key: "digest",
      label: `1 — SHAKE256 over ${num(input.length)} bytes → ${num(out.length)}`,
      Prose: (props) => (
        <div>
          <p>
            {num(out.length)} bytes is {hashJob(out.length)}.
          </p>
          <p>
            <Bytes bytes={out.subarray(0, Math.min(out.length, 32))} fmt={props.fmt} />
            {out.length > 32 ? " …" : ""}
          </p>
          <p>
            The sponge is the one under <b>Hash → SHAKE256</b>, collapsed to one frame here.
          </p>
        </div>
      ),
    },
  ];
};

// ─── ml-dsa.expand-a@1 / expand-s@1 / expand-mask@1 ────────────────────────

export const mlDsaExpandANarration: NarrationFn = (frame) => {
  const k = intParam(frame.params, "k");
  const l = intParam(frame.params, "l");
  const p = safeVecParams(frame.params, "ml-dsa.expand-a@1");
  const out = frame.portOutputs?.get("output");
  if (k === null || l === null || !p || !(out instanceof Uint8Array)) return null;
  const first = coeffs(out.subarray(0, 4 * p.coeffBytes), p).map((c) => num(Number(c)));
  return [
    {
      key: "matrix",
      label: `1 — a ${k} × ${l} matrix: ${num(k * l)} polynomials, ${num(k * l * 256)} coefficients`,
      Prose: () => (
        <div>
          <p>
            Every entry was squeezed out of SHAKE256's smaller sibling, SHAKE128, from the public
            seed followed by two index bytes — the column, then the row. Candidates of 23 bits were
            kept only when below q, so each entry cost a slightly different number of bytes.
          </p>
          <p>
            Entry [0][0] begins <code>{first.join(", ")}, …</code> — already in the transformed
            domain, because a uniformly random matrix is just as random after the transform.
          </p>
        </div>
      ),
    },
  ];
};

export const mlDsaExpandSNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "ml-dsa.expand-s@1");
  const eta = intParam(frame.params, "eta");
  if (!p || eta === null) return null;
  const qb = modulusOf(frame, p);
  const s1 = vecOf(frame.portOutputs, "s1", p);
  const s2 = vecOf(frame.portOutputs, "s2", p);
  if (qb === null || s1 === null || s2 === null) return null;
  const q = Number(qb);
  const all = [...s1, ...s2].map((v) => signed(v, q));
  const counts = new Map<number, number>();
  for (const v of all) counts.set(v, (counts.get(v) ?? 0) + 1);
  const histogram: { label: string; text: string }[] = [];
  for (let v = -eta; v <= eta; v++)
    histogram.push({ label: sNum(v), text: num(counts.get(v) ?? 0) });
  return [
    {
      key: "histogram",
      label: `1 — ${num(all.length)} secret coefficients, each in ${sNum(-eta)} … ${eta}`,
      Prose: () => (
        <div>
          <p>
            How often each value came up in s1 and s2 together. The rule draws them uniformly, so
            the counts should be roughly equal — roughly{" "}
            {num(Math.round(all.length / (2 * eta + 1)))} each:
          </p>
          <ValueList items={histogram} />
          <p>
            A negative value travels the wire as q minus its size: −1 is <code>{num(q - 1)}</code>.
          </p>
        </div>
      ),
    },
  ];
};

export const mlDsaExpandMaskNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "ml-dsa.expand-mask@1");
  const l = intParam(frame.params, "l");
  if (!p || l === null) return null;
  const kappa = scalarOf(frame, "kappa");
  const gamma1 = scalarOf(frame, "gamma1");
  const qb = modulusOf(frame, p);
  const y = vecOf(frame.portOutputs, "output", p);
  if (kappa === null || gamma1 === null || qb === null || y === null) return null;
  const q = Number(qb);
  let max = 0;
  for (const v of y) max = Math.max(max, Math.abs(signed(v, q)));
  const attempt = Math.floor(kappa / l) + 1;
  return [
    {
      key: "counter",
      label: `1 — attempt ${attempt}: counters ${num(kappa)} … ${num(kappa + l - 1)}`,
      Prose: () => (
        <div>
          <p>
            κ = {num(kappa)} and l = {l}, so this is signing attempt {attempt}, and its {l}{" "}
            polynomials were drawn from counters {num(kappa)} to {num(kappa + l - 1)}. Every attempt
            uses counters no earlier attempt touched, so its mask is new.
          </p>
          <p>
            The coefficients spread over −{num(gamma1 - 1)} … {num(gamma1)}; the largest here is{" "}
            {num(max)} from zero. The mask is big on purpose: it is what drowns out the secret.
          </p>
        </div>
      ),
    },
  ];
};

// ─── ml-dsa.sample-in-ball@1 ───────────────────────────────────────────────

export const mlDsaSampleInBallNarration: NarrationFn = (frame) => {
  const p = safeVecParams(frame.params, "ml-dsa.sample-in-ball@1");
  const tau = intParam(frame.params, "tau");
  if (!p || tau === null) return null;
  const qb = modulusOf(frame, p);
  const c = vecOf(frame.portOutputs, "output", p);
  const rej = frame.portOutputs?.get("rejections");
  if (qb === null || c === null || !(rej instanceof Uint8Array)) return null;
  const q = Number(qb);
  const s = c.map((v) => signed(v, q));
  const plus = s.filter((v) => v === 1).length;
  const minus = s.filter((v) => v === -1).length;
  const rejections = ((rej[0] ?? 0) << 8) | (rej[1] ?? 0);
  const positions = s.flatMap((v, i) => (v !== 0 ? [i] : []));
  return [
    {
      key: "shape",
      label: `1 — ${plus + minus} nonzero: ${plus} × (+1), ${minus} × (−1)`,
      Prose: () => (
        <div>
          <p>
            Exactly τ = {tau} of the 256 coefficients are ±1, at positions{" "}
            {positions.slice(0, 10).join(", ")}
            {positions.length > 10 ? ", …" : ""}. The rest are 0.
          </p>
          <p>
            That sparseness is the point: multiplying a secret whose coefficients are at most η by
            this c gives coefficients no bigger than τ·η — the β the signing checks leave room for.
          </p>
        </div>
      ),
    },
    {
      key: "rejections",
      label: `2 — ${rejections} squeezed byte${rejections === 1 ? "" : "s"} thrown away`,
      Prose: () => (
        <div>
          <p>
            Each placement needs a byte no larger than the position being filled, and a larger one
            is discarded. On this hash that happened {rejections} time{rejections === 1 ? "" : "s"}.
            Another hash would give another number — this step's cost depends on its input's value,
            not its size.
          </p>
        </div>
      ),
    },
  ];
};

// ─── ml-dsa.format-message@1 ───────────────────────────────────────────────

export const mlDsaFormatMessageNarration: NarrationFn = (frame) => {
  const input = frame.portInputs?.get("input");
  const out = frame.portOutputs?.get("output");
  if (!(input instanceof Uint8Array) || !(out instanceof Uint8Array) || out.length < 2) return null;
  const ctxLen = out[1] as number;
  return [
    {
      key: "prefix",
      label:
        ctxLen === 0
          ? `1 — prefix 00 00: no context, ${num(input.length)}-byte message`
          : `1 — prefix 00 ${ctxLen.toString(16).padStart(2, "0")} + a ${ctxLen}-byte context`,
      Prose: (props) => (
        <div>
          <p>
            The first byte, 0, says the message itself is being signed (the pre-hashed variant uses
            1). The second is the context string's length, {ctxLen}
            {ctxLen === 0 ? ", so nothing follows it but the message." : ":"}
          </p>
          {ctxLen > 0 ? (
            <p>
              <Bytes bytes={out.subarray(2, 2 + ctxLen)} fmt={props.fmt} />
            </p>
          ) : null}
          <p>
            Leave this prefix out and every other implementation rejects the signature, because it
            would be checking different bytes from the ones that were signed.
          </p>
        </div>
      ),
    },
  ];
};
