/**
 * AES key-schedule simulator. Pure pedagogy-only re-implementation of
 * FIPS-197 §5.2 that *yields* per-word stage decomposition alongside the
 * round-key bytes.
 *
 * Why this exists separately from `src/steps/key-expansion.ts`: the
 * executor's contract is `(state, params, ctx) → state`, so it can only
 * write the final round-key buffers to aux — the intermediate `RotWord →
 * SubWord → Rcon → XOR-prev` chain that *makes* those round keys is
 * invisible to the trace. Phase 2 of the linear-mode pedagogy plan
 * surfaces that chain: this file re-runs the algorithm and *yields* the
 * intermediate words so the UI can step through "first compute
 * `RotWord(W[3])`, then `SubWord`, then XOR with Rcon[1]…" frame by frame.
 *
 * Architectural cost vs. refactoring the executor to yield: re-simulating
 * in viz duplicates the algorithm logic — but it leaves the runtime
 * contract intact (no `StepResult` shape change, no registry-wide ripple)
 * and the parity test (`tests/aes-key-schedule-sim-parity.test.ts`) pins
 * the simulator's `roundKeys` byte-for-byte against the executor's
 * `auxWrites`. Plan trade-off, decided in
 * ~/.claude/plans/immutable-doodling-quokka.md.
 *
 * Covers both `aes.key-expansion@1` (canonical `rounds === Nk + 6`) and
 * `aes.key-expansion@2` (relaxed `rounds >= Nk + 1`, on-the-fly Rcon
 * extension via `xtime`). The simulator extends Rcon when the seed is
 * short — at canonical round counts the seed is long enough and no
 * extension fires, matching `@1`'s behavior.
 */

/**
 * One discrete transformation step inside a word's derivation. Each stage
 * carries enough state (input + output, plus kind-specific details) for the
 * UI to render an arrow between two byte rows with a labelled operator.
 *
 * The discriminant is the union tag, picked to read aloud as the
 * pedagogically-honest name of the operation ("rotword", "subword", etc).
 */
export type AesStage =
  | {
      // i < Nk: word is unpacked directly from the master key. No
      // arithmetic, just a slice — surfaces in the explorer as
      // "W[i] = masterKey[4i..4i+4]" with no operator arrow.
      readonly kind: "init";
      readonly word: Uint8Array;
    }
  | {
      // Cyclic byte rotation: [a, b, c, d] → [b, c, d, a]. Fires only on
      // chain words (i % Nk === 0). Input is W[i-1], output is the rotated
      // word that feeds the next stage.
      readonly kind: "rotword";
      readonly input: Uint8Array;
      readonly output: Uint8Array;
    }
  | {
      // Byte-wise S-box substitution. Fires inside the chain (`subword`
      // here is the "with-rotword" variant) and again, separately, in
      // the AES-256 `Nk > 6 && i % Nk === 4` branch — distinguished by
      // `kind: "extra-subword"` so the UI can label them differently.
      readonly kind: "subword";
      readonly input: Uint8Array;
      readonly output: Uint8Array;
      // The four input bytes themselves, exposed so the UI can render
      // "S[a] = X, S[b] = Y, …" with the input indices visible. Indices
      // 0..255 into the S-box table.
      readonly sboxLookups: readonly [number, number, number, number];
    }
  | {
      // XOR round constant Rcon[i/Nk] into byte 0 of the word. Only one
      // byte changes; the other three pass through. The simulator
      // surfaces the Rcon value explicitly so the UI can write
      // "byte[0] XOR 0x{rconValue.toString(16)}".
      readonly kind: "rcon-xor";
      readonly input: Uint8Array;
      readonly rconValue: number;
      readonly output: Uint8Array;
    }
  | {
      // The AES-256-only branch (Nk > 6 && i % Nk === 4): a SubWord pass
      // with NO RotWord and NO Rcon XOR. Marked with a distinct kind so
      // the UI can call this out — it's the "AES-256 wrinkle" that
      // doesn't fire in AES-128 or AES-192.
      readonly kind: "extra-subword";
      readonly input: Uint8Array;
      readonly output: Uint8Array;
      readonly sboxLookups: readonly [number, number, number, number];
    }
  | {
      // Final XOR with W[i-Nk]: closes every chain (i % Nk === 0), every
      // AES-256 extra-subword path, AND every "plain" word's derivation.
      // The simulator emits this as the last stage for any word with
      // `i >= Nk`, varying only in what `input` is (the chain's output
      // / the extra-subword's output / W[i-1] verbatim, respectively).
      readonly kind: "xor-prev";
      readonly input: Uint8Array;
      readonly prevWord: Uint8Array;
      // Index of `prevWord` in the schedule, exposed so the UI can label
      // the arrow ("⊕ W[3]" rather than just "⊕"). Always `i - Nk`.
      readonly prevWordIndex: number;
      readonly output: Uint8Array;
    };

/**
 * One word in the expanded schedule, with its full derivation chain. The
 * top-level entry the UI iterates over.
 */
export type AesScheduleWord = {
  readonly wordIndex: number;
  readonly Nk: number;
  /** True when `wordIndex % Nk === 0` and `wordIndex >= Nk`. */
  readonly isChainStart: boolean;
  /** True when `Nk > 6 && wordIndex % Nk === 4` and `wordIndex >= Nk`. */
  readonly isNk8Mid: boolean;
  readonly stages: readonly AesStage[];
  /** The final 4 bytes of this word. Equals the last stage's `output`. */
  readonly finalValue: Uint8Array;
};

/**
 * Full simulation result. `roundKeys` packs `words[r*4..r*4+3]` into a
 * 16-byte column-major buffer per round — matches the executor's
 * `auxWrites.set("${prefix}.${r}", ...)` byte layout exactly. The parity
 * test asserts this equality.
 */
export type AesScheduleTrace = {
  readonly Nk: number;
  readonly Nr: number;
  readonly words: readonly AesScheduleWord[];
  readonly roundKeys: readonly Uint8Array[];
};

/**
 * Multiply by `x` in GF(2^8) with reduction polynomial 0x11b. The exact
 * recurrence the executor's `@2` variant uses to extend a short Rcon
 * seed. Replicated here rather than imported from `src/core/state/...`
 * so this file stays a self-contained pedagogy artifact — the parity
 * test catches any drift between the two copies.
 */
const xtime = (n: number): number => {
  const shifted = (n << 1) & 0xff;
  return (n & 0x80) === 0 ? shifted : shifted ^ 0x1b;
};

const rotWord = (w: Uint8Array): Uint8Array =>
  new Uint8Array([w[1] ?? 0, w[2] ?? 0, w[3] ?? 0, w[0] ?? 0]);

const subWord = (
  w: Uint8Array,
  sbox: readonly number[],
): { output: Uint8Array; lookups: readonly [number, number, number, number] } => {
  const a = w[0] ?? 0;
  const b = w[1] ?? 0;
  const c = w[2] ?? 0;
  const d = w[3] ?? 0;
  const output = new Uint8Array([sbox[a] ?? 0, sbox[b] ?? 0, sbox[c] ?? 0, sbox[d] ?? 0]);
  return { output, lookups: [a, b, c, d] };
};

const xorWord = (a: Uint8Array, b: Uint8Array): Uint8Array =>
  new Uint8Array([
    (a[0] ?? 0) ^ (b[0] ?? 0),
    (a[1] ?? 0) ^ (b[1] ?? 0),
    (a[2] ?? 0) ^ (b[2] ?? 0),
    (a[3] ?? 0) ^ (b[3] ?? 0),
  ]);

/**
 * Run the full AES key schedule yielding per-word stage decomposition.
 *
 * Throws on invalid `masterKey` length (must be 16, 24, or 32 bytes) or
 * `rounds < 1`. Matches the executor's validation envelope — both `@1`
 * and `@2` accept this same range; `@1` additionally requires `rounds ===
 * Nk + 6`, but the simulator does NOT enforce that (parity tests run
 * against `@2`'s relaxed bound and `@1`'s canonical bound alike).
 *
 * The Rcon seed extends on the fly via `xtime` when shorter than needed.
 * At canonical round counts the canonical seed is long enough and no
 * extension fires.
 */
export const simulateAesKeySchedule = (
  masterKey: Uint8Array,
  sbox: readonly number[],
  rconSeed: readonly number[],
  rounds: number,
): AesScheduleTrace => {
  if (masterKey.length !== 16 && masterKey.length !== 24 && masterKey.length !== 32) {
    throw new Error(
      `simulateAesKeySchedule: master key must be 16, 24, or 32 bytes; got ${masterKey.length}`,
    );
  }
  if (!Number.isInteger(rounds) || rounds < 1) {
    throw new Error(`simulateAesKeySchedule: rounds (${rounds}) must be an integer >= 1`);
  }
  if (sbox.length !== 256) {
    throw new Error(`simulateAesKeySchedule: sbox must have 256 entries; got ${sbox.length}`);
  }

  const Nk = masterKey.length / 4;
  const Nb = 4;
  const totalWords = Nb * (rounds + 1);
  const maxRconIdx = Math.floor((totalWords - 1) / Nk);

  // Resolve the Rcon table eagerly — extends from the seed via xtime if
  // needed (mirroring `@2`'s relaxed-rounds variant). At canonical round
  // counts the seed already covers `maxRconIdx`; the while-loop body
  // doesn't execute.
  const rcon: number[] = [...rconSeed];
  while (rcon.length <= maxRconIdx) {
    const prev = rcon[rcon.length - 1] ?? 0;
    // The recurrence starts at index 1 = 0x01 if the seed only contains
    // index 0 = 0 (canonical Rcon[0] is unused). Matches the executor's
    // identical fallback.
    rcon.push(rcon.length === 1 ? 0x01 : xtime(prev));
  }

  const words: AesScheduleWord[] = [];

  // ─── i < Nk: init words from the master key ──────────────────────────
  for (let i = 0; i < Nk; i++) {
    const w = new Uint8Array([
      masterKey[4 * i] ?? 0,
      masterKey[4 * i + 1] ?? 0,
      masterKey[4 * i + 2] ?? 0,
      masterKey[4 * i + 3] ?? 0,
    ]);
    words.push({
      wordIndex: i,
      Nk,
      isChainStart: false,
      isNk8Mid: false,
      stages: [{ kind: "init", word: w }],
      finalValue: w,
    });
  }

  // ─── i >= Nk: derived words with per-stage decomposition ─────────────
  for (let i = Nk; i < totalWords; i++) {
    const prevWord = words[i - 1]?.finalValue ?? new Uint8Array(4);
    const farPrevWord = words[i - Nk]?.finalValue ?? new Uint8Array(4);
    const isChainStart = i % Nk === 0;
    const isNk8Mid = Nk > 6 && i % Nk === 4;

    const stages: AesStage[] = [];
    let chainOutput: Uint8Array = prevWord;

    if (isChainStart) {
      // Stage 1: RotWord
      const rotated = rotWord(prevWord);
      stages.push({ kind: "rotword", input: prevWord, output: rotated });

      // Stage 2: SubWord
      const subResult = subWord(rotated, sbox);
      stages.push({
        kind: "subword",
        input: rotated,
        output: subResult.output,
        sboxLookups: subResult.lookups,
      });

      // Stage 3: Rcon XOR (byte 0 only)
      const rconIdx = i / Nk;
      const rconValue = rcon[rconIdx] ?? 0;
      const rconOutput = new Uint8Array([
        (subResult.output[0] ?? 0) ^ rconValue,
        subResult.output[1] ?? 0,
        subResult.output[2] ?? 0,
        subResult.output[3] ?? 0,
      ]);
      stages.push({
        kind: "rcon-xor",
        input: subResult.output,
        rconValue,
        output: rconOutput,
      });

      chainOutput = rconOutput;
    } else if (isNk8Mid) {
      // AES-256 wrinkle: extra-SubWord, no RotWord, no Rcon.
      const subResult = subWord(prevWord, sbox);
      stages.push({
        kind: "extra-subword",
        input: prevWord,
        output: subResult.output,
        sboxLookups: subResult.lookups,
      });
      chainOutput = subResult.output;
    }
    // Plain word: chainOutput stays as prevWord (no intermediate stages).

    // Final stage: XOR with W[i-Nk].
    const finalWord = xorWord(farPrevWord, chainOutput);
    stages.push({
      kind: "xor-prev",
      input: chainOutput,
      prevWord: farPrevWord,
      prevWordIndex: i - Nk,
      output: finalWord,
    });

    words.push({
      wordIndex: i,
      Nk,
      isChainStart,
      isNk8Mid,
      stages,
      finalValue: finalWord,
    });
  }

  // Pack 4 consecutive words into each 16-byte round key — exact same
  // layout the executor writes to `auxWrites.set("${prefix}.${r}", rk)`.
  // Column-major: rk[word*4 + 0..3] = word's bytes 0..3.
  const roundKeys: Uint8Array[] = [];
  for (let r = 0; r <= rounds; r++) {
    const rk = new Uint8Array(16);
    for (let word = 0; word < 4; word++) {
      const src = words[r * 4 + word]?.finalValue ?? new Uint8Array(4);
      rk[word * 4 + 0] = src[0] ?? 0;
      rk[word * 4 + 1] = src[1] ?? 0;
      rk[word * 4 + 2] = src[2] ?? 0;
      rk[word * 4 + 3] = src[3] ?? 0;
    }
    roundKeys.push(rk);
  }

  return {
    Nk,
    Nr: rounds,
    words,
    roundKeys,
  };
};
