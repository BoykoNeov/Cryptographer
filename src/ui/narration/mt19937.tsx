/**
 * MT19937 per-frame value-prose narrators (2026-08-09).
 *
 * Two narrators, both keyed on MT19937-ONLY step types, so no other
 * algorithm's linear view is touched. The tempering chain below them is
 * deliberately left to PortFlowView plus each leaf's `narrationOverride`,
 * matching how AES's, Blowfish's and Twofish's port-native bodies are handled
 * — those leaves are ordinary shifts, masks and XORs whose port I/O table is
 * already legible.
 *
 * These two are the exception, and for the reason the whole
 * `blowfishKeyScheduleNarration` / `twofishHExpandNarration` pattern exists:
 * **they are opaque monoliths**, so a static description alone asks the
 * learner to take 624 steps on faith. The `<details>` disclosure rows give
 * each hidden stage its own row, annotated with the REAL values this run
 * produced — read out of the frame's own port I/O, never recomputed by
 * re-running the algorithm, so the prose cannot agree with itself while the
 * executor is wrong.
 *
 * The one derivation performed here is the splice `y` in the twist narrator,
 * which is assembled from two words read off the input port. That is a
 * display convenience for a value the frame does not expose on a port of its
 * own; it is a bit-concatenation of two shown values, so a reader can check it
 * against the two words printed beside it.
 */

import { Index } from "solid-js";
import { formatBytes } from "../components/byte-row";
import type { NarrationFn, NarrationUnit } from "./registry";

/** Words in the state — MT19937's `n`. */
const N = 624;
/** The offset word — `m`. */
const M = 397;

/** The i-th big-endian word of a state buffer, or null if out of range. */
const wordAt = (bytes: Uint8Array, i: number): Uint8Array | null =>
  i >= 0 && (i + 1) * 4 <= bytes.length ? bytes.subarray(i * 4, (i + 1) * 4) : null;

/** Read a 4-byte big-endian word as an unsigned number. */
const toU32 = (w: Uint8Array): number =>
  (((w[0] as number) << 24) |
    ((w[1] as number) << 16) |
    ((w[2] as number) << 8) |
    (w[3] as number)) >>>
  0;

const hex32 = (v: number): string => `0x${(v >>> 0).toString(16).padStart(8, "0")}`;

/** A small labelled list of words, formatted in the active byte format. */
const WordList = (props: { items: { label: string; bytes: Uint8Array }[]; fmt: string }) => (
  <ol class="twofish-word-list">
    <Index each={props.items}>
      {(it) => (
        <li>
          <code>
            {it().label} = {formatBytes(it().bytes, props.fmt as never)}
          </code>
        </li>
      )}
    </Index>
  </ol>
);

// ─── mt19937.seed@1 ────────────────────────────────────────────────────────

/**
 * Disclosure rows for the seeding monolith. Reads the seed off the input port
 * and the resulting state off the output port, so every number shown is the
 * one this run actually produced. Declines if the ports are not the expected
 * 4-byte-in / 2496-byte-out shape.
 */
export const mt19937SeedNarration: NarrationFn = (frame) => {
  const seed = frame.portInputs?.get("input");
  const state = frame.portOutputs?.get("output");
  if (!(seed instanceof Uint8Array) || seed.length !== 4) return null;
  if (!(state instanceof Uint8Array) || state.length !== N * 4) return null;

  const mt0 = wordAt(state, 0);
  const mt1 = wordAt(state, 1);
  const mt2 = wordAt(state, 2);
  const last3 = [621, 622, 623].map((i) => wordAt(state, i));
  if (!mt0 || !mt1 || !mt2 || last3.some((w) => w === null)) return null;

  const seedValue = toU32(seed);
  const units: NarrationUnit[] = [];

  units.push({
    key: "verbatim",
    label: `1 — mt[0] is the seed itself (${seedValue})`,
    Prose: (props) => (
      <div>
        <p>
          The first word of the state is the seed, copied in unchanged. Everything else in this
          624-word array is manufactured from it by the recurrence below — which is why the seed
          alone determines the entire sequence.
        </p>
        <WordList
          items={[
            { label: "seed", bytes: seed },
            { label: "mt[0]", bytes: mt0 },
          ]}
          fmt={props.fmt}
        />
      </div>
    ),
  });

  units.push({
    key: "recurrence",
    label: "2 — each later word from the one before it",
    Prose: (props) => (
      <div>
        <p>
          For <code>i = 1 … 623</code>, Matsumoto and Nishimura's <code>init_genrand</code> runs a
          small linear congruential generator — Knuth's multiplier, with each word's top two bits
          folded down before the multiply so consecutive words do not stay correlated:
        </p>
        <p>
          <code>mt[i] = 1812433253 · (mt[i−1] ^ (mt[i−1] &gt;&gt; 30)) + i</code>
        </p>
        <p>
          On this run that produced <code>mt[1] = {hex32(toU32(mt1))}</code> from{" "}
          <code>mt[0] = {hex32(toU32(mt0))}</code>, and then <code>mt[2]</code> from that:
        </p>
        <WordList
          items={[
            { label: "mt[0]", bytes: mt0 },
            { label: "mt[1]", bytes: mt1 },
            { label: "mt[2]", bytes: mt2 },
          ]}
          fmt={props.fmt}
        />
        <p>
          Note the <code>+ i</code>: that is the loop counter, and it is the reason this stage is a
          single step here rather than 623 visible ones — nothing in this app produces an iteration
          index for a loop body to read.
        </p>
      </div>
    ),
  });

  units.push({
    key: "far-end",
    label: "3 — the far end of the state, 623 steps later",
    Prose: (props) => (
      <div>
        <p>
          The same recurrence, run to the end of the array. These are the last three words this run
          produced — worth a look because the twist below reads <em>forward</em> from every position
          and wraps around to here.
        </p>
        <WordList
          items={[
            { label: "mt[621]", bytes: last3[0] as Uint8Array },
            { label: "mt[622]", bytes: last3[1] as Uint8Array },
            { label: "mt[623]", bytes: last3[2] as Uint8Array },
          ]}
          fmt={props.fmt}
        />
      </div>
    ),
  });

  units.push({
    key: "cost",
    label: "4 — what a 32-bit seed costs, permanently",
    Prose: () => (
      <div>
        <p>
          The state holds 19,937 usable bits, but it was filled from <strong>32</strong>. So only
          2³² of the possible states can ever be reached — about four billion distinct sequences,
          out of a space astronomically larger.
        </p>
        <p>
          The period of any one sequence is 2¹⁹⁹³⁷−1, which sounds like the relevant number and is
          not. If a program seeds from the clock, an attacker's search space is not the state space;
          it is the set of plausible timestamps.
        </p>
        <p>
          One more thing worth knowing: <code>init_genrand(s)</code> is not the only seeding routine
          MT19937 ships with. <code>init_by_array</code> exists too, CPython and numpy's modern
          generators use it for integer seeds, and it produces a completely different stream from
          the same number. This app implements <code>init_genrand</code>, the convention of C++'s{" "}
          <code>std::mt19937</code>.
        </p>
      </div>
    ),
  });

  return units;
};

// ─── mt19937.twist@1 ───────────────────────────────────────────────────────

/**
 * Disclosure rows for the twist monolith. Reads the state before and after off
 * the frame's two ports, so the splice, the conditional XOR and the in-place
 * overwrite are all shown with this run's real words.
 */
export const mt19937TwistNarration: NarrationFn = (frame) => {
  const before = frame.portInputs?.get("input");
  const after = frame.portOutputs?.get("output");
  if (!(before instanceof Uint8Array) || before.length !== N * 4) return null;
  if (!(after instanceof Uint8Array) || after.length !== N * 4) return null;

  const old0 = wordAt(before, 0);
  const old1 = wordAt(before, 1);
  const oldM = wordAt(before, M);
  const new0 = wordAt(after, 0);
  if (!old0 || !old1 || !oldM || !new0) return null;

  // The splice, assembled from the two words shown beside it: the top bit of
  // mt[0] with the low 31 bits of mt[1]. Displayed rather than published,
  // because the monolith exposes no port for it.
  const y = ((toU32(old0) & 0x80000000) | (toU32(old1) & 0x7fffffff)) >>> 0;
  const lowBitSet = (y & 1) === 1;

  // Position 227 is where the wrap starts reading ALREADY-TWISTED words:
  // 227 + 397 = 624 ≡ 0, so mt[227] is built from the NEW mt[0].
  const wrapIndex = N - M; // 227
  const newWrap = wordAt(after, wrapIndex);
  const oldWrap = wordAt(before, wrapIndex);

  const units: NarrationUnit[] = [];

  units.push({
    key: "splice",
    label: `1 — the splice at i = 0 → y = ${hex32(y)}`,
    Prose: (props) => (
      <div>
        <p>
          Each step first builds a value <code>y</code> by taking the <strong>top bit</strong> of
          one word and the <strong>low 31 bits</strong> of the next:
        </p>
        <p>
          <code>y = (mt[0] &amp; 0x80000000) | (mt[1] &amp; 0x7fffffff)</code>
        </p>
        <WordList
          items={[
            { label: "mt[0]", bytes: old0 },
            { label: "mt[1]", bytes: old1 },
          ]}
          fmt={props.fmt}
        />
        <p>
          which on this run gives <code>y = {hex32(y)}</code>.
        </p>
        <p>
          That 31/1 split is where the generator's name comes from. The state holds 624 × 32 =
          19,968 bits, but one word only ever contributes its highest — so 31 bits never take part,
          and the period is 2¹⁹⁹³⁷−1 rather than 2¹⁹⁹⁶⁸−1. 19937 is a Mersenne exponent, and that
          period is a Mersenne prime.
        </p>
      </div>
    ),
  });

  units.push({
    key: "twist",
    label: `2 — the twist: ${lowBitSet ? "0x9908b0df XORed in" : "0x9908b0df skipped"}`,
    Prose: (props) => (
      <div>
        <p>
          The new word is the word 397 places along, XORed with <code>y &gt;&gt; 1</code> and —{" "}
          <strong>
            only when the bit shifted off the bottom of <code>y</code> was 1
          </strong>{" "}
          — with the twist constant:
        </p>
        <p>
          <code>mt[0] = mt[397] ^ (y &gt;&gt; 1) ^ (y &amp; 1 ? 0x9908b0df : 0)</code>
        </p>
        <p>
          Here <code>y = {hex32(y)}</code>, whose lowest bit is <strong>{lowBitSet ? 1 : 0}</strong>
          , so the constant was <strong>{lowBitSet ? "applied" : "not applied"}</strong> on this
          step.
        </p>
        <WordList
          items={[
            { label: "mt[397]", bytes: oldM },
            { label: "mt[0] (new)", bytes: new0 },
          ]}
          fmt={props.fmt}
        />
        <p>
          <code>0x9908b0df</code> is the coefficient vector of a primitive polynomial over GF(2),
          and that conditional XOR is a matrix multiplication in disguise. Its primitivity is what
          makes the period maximal — and it is also the generator's defining weakness, because{" "}
          <strong>every operation here is linear over GF(2)</strong>. XOR, shift, conditional XOR:
          no addition, no carry anywhere. Each new bit is a fixed exclusive-or of old bits, which is
          why enough observed output lets you solve for the state with linear algebra rather than
          search.
        </p>
      </div>
    ),
  });

  if (newWrap && oldWrap) {
    units.push({
      key: "wrap",
      label: `3 — from i = ${wrapIndex} the loop reads its own output`,
      Prose: (props) => (
        <div>
          <p>
            The update happens <strong>in place</strong>. At <code>i = {wrapIndex}</code> the{" "}
            <code>mt[i+397]</code> term wraps around to <code>mt[0]</code> — a word this same loop
            already rewrote a moment ago. So the first {wrapIndex} steps read only old values, and
            the remaining {M} read a mixture:
          </p>
          <WordList
            items={[
              { label: `mt[${wrapIndex}] (old)`, bytes: oldWrap },
              { label: `mt[${wrapIndex}] (new)`, bytes: newWrap },
              { label: "mt[0] (new — the word it read)", bytes: new0 },
            ]}
            fmt={props.fmt}
          />
          <p>
            This is the second reason the twist is a single step rather than a visible loop. Even
            setting aside that each step reads three words where a loop body can only see its own,
            the sequence genuinely cannot be run in parallel: treating it as one wide operation over
            shifted copies of the array yields a different generator that merely looks similar.
          </p>
        </div>
      ),
    });
  }

  units.push({
    key: "refill",
    label: "4 — and it happens again every 624 words",
    Prose: () => (
      <div>
        <p>
          All 624 words advanced at once, and they are handed out one at a time until they run out —
          at which point the real generator twists again. This app's output ceiling keeps a run
          inside the first batch, so this is the only twist you will see here.
        </p>
        <p>
          Nothing in this step conceals its state: the words above are the generator's complete
          internal state, and the tempering that follows is a reversible relabelling of them. That
          is the whole difference between this generator and the ChaCha20 CSPRNG in the same menu.
        </p>
      </div>
    ),
  });

  return units;
};
