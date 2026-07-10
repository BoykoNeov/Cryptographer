/**
 * Blowfish per-frame value-prose narrators (2026-07-11).
 *
 * Two narrators, both keyed on Blowfish-ONLY step types so no other cipher's
 * linear view is touched (the shared port-native arithmetic primitives —
 * `xor@1` / `add-mod-32@1` / `xor-with-aux@1` / `concat@1` / `split-bytes@1` —
 * are deliberately left to PortFlowView + each leaf's `narrationOverride`
 * detail, matching AES's port-native round body, which also carries no
 * value-prose narrator):
 *
 *   1. `blowfish.sbox-lookup@1` — the single highest-value narrator. A 1-byte
 *      index → 4-byte word is exactly the transformation the port I/O table
 *      does NOT make legible ("why did these 4 bytes appear from that 1?").
 *      Names the specific key-derived S-box and shows the resolved word.
 *
 *   2. `blowfish.key-schedule@1` — the "expand the monolith in linear view"
 *      request. The 521-encryption loop stays ONE trace frame (there is no
 *      legible per-encryption decomposition — see the step doc), but the
 *      StepNarration `<details>` mechanism gives it disclosable pedagogy ROWS:
 *      a coarse mix / P-fill / S-fill / result breakdown, each annotated with
 *      the REAL published values the frame wrote into aux (`blowfish.P.*` /
 *      `blowfish.S*`) — not static text. Coarse by design (the authoring
 *      convention forbids 521 per-item disclosures).
 */

import type { Json } from "@/core/types";
import { Index } from "solid-js";
import { formatBytes } from "../components/byte-row";
import type { NarrationFn, NarrationUnit } from "./registry";

// ─── blowfish.sbox-lookup@1 ────────────────────────────────────────────────

/**
 * Narrate one F-function S-box lookup: byte `index` → the 32-bit word stored at
 * that position of the (key-derived) S-box named by the `sboxName` param.
 * Declines (null) if the port bytes aren't the expected 1-byte-in / 4-byte-out
 * shape — e.g. a half-wired palette-dropped copy.
 */
export const blowfishSboxLookupNarration: NarrationFn = (frame) => {
  const index = frame.portInputs?.get("index");
  const output = frame.portOutputs?.get("output");
  if (!(index instanceof Uint8Array) || index.length !== 1) return null;
  if (!(output instanceof Uint8Array) || output.length !== 4) return null;
  const entry = index[0] ?? 0;
  // `sboxName` is e.g. "blowfish.S0"; show just the "S0" tail as the box label.
  const sboxName = readStringParam(frame.params, "sboxName") ?? "S?";
  const boxLabel = sboxName.slice(sboxName.lastIndexOf(".") + 1);
  return [
    {
      key: "lookup",
      // Decimal entry in the label so it stays stable across the byte-format
      // toggle (labels aren't fmt-reactive; only Prose bodies are).
      label: `${boxLabel}[entry ${entry}] → 32-bit word`,
      Prose: (props) => (
        <div>
          <p>
            F splits its 32-bit input into four bytes and looks each up in a different S-box. This
            leaf takes byte <strong>{formatBytes(index, props.fmt)}</strong> (entry {entry} of 256)
            and reads the 32-bit word stored there in <code>{boxLabel}</code>:{" "}
            <strong>{formatBytes(output, props.fmt)}</strong>.
          </p>
          <p>
            Blowfish's four S-boxes are <em>key-derived</em> — regenerated from the key during key
            setup, not fixed constants. So this entire table (and therefore this lookup's result)
            changes completely when the key changes; that key dependence, spread across 1024
            entries, is most of what F contributes to the cipher's strength.
          </p>
        </div>
      ),
    },
  ];
};

// ─── blowfish.key-schedule@1 (the monolith) ────────────────────────────────

/**
 * Disclosable pedagogy rows for the opaque 521-encryption loop. Reads the
 * frame's key-mixed-P input + the P/S it published to aux, so each row shows
 * the actual bytes this run produced. Declines only if the frame carries no
 * published P material (a genuinely broken/unwired monolith).
 */
export const blowfishKeyScheduleNarration: NarrationFn = (frame) => {
  const prefix = readStringParam(frame.params, "outputPrefix") ?? "blowfish";
  const keyMixedP = frame.portInputs?.get("keyMixedP");

  // Collect the 18 published P words (blowfish.P.0 .. blowfish.P.17).
  const pWords: Uint8Array[] = [];
  for (let i = 0; i < 18; i++) {
    const w = frame.auxWritten.get(`${prefix}.P.${i}`);
    if (w instanceof Uint8Array) pWords.push(w);
  }
  if (pWords.length === 0) return null; // nothing published → decline.

  // Collect the four S-box heads (first 4 words = 16 bytes) for a legible peek.
  const sHeads: { label: string; head: Uint8Array; words: number }[] = [];
  for (let b = 0; b < 4; b++) {
    const box = frame.auxWritten.get(`${prefix}.S${b}`);
    if (box instanceof Uint8Array) {
      sHeads.push({ label: `S${b}`, head: box.slice(0, 16), words: Math.floor(box.length / 4) });
    }
  }

  const units: NarrationUnit[] = [];

  // Row 1 — the visible key-mix that feeds this step.
  units.push({
    key: "mix",
    label: "1 — Mix the key into the P-array (18 XORs, shown above)",
    Prose: (props) => (
      <div>
        <p>
          The 18 <code>xor</code> frames above this step XOR the key (cycling its words) into the
          π-derived P-array seed, producing the <strong>key-mixed P-array</strong> — the 72-byte
          value this step reads on its <code>keyMixedP</code> input:
        </p>
        {keyMixedP instanceof Uint8Array ? (
          <p>
            <code>{formatBytes(keyMixedP, props.fmt)}</code>
          </p>
        ) : (
          <p>(input not captured)</p>
        )}
        <p>
          This is the <em>only</em> visible part of the key schedule. Everything below happens
          inside the opaque loop — there is no legible per-encryption decomposition (a full unroll
          is tens of thousands of frames), so the app shows the loop's <em>stages and results</em>,
          not each of its 521 encryptions.
        </p>
      </div>
    ),
  });

  // Row 2 — the 9 encryptions that fill the P-array.
  units.push({
    key: "pfill",
    label: `2 — Nine encryptions fill P[0..${pWords.length - 1}]`,
    Prose: (props) => (
      <div>
        <p>
          Encrypt the all-zero 64-bit block with the current P/S; its two output words become{" "}
          <code>P[0], P[1]</code>. Encrypt that output for <code>P[2], P[3]</code>, and so on — nine
          encryptions fill all {pWords.length} P-array words. The final P-array this run produced:
        </p>
        <ol class="blowfish-pword-list">
          <Index each={pWords}>
            {(w, i) => (
              <li>
                <code>
                  P[{i}] = {formatBytes(w(), props.fmt)}
                </code>
              </li>
            )}
          </Index>
        </ol>
      </div>
    ),
  });

  // Row 3 — the 512 encryptions that fill the four S-boxes.
  if (sHeads.length > 0) {
    units.push({
      key: "sfill",
      label: "3 — 512 encryptions fill the four S-boxes S0..S3",
      Prose: (props) => (
        <div>
          <p>
            The loop keeps going, filling <code>S0[0], S0[1], … S3[255]</code> — {sHeads[0]?.words}{" "}
            words per box, {sHeads.length} boxes, {sHeads.length * (sHeads[0]?.words ?? 0)} words in
            all, one word per pair of the 512 remaining encryptions. The head of each box this run
            produced (first four words):
          </p>
          <ul class="blowfish-sbox-head-list">
            <Index each={sHeads}>
              {(s) => (
                <li>
                  <code>
                    {s().label}[0..3] = {formatBytes(s().head, props.fmt)}
                  </code>
                </li>
              )}
            </Index>
          </ul>
        </div>
      ),
    });
  }

  // Row 4 — what the step publishes + why the loop is deliberately slow.
  units.push({
    key: "result",
    label: "4 — Publish the final P-array + S-boxes to aux",
    Prose: () => (
      <div>
        <p>
          The finished P-array and four S-boxes are published into{" "}
          <code>
            aux[{prefix}.P.0 … {prefix}.P.17]
          </code>{" "}
          and{" "}
          <code>
            aux[{prefix}.S0 … {prefix}.S3]
          </code>
          . Each Feistel round below reads its subkey <code>P[i]</code> from the first; the four
          F-function lookups read the S-boxes from the second.
        </p>
        <p>
          Because the entire P-array and all four S-boxes are re-derived from scratch, changing the
          key re-runs all 521 encryptions. That slow key setup was a deliberate Blowfish design goal
          (it frustrates brute-force key search); here the cost is microseconds.
        </p>
      </div>
    ),
  });

  return units;
};

// ─── Helpers ────────────────────────────────────────────────────────────────

const readStringParam = (params: Json, key: string): string | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>)[key];
  return typeof v === "string" && v.length > 0 ? v : null;
};
