/**
 * Twofish per-frame value-prose narrators (2026-07-12).
 *
 * Two narrators, both keyed on Twofish-ONLY step types so no other cipher's
 * linear view is touched (the shared port-native arithmetic — `xor@1` /
 * `add-mod-32@1` / `rotate-bits-right@1` / `concat@1` / `split-bytes@1` /
 * `gf-matrix-multiply@2` — is deliberately left to PortFlowView + each leaf's
 * `narrationOverride`, matching AES's / Blowfish's port-native round bodies):
 *
 *   1. `twofish.sbox-lookup@1` — the g-function's byte→byte substitution. A
 *      1-byte index → 1-byte value through a key-derived S-box is exactly the
 *      transformation the port I/O table does not make legible.
 *
 *   2. `twofish.h-expand@1` — the user's explicit "explain the opaque block"
 *      requirement. The h-function machinery stays ONE trace frame (no legible
 *      per-frame decomposition), but the StepNarration `<details>` mechanism
 *      gives it disclosable pedagogy ROWS — one per hidden stage (key decode →
 *      RS S-vector → S-box construction → h/A-B material) — each annotated with
 *      the REAL per-key values this run produced (read from the frame's port
 *      I/O + published aux, never recomputed). This is the
 *      `blowfishKeyScheduleNarration` pattern; Twofish is a better fit because
 *      its hidden stages are conceptually distinct and legibly explainable.
 */

import type { Json } from "@/core/types";
import { Index } from "solid-js";
import { formatBytes } from "../components/byte-row";
import type { NarrationFn, NarrationUnit } from "./registry";

// ─── twofish.sbox-lookup@1 ─────────────────────────────────────────────────

/**
 * Narrate one g-function S-box lookup: byte `index` → the byte stored at that
 * position of the (key-derived) S-box named by `sboxName`. Declines (null) if
 * the port bytes aren't the expected 1-byte-in / 1-byte-out shape.
 */
export const twofishSboxLookupNarration: NarrationFn = (frame) => {
  const index = frame.portInputs?.get("index");
  const output = frame.portOutputs?.get("output");
  if (!(index instanceof Uint8Array) || index.length !== 1) return null;
  if (!(output instanceof Uint8Array) || output.length !== 1) return null;
  const entry = index[0] ?? 0;
  const outByte = output[0] ?? 0;
  const sboxName = readStringParam(frame.params, "sboxName") ?? "S?";
  const boxLabel = sboxName.slice(sboxName.lastIndexOf(".") + 1);
  return [
    {
      key: "lookup",
      // Decimal in the label so it stays stable across the byte-format toggle.
      label: `${boxLabel}[entry ${entry}] → ${outByte}`,
      Prose: (props) => (
        <div>
          <p>
            Twofish's g function splits its 32-bit input into four bytes and runs each through a
            different S-box. This leaf takes byte <strong>{formatBytes(index, props.fmt)}</strong>{" "}
            (entry {entry} of 256) and reads the byte stored there in <code>{boxLabel}</code>:{" "}
            <strong>{formatBytes(output, props.fmt)}</strong>. The four substituted bytes are then
            combined by the MDS matrix into a 32-bit word.
          </p>
          <p>
            Twofish's four S-boxes are <em>key-dependent</em> — built from the key during key setup
            (through the RS S-vector and the q-permutation construction), not fixed constants. So
            this entire table (and therefore this lookup's result) changes completely when the key
            changes; that key-dependent substitution is a large part of what makes Twofish's g
            function hard to analyze.
          </p>
        </div>
      ),
    },
  ];
};

// ─── twofish.h-expand@1 (the opaque monolith) ──────────────────────────────

const WORD = (b: unknown): Uint8Array | null =>
  b instanceof Uint8Array && b.length === 4 ? b : null;

/**
 * Disclosable pedagogy rows for the opaque h-function half of the key schedule.
 * Reads the frame's published aux (A/B/S) + display-only port outputs (S-vector,
 * master-key words), so each row shows the actual values this run produced.
 * Declines only if the frame published no A material (a broken/unwired monolith).
 */
export const twofishHExpandNarration: NarrationFn = (frame) => {
  const prefix = readStringParam(frame.params, "outputPrefix") ?? "twofish";

  // The 20 A_i / 20 B_i (published to aux).
  const aWords: Uint8Array[] = [];
  const bWords: Uint8Array[] = [];
  for (let i = 0; i < 20; i++) {
    const a = WORD(frame.auxWritten.get(`${prefix}.A.${i}`));
    const b = WORD(frame.auxWritten.get(`${prefix}.B.${i}`));
    if (a) aWords.push(a);
    if (b) bWords.push(b);
  }
  if (aWords.length === 0) return null; // nothing published → decline.

  // The four S-box heads (first 16 bytes) for a legible peek.
  const sHeads: { label: string; head: Uint8Array }[] = [];
  for (let b = 0; b < 4; b++) {
    const box = frame.auxWritten.get(`${prefix}.S${b}`);
    if (box instanceof Uint8Array) sHeads.push({ label: `S${b}`, head: box.slice(0, 16) });
  }

  // Display-only ports: the S-vector words + master-key words.
  const svec0 = WORD(frame.portOutputs?.get("svec0"));
  const svec1 = WORD(frame.portOutputs?.get("svec1"));
  const mWords: Uint8Array[] = [];
  for (let i = 0; i < 4; i++) {
    const m = WORD(frame.portOutputs?.get(`m${i}`));
    if (m) mWords.push(m);
  }

  const units: NarrationUnit[] = [];

  // Row 1 — decode the key into words + the even/odd split.
  units.push({
    key: "decode",
    label: "1 — Decode the key → words M0..M3, split even/odd",
    Prose: (props) => (
      <div>
        <p>
          Twofish reads the 16-byte key as four little-endian 32-bit words <code>M0..M3</code>, then
          splits them into the <strong>even</strong> words <code>Me = (M0, M2)</code> (which feed
          the A-side h evaluations) and the <strong>odd</strong> words <code>Mo = (M1, M3)</code>{" "}
          (the B-side).
        </p>
        {mWords.length === 4 ? (
          <ol class="twofish-word-list">
            <Index each={mWords}>
              {(w, i) => (
                <li>
                  <code>
                    M{i} = {formatBytes(w(), props.fmt)}
                  </code>
                </li>
              )}
            </Index>
          </ol>
        ) : (
          <p>(key words not captured)</p>
        )}
      </div>
    ),
  });

  // Row 2 — the RS S-vector.
  units.push({
    key: "svector",
    label: "2 — Reed–Solomon S-vector (keys the S-boxes)",
    Prose: (props) => (
      <div>
        <p>
          Each 8-byte half of the key is run through a Reed–Solomon code — a 4×8 matrix multiply
          over GF(2⁸) with reduction polynomial <code>0x14D</code> — to produce two 32-bit words{" "}
          <code>S_0, S_1</code>. These key the four S-boxes. Note the word-order <em>reversal</em>:
          the S-box construction uses the list <code>(S_1, S_0)</code> — a classic gotcha an
          endpoint test can't catch.
        </p>
        {svec0 && svec1 ? (
          <ul class="twofish-word-list">
            <li>
              <code>S_0 = {formatBytes(svec0, props.fmt)}</code>
            </li>
            <li>
              <code>S_1 = {formatBytes(svec1, props.fmt)}</code>
            </li>
          </ul>
        ) : (
          <p>(S-vector not captured)</p>
        )}
      </div>
    ),
  });

  // Row 3 — the four key-dependent S-boxes.
  if (sHeads.length > 0) {
    units.push({
      key: "sboxes",
      label: "3 — Build the four key-dependent S-boxes S0..S3",
      Prose: (props) => (
        <div>
          <p>
            Each of the four byte→byte S-boxes composes the fixed q0/q1 permutations with XORs of
            the S-vector bytes (three q-layers for a 128-bit key). At run time the g function is
            then just <em>four lookups → MDS</em>. The head of each box this run produced (first 16
            bytes):
          </p>
          <ul class="twofish-sbox-head-list">
            <Index each={sHeads}>
              {(s) => (
                <li>
                  <code>
                    {s().label}[0..15] = {formatBytes(s().head, props.fmt)}
                  </code>
                </li>
              )}
            </Index>
          </ul>
        </div>
      ),
    });
  }

  // Row 4 — the h evaluations that produce A/B, and the handoff to the PHT.
  units.push({
    key: "ab",
    label: "4 — Forty h evaluations → the A/B subkey material",
    Prose: (props) => (
      <div>
        <p>
          For <code>i = 0..19</code>, Twofish computes <code>A_i = h(2i·ρ, Me)</code> and{" "}
          <code>B_i = ROL(h((2i+1)·ρ, Mo), 8)</code>, where h is the same q-box + MDS chain the
          S-boxes use and ρ = <code>0x01010101</code>. These 40 words feed the <em>visible</em> PHT
          blocks just below, which combine each pair into the subkeys{" "}
          <code>
            K_{"{"}2i{"}"}
          </code>{" "}
          /{" "}
          <code>
            K_{"{"}2i+1{"}"}
          </code>
          . The first few produced this run:
        </p>
        <ol class="twofish-ab-list">
          <Index each={aWords.slice(0, 4)}>
            {(a, i) => (
              <li>
                <code>
                  A_{i} = {formatBytes(a(), props.fmt)}
                  {bWords[i]
                    ? `   B_${i} = ${formatBytes(bWords[i] as Uint8Array, props.fmt)}`
                    : ""}
                </code>
              </li>
            )}
          </Index>
        </ol>
        <p>
          This row is the handoff from the opaque half to the visible half: everything above happens
          inside this one frame; the subkey mixing below is shown step by step.
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
