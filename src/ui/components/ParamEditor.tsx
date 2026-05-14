/**
 * Top-level params editor. Looks at the currently selected step (whatever
 * frame the timeline is parked on) and dispatches to a per-step-type
 * sub-editor: 16x16 grid for S-boxes, 4x4 for MixColumns, etc.
 *
 * The "Apply to all" button below each editor propagates the same params
 * to every step of the same type — useful when changing "the AES S-box"
 * (which the architecture stores as 10 separate copies, one per round).
 *
 * Editing flows: ParamEditor → spec store mutator → spec signal updates →
 * createEffect in App.tsx detects the change → debounced re-run → trace
 * updates → matrix view re-renders. No imperative re-run call from here.
 */

import { findStep } from "@/core/spec-mutations";
import type { Json, StepLeaf } from "@/core/types";
import { For, Match, Show, Switch, createSignal } from "solid-js";
import { editAllStepsByType, editStepParams, removeStepFromSpec, useSpec } from "../stores/spec";
import { ByteCellInput } from "./ByteCellInput";
import { MatrixEditor } from "./MatrixEditor";
import { SboxEditor } from "./SboxEditor";
import { ShiftsEditor } from "./ShiftsEditor";

type Props = {
  /**
   * The id of the step we should be editing. Decoupled from the trace
   * frame so freshly-inserted steps (palette drops, with empty params and
   * no executed frame yet) are immediately editable, and so steps that
   * never executed (e.g. an upstream step threw) remain reachable through
   * a graph-view click. The id is resolved against the live spec via
   * `findStep`, so the spec — not the trace — is the source of truth.
   */
  stepId: string | null;
};

export const ParamEditor = (props: Props) => {
  const spec = useSpec();

  // Resolve the stepId to a live spec leaf. Returns null if the id is null
  // or no longer present in the spec (e.g. the user deleted it from
  // another surface). The Show below renders the "no step selected"
  // fallback in both cases.
  const step = (): StepLeaf | null => {
    const id = props.stepId;
    if (!id) return null;
    return findStep(spec(), id);
  };

  const matchingSteps = (): number => {
    const s = step();
    if (!s) return 0;
    // Count how many leaves share this step's type — used by the
    // "Apply to all N steps" button label.
    let count = 0;
    const visit = (
      nodes: readonly { kind: string; type?: string; children?: readonly unknown[] }[],
    ): void => {
      for (const node of nodes) {
        if (node.kind === "step" && node.type === s.type) count++;
        else if (node.kind === "group") visit(node.children as never);
      }
    };
    visit(spec().steps as never);
    return count;
  };

  return (
    <Show when={step()} fallback={<div class="muted">no step selected</div>}>
      {(getStep) => (
        <div class="param-editor">
          <div class="param-editor-header">
            <span class="param-editor-title">params · {getStep().id}</span>
            <span class="param-editor-type">{getStep().type}</span>
          </div>

          <Switch
            fallback={
              <div class="muted small">
                no editor for step type {getStep().type} (raw params view)
                <pre class="param-raw">{JSON.stringify(getStep().params, null, 2)}</pre>
              </div>
            }
          >
            <Match when={getStep().type === "generic.byte-substitution@1"}>
              <SbxBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "generic.mix-columns@1"}>
              <MixBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "generic.shift-rows@1"}>
              <ShiftsBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match
              when={
                getStep().type === "aes.key-expansion@1" || getStep().type === "aes.key-expansion@2"
              }
            >
              <KeyExpansionBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "generic.add-round-key@1"}>
              <AddRoundKeyBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={BLOCK_SIZE_PARAM_TYPES.has(getStep().type)}>
              <BlockSizeBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "speck.key-schedule@1"}>
              <SpeckKeyScheduleBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match
              when={
                getStep().type === "speck.round@1" || getStep().type === "speck.round-inverse@1"
              }
            >
              <SpeckRoundBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "serpent.key-expansion@1"}>
              <SerpentKeyExpansionBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "serpent.bit-permutation@1"}>
              <SerpentBitPermutationBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "serpent.add-round-key@1"}>
              <SerpentAddRoundKeyBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "serpent.sub-bytes@1"}>
              <SerpentSubBytesBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match
              when={
                getStep().type === "serpent.linear-transform@1" ||
                getStep().type === "serpent.inv-linear-transform@1"
              }
            >
              <NoParamsBlock label="Linear transform has no editable parameters." />
            </Match>
            <Match when={getStep().type === "generic.aux-load@1"}>
              <AuxLoadBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "generic.aux-xor@1"}>
              <AuxXorBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "generic.aux-copy@1"}>
              <AuxCopyBlock step={getStep()} />
            </Match>
          </Switch>

          {/* Delete affordance. Sits at the bottom of the editor so it
              doesn't compete with per-block "Apply to all" rows. No
              confirmation dialog — the cipher pedagogy is "experiment
              freely, see what breaks"; an accidental delete is recovered
              by dragging the step back in from the palette. The button
              is intentionally low-emphasis (no .danger class) to keep
              the editor feeling like a workbench, not a tribunal. */}
          <div class="param-editor-footer">
            <button
              type="button"
              class="param-editor-delete"
              data-testid="param-editor-delete"
              onClick={() => removeStepFromSpec(getStep().id)}
              title={`Remove ${getStep().id} from the spec`}
            >
              Delete this step
            </button>
          </div>
        </div>
      )}
    </Show>
  );
};

// ─── Per-step-type editor blocks ─────────────────────────────────────────
// Each one knows the param shape for its step type, owns its "Apply to all"
// button, and writes through the spec store. Kept small + similar so the
// pattern is obvious when adding the next step type.

type BlockProps = { step: StepLeaf; matchingCount: number };

const SbxBlock = (props: BlockProps) => {
  const sbox = (): readonly number[] =>
    ((props.step.params as { sbox?: number[] }).sbox ?? []) as readonly number[];

  return (
    <>
      <SboxEditor
        sbox={sbox()}
        onChange={(next) => {
          // Replace just this step's S-box. The user must explicitly hit
          // "Apply to all" to propagate.
          // params is typed as Json (which may be a primitive) but we know
          // these step types always have object params.
          editStepParams(props.step.id, {
            ...(props.step.params as Record<string, Json>),
            sbox: next,
          });
        }}
      />
      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="S-box"
      />
    </>
  );
};

const MixBlock = (props: BlockProps) => {
  const matrix = (): readonly (readonly number[])[] =>
    (props.step.params as { matrix?: number[][] }).matrix ?? [];

  return (
    <>
      <MatrixEditor
        matrix={matrix()}
        onChange={(next) => {
          editStepParams(props.step.id, {
            ...(props.step.params as Record<string, Json>),
            matrix: next,
          });
        }}
      />
      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="MixColumns matrix"
      />
    </>
  );
};

const ShiftsBlock = (props: BlockProps) => {
  const shifts = (): readonly number[] =>
    ((props.step.params as { shifts?: number[] }).shifts ?? []) as readonly number[];

  return (
    <>
      <ShiftsEditor
        shifts={shifts()}
        onChange={(next) => {
          editStepParams(props.step.id, {
            ...(props.step.params as Record<string, Json>),
            shifts: next,
          });
        }}
      />
      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="row shifts"
      />
    </>
  );
};

// Key-expansion block.
//
// The raw JSON fallback was unusable for this step type — `sbox` (256
// numbers) and `rcon` (~11) pretty-print to hundreds of single-value
// lines. This compact view shows:
//   - scalars (keyAuxName / outputPrefix / rounds) as a read-only dl;
//     editing them by hand reliably breaks the spec (mismatched aux
//     names throw, and the executor asserts `rounds === Nk + 6`).
//   - rcon as a single horizontal row of editable byte cells.
//   - the S-box collapsed inside a <details>, reusing SboxEditor so
//     the affordance is identical to SubBytes.
const KeyExpansionBlock = (props: BlockProps) => {
  const params = (): {
    keyAuxName?: string;
    outputPrefix?: string;
    rounds?: number;
    sbox?: readonly number[];
    rcon?: readonly number[];
  } => props.step.params as never;

  const sbox = (): readonly number[] => params().sbox ?? [];
  const rcon = (): readonly number[] => params().rcon ?? [];

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Input aux</dt>
          <dd>{params().keyAuxName ?? "—"}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Output prefix</dt>
          <dd>{params().outputPrefix ?? "—"}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Rounds (Nr)</dt>
          <dd>{params().rounds ?? "—"}</dd>
        </div>
      </dl>

      <div class="param-section">
        <div class="param-section-label">Rcon (round constants)</div>
        <div class="rcon-row">
          <For each={rcon()}>
            {(value, i) => (
              <ByteCellInput
                value={value}
                onCommit={(next) => {
                  const out = [...rcon()];
                  out[i()] = next;
                  writeParams({ rcon: out });
                }}
              />
            )}
          </For>
        </div>
      </div>

      <details class="param-section param-collapsible">
        <summary class="param-section-label">S-box (256 entries — click to expand)</summary>
        <SboxEditor sbox={sbox()} onChange={(next) => writeParams({ sbox: next })} />
      </details>

      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="key-expansion params"
      />
    </>
  );
};

// Padding-family + load/store block-size block.
//
// All of these steps share a single { blockSize: number } param. The raw
// JSON fallback rendered three lines for that one fact. One read-only
// scalar row matches the look of the AddRoundKey block.
//
// Why read-only:
//  - load-block hard-asserts blockSize === 16; anything else throws.
//  - pkcs7-pad / zero-pad / iso7816-4-pad will run with any 1..255 value,
//    but the App's Run handler caps input length based on the *active
//    padding scheme* (paddingLimits in stores/padding.ts), not this
//    param, so editing it here just produces a downstream length mismatch
//    at load-block.
// Multi-block + non-AES block sizes will unlock genuine editability when
// the cipher modes (ECB/CBC/CTR/GCM) feature lands.
const BLOCK_SIZE_PARAM_TYPES = new Set([
  "generic.pkcs7-pad@1",
  "generic.pkcs7-unpad@1",
  "generic.zero-pad@1",
  "generic.zero-unpad@1",
  "generic.iso7816-4-pad@1",
  "generic.iso7816-4-unpad@1",
  "generic.load-block@1",
  "generic.store-block@1",
]);

const BlockSizeBlock = (props: BlockProps) => {
  const params = (): { blockSize?: number } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Block size</dt>
        <dd>{params().blockSize ?? "—"} bytes</dd>
      </div>
    </dl>
  );
};

// AddRoundKey block.
//
// One param, one string: { auxName: "roundKey.N" }. The raw-JSON fallback
// rendered this as three lines for one fact. Single read-only scalar row
// matches the look of the key-expansion scalars.
//
// No ApplyAllRow: each AddRoundKey step intentionally references a
// DIFFERENT round key (roundKey.0 … roundKey.Nr), and copying one step's
// auxName onto every match would silently XOR the same round key Nr+1
// times and produce wrong ciphertext.
const AddRoundKeyBlock = (props: BlockProps) => {
  const params = (): { auxName?: string } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Round key aux</dt>
        <dd>{params().auxName ?? "—"}</dd>
      </div>
    </dl>
  );
};

// Speck key-schedule block.
//
// All seven params are structural (cipher-defining constants or naming
// hooks); we render them read-only as a scalars dl. Mirrors the shape of
// KeyExpansionBlock's scalars row but without the embedded S-box / rcon
// editors — Speck has no S-box, and its "round constant" is just the
// loop counter `i` XOR'd into the schedule (no table to edit).
//
// No ApplyAllRow: there's only one key-schedule step in any Speck spec.
const SpeckKeyScheduleBlock = (props: BlockProps) => {
  const params = (): {
    keyAuxName?: string;
    outputPrefix?: string;
    rounds?: number;
    wordBits?: number;
    m?: number;
    alpha?: number;
    beta?: number;
    byteOrder?: string;
  } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Input aux</dt>
        <dd>{params().keyAuxName ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Output prefix</dt>
        <dd>{params().outputPrefix ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Rounds</dt>
        <dd>{params().rounds ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Word bits (n)</dt>
        <dd>{params().wordBits ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Key words (m)</dt>
        <dd>{params().m ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>α (ROR)</dt>
        <dd>{params().alpha ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>β (ROL)</dt>
        <dd>{params().beta ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Byte order</dt>
        <dd>{params().byteOrder ?? "—"}</dd>
      </div>
    </dl>
  );
};

// Speck round / round-inverse block.
//
// Five structural params shared by both forward and inverse steps. The
// `roundKeyAux` is the per-leaf knob that wires the round to its specific
// round-key word; pinning it visible makes the encrypt-vs-decrypt key
// ordering (`roundKey.0` first vs. `roundKey.21` first) inspectable when
// scrubbing through the trace.
//
// No ApplyAllRow: like AddRoundKey, each Speck round leaf intentionally
// references a DIFFERENT roundKey aux name. Copying one step's params
// onto every match would point every round at the same key.
const SpeckRoundBlock = (props: BlockProps) => {
  const params = (): {
    roundKeyAux?: string;
    alpha?: number;
    beta?: number;
    wordBits?: number;
    byteOrder?: string;
  } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Round key aux</dt>
        <dd>{params().roundKeyAux ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>α (ROR)</dt>
        <dd>{params().alpha ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>β (ROL)</dt>
        <dd>{params().beta ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Word bits (n)</dt>
        <dd>{params().wordBits ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Byte order</dt>
        <dd>{params().byteOrder ?? "—"}</dd>
      </div>
    </dl>
  );
};

// ─── Serpent step blocks ─────────────────────────────────────────────────

// Serpent key-expansion: three scalars (keyAuxName, outputPrefix,
// keyByteLength). All structural — editing them by hand breaks the spec.
// No S-box param to expose here (Serpent's S-boxes live on the per-round
// sub-bytes leaves, not on the schedule itself — unlike AES, which has
// the S-box on its schedule because the schedule consumes it for SubWord).
const SerpentKeyExpansionBlock = (props: BlockProps) => {
  const params = (): {
    keyAuxName?: string;
    outputPrefix?: string;
    keyByteLength?: number;
  } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Input aux</dt>
        <dd>{params().keyAuxName ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Output prefix</dt>
        <dd>{params().outputPrefix ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Key bytes</dt>
        <dd>{params().keyByteLength ?? "—"}</dd>
      </div>
    </dl>
  );
};

// Serpent bit-permutation: 128-entry table param. Editing the table by
// hand is impractical; we show the label (IP / FP) as a scalar and tuck
// the table behind a <details>. Display is a 16x8 grid of source-bit
// indices (matches the layout the constants file uses for line-by-line
// auditing). Read-only — this is a structural cipher constant.
const SerpentBitPermutationBlock = (props: BlockProps) => {
  const params = (): { table?: number[]; label?: string } => props.step.params as never;
  const table = (): readonly number[] => params().table ?? [];

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Permutation</dt>
          <dd>{params().label ?? "—"}</dd>
        </div>
      </dl>
      <details class="param-section param-collapsible">
        <summary class="param-section-label">
          Bit permutation table (128 entries — click to expand)
        </summary>
        <div class="serpent-bit-table">
          <For each={table()}>
            {(value, i) => (
              <span class="bit-table-cell" title={`output bit ${i()} ← input bit ${value}`}>
                {value}
              </span>
            )}
          </For>
        </div>
      </details>
    </>
  );
};

// Serpent add-round-key: one scalar (roundKeyAux). Same shape as AES
// AddRoundKeyBlock — no ApplyAllRow because each leaf intentionally
// points at a different round key.
const SerpentAddRoundKeyBlock = (props: BlockProps) => {
  const params = (): { roundKeyAux?: string } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Round key aux</dt>
        <dd>{params().roundKeyAux ?? "—"}</dd>
      </div>
    </dl>
  );
};

// Serpent SubBytes: 16-entry 4-bit S-box. Rendered as an editable 4x4
// grid (16 cells in row-major order, index 0 top-left). Each cell is a
// ByteCellInput; the user can experiment by swapping values, and the
// effect propagates through the spec store like any other param edit.
//
// sboxIndex (0..7) is shown read-only as context — telling the user
// "this is S-box 3 of the 8 Serpent S-boxes" so they can correlate
// with the cipher description.
const SerpentSubBytesBlock = (props: BlockProps) => {
  const params = (): { sbox?: number[]; sboxIndex?: number } => props.step.params as never;
  const sbox = (): readonly number[] => params().sbox ?? [];

  const writeSbox = (next: number[]) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      sbox: next,
    });
  };

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>S-box index</dt>
          <dd>S_{params().sboxIndex ?? "—"}</dd>
        </div>
      </dl>
      <div class="param-section">
        <div class="param-section-label">S-box (16 entries, 4-bit each)</div>
        <div class="serpent-sbox-grid">
          <For each={sbox()}>
            {(value, i) => (
              <div class="serpent-sbox-cell-wrap" title={`S[${i()}] = ${value}`}>
                <ByteCellInput
                  compact
                  value={value}
                  onCommit={(next) => {
                    // Clamp to 0..15 — anything outside that range isn't a
                    // valid 4-bit S-box entry. ByteCellInput will already
                    // refuse non-byte values; we tighten further here.
                    const clamped = Math.max(0, Math.min(15, next));
                    const out = [...sbox()];
                    out[i()] = clamped;
                    writeSbox(out);
                  }}
                />
              </div>
            )}
          </For>
        </div>
      </div>
    </>
  );
};

// Empty-params placeholder for steps whose entire computation is in code
// (the Serpent LT and inverse LT). Avoids the raw-JSON fallback rendering
// `{}` for an empty params object.
const NoParamsBlock = (props: { label: string }) => <div class="muted small">{props.label}</div>;

// ─── Slice 10 aux primitives ─────────────────────────────────────────────
//
// These three step types arrive on the canvas via palette drop with empty
// params, so unlike the structural read-only blocks above (KeyExpansion,
// SpeckKeySchedule, AddRoundKey), they MUST be editable in place —
// otherwise the user can't fill in the aux names and the step never runs.
//
// No ApplyAllRow on any of them: every aux-load/aux-xor/aux-copy leaf is
// expected to point at distinct aux keys by design (the whole point of the
// primitives is wiring DIFFERENT slots together). Copying one step's
// params onto every sibling would silently route all of them at the same
// slot and produce wrong output — same reasoning as AddRoundKeyBlock.

// Generic editable text-input row used by the aux-primitive blocks. Keeps
// the per-block bodies tight and the input styling consistent with the
// `.param-scalar-row` look of the read-only blocks above.
const AuxNameInput = (props: {
  value: string;
  placeholder: string;
  onCommit: (v: string) => void;
}) => {
  const [draft, setDraft] = createSignal(props.value);
  // Re-sync the local draft if the upstream value changes (e.g. another
  // tab edits the spec, or an Apply-to-all on a different step type lands).
  let lastUpstream = props.value;
  const syncedDraft = () => {
    if (props.value !== lastUpstream) {
      lastUpstream = props.value;
      setDraft(props.value);
    }
    return draft();
  };
  const commit = () => {
    const next = draft().trim();
    if (next !== props.value) props.onCommit(next);
    // Snap draft to the committed value (or upstream if commit was a no-op).
    setDraft(next || props.value);
  };
  return (
    <input
      type="text"
      class="aux-name-input"
      spellcheck={false}
      placeholder={props.placeholder}
      value={syncedDraft()}
      onInput={(e) => setDraft(e.currentTarget.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          commit();
          e.currentTarget.blur();
        } else if (e.key === "Escape") {
          setDraft(props.value);
          e.currentTarget.blur();
        }
      }}
    />
  );
};

// aux-load: { auxName: string, value: number[] }.
// Renders an editable text input for the destination aux key + a horizontal
// row of ByteCellInput byte cells for `value` (reuses the `.rcon-row`
// styling from KeyExpansionBlock). Append/remove buttons let the user
// grow/shrink the byte sequence — palette inserts start at length 0 and
// the user adds bytes one at a time.
const AuxLoadBlock = (props: { step: StepLeaf }) => {
  const params = (): { auxName?: string; value?: readonly number[] } => props.step.params as never;
  const auxName = () => params().auxName ?? "";
  const value = (): readonly number[] => params().value ?? [];

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Aux name (write)</dt>
          <dd>
            <AuxNameInput
              value={auxName()}
              placeholder="e.g. iv, counter, tweak"
              onCommit={(v) => writeParams({ auxName: v })}
            />
          </dd>
        </div>
      </dl>
      <div class="param-section">
        <div class="param-section-label">Value (bytes — {value().length})</div>
        <div class="rcon-row">
          <For each={value()}>
            {(byte, i) => (
              <ByteCellInput
                value={byte}
                onCommit={(next) => {
                  const out = [...value()];
                  out[i()] = next;
                  writeParams({ value: out });
                }}
              />
            )}
          </For>
        </div>
        <div class="aux-byte-controls">
          <button
            type="button"
            onClick={() => writeParams({ value: [...value(), 0] })}
            title="Append a zero byte to the value"
          >
            + byte
          </button>
          <button
            type="button"
            onClick={() => {
              const v = value();
              if (v.length > 0) writeParams({ value: v.slice(0, -1) });
            }}
            disabled={value().length === 0}
            title="Drop the last byte"
          >
            − byte
          </button>
        </div>
      </div>
    </>
  );
};

// aux-xor: { from: string, into: string }.
// Two editable aux-name inputs. The graceful-on-missing semantic is in the
// executor — leaving either field empty just produces an orphaned-read
// warning glyph in the graph view rather than throwing.
const AuxXorBlock = (props: { step: StepLeaf }) => {
  const params = (): { from?: string; into?: string } => props.step.params as never;

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>From (read)</dt>
        <dd>
          <AuxNameInput
            value={params().from ?? ""}
            placeholder="aux key to XOR IN"
            onCommit={(v) => writeParams({ from: v })}
          />
        </dd>
      </div>
      <div class="param-scalar-row">
        <dt>Into (read+write)</dt>
        <dd>
          <AuxNameInput
            value={params().into ?? ""}
            placeholder="aux key to accumulate into"
            onCommit={(v) => writeParams({ into: v })}
          />
        </dd>
      </div>
    </dl>
  );
};

// aux-copy: { from: string, to: string }. Mirror of AuxXorBlock with the
// destination key labelled `to` to match the executor's params.
const AuxCopyBlock = (props: { step: StepLeaf }) => {
  const params = (): { from?: string; to?: string } => props.step.params as never;

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>From (read)</dt>
        <dd>
          <AuxNameInput
            value={params().from ?? ""}
            placeholder="aux key to copy FROM"
            onCommit={(v) => writeParams({ from: v })}
          />
        </dd>
      </div>
      <div class="param-scalar-row">
        <dt>To (write)</dt>
        <dd>
          <AuxNameInput
            value={params().to ?? ""}
            placeholder="aux key to copy TO"
            onCommit={(v) => writeParams({ to: v })}
          />
        </dd>
      </div>
    </dl>
  );
};

// ─── Apply-to-all button ─────────────────────────────────────────────────

const ApplyAllRow = (props: {
  currentParams: Json;
  stepType: string;
  matchingCount: number;
  label: string;
}) => (
  <Show when={props.matchingCount > 1}>
    <div class="apply-all-row">
      <button
        type="button"
        title={`Copy this step's ${props.label} to all ${props.matchingCount} steps of type ${props.stepType}`}
        onClick={() => {
          // The update fn replaces every matching step's params with this
          // step's exact current params. That's stronger than just copying
          // one field, but for AES our generic step types have only one
          // meaningful field anyway.
          editAllStepsByType(props.stepType, () => props.currentParams);
        }}
      >
        Apply this {props.label} to all {props.matchingCount} matching steps
      </button>
    </div>
  </Show>
);
