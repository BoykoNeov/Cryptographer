/**
 * Cipher-constants editor panel (scaffolding-suppression plan, Slice A1).
 *
 * Published constants (SHA-256's round constants K and initial-hash values
 * H; AES's S-box / Rcon once B1 lands) live on `spec.cipherConstants` and
 * are materialized into aux by the runtime — no per-spec "loader" leaf. This
 * panel is the editable surface for them, rendered in the main column near
 * `<ParamEditor>` so it's reachable from every view (including graph, where
 * the linear-mode step tree is hidden).
 *
 * Two channels, per the A1 UX picks:
 *
 *   - **Edit**: each constant's bytes render as a collapsible grid of
 *     `<ByteCellInput>` cells (byte-format-aware, like every other byte
 *     editor). A commit routes through `editCipherConstant` → the
 *     debounced spec effect re-runs the cipher, so the edit propagates to
 *     EVERY consumer in lockstep (the single-source-of-truth property A1
 *     exists to create).
 *
 *   - **Forward cross-ref**: under each constant, an inline clickable list
 *     of the leaves that consume it (every `aux-load-bytes@1` whose
 *     `auxName` matches). Clicking selects that leaf (scrubs the trace +
 *     binds the editor). The complementary back-ref ("reads constant: K")
 *     lives on the leaf inspector in `ParamEditor`.
 *
 * Renders nothing when the active spec has no `cipherConstants` (every
 * cipher except SHA-256 in A1), so it's inert for AES/Speck/Serpent/DES.
 */

import type { StepNode } from "@/core/types";
import { For, Index, Show, createMemo } from "solid-js";
import { editCipherConstant, useSpec } from "../stores/spec";
import { setSelectedStepId } from "../stores/trace";
import { ByteCellInput } from "./ByteCellInput";

/**
 * Walk the spec tree and collect the ids of every `aux-load-bytes@1` leaf
 * whose `params.auxName` equals `name` — the constant's consumers. Descends
 * into every container kind (group / iterate / for-each-subgraph /
 * for-each-subgraph-with-history via `children`; feistel-round via
 * `tracks[*].children`). Order is spec-tree order, which reads naturally
 * (round.0.fetch-K before round.1.fetch-K, …).
 */
const collectConsumers = (nodes: readonly StepNode[], name: string): string[] => {
  const out: string[] = [];
  const visit = (ns: readonly StepNode[]): void => {
    for (const n of ns) {
      if (n.kind === "step") {
        if (n.type === "aux-load-bytes@1" && (n.params as { auxName?: string }).auxName === name) {
          out.push(n.id);
        }
      } else if (n.kind === "feistel-round") {
        for (const t of n.tracks) visit(t.children);
      } else {
        visit(n.children);
      }
    }
  };
  visit(nodes);
  return out;
};

export const ConstantsPanel = () => {
  const spec = useSpec();

  // The constant names, recomputed when the spec changes. `undefined` /
  // empty → the whole panel renders nothing (the common case for ciphers
  // that haven't moved their tables to cipherConstants yet).
  const names = createMemo<readonly string[]>(() => {
    const c = spec().cipherConstants;
    return c ? Object.keys(c) : [];
  });

  return (
    <Show when={names().length > 0}>
      <details class="constants-panel" id="cipher-constants-panel" open>
        <summary class="constants-panel-title">cipher constants</summary>
        <div class="constants-panel-hint muted small">
          Published constants materialized into aux before the cipher runs. Editing one re-runs the
          cipher and updates every consumer at once.
        </div>
        <For each={names()}>{(name) => <ConstantRow name={name} />}</For>
      </details>
    </Show>
  );
};

const ConstantRow = (props: { name: string }) => {
  const spec = useSpec();

  // The live bytes for this constant. Re-reads `spec()` so a commit (or a
  // byte-format toggle) re-renders the cells. Falls back to an empty array
  // if the name vanished (defensive — `names()` gates the parent For).
  const bytes = createMemo<readonly number[]>(() => {
    const buf = spec().cipherConstants?.[props.name];
    return buf ? Array.from(buf) : [];
  });

  const consumers = createMemo<readonly string[]>(() => collectConsumers(spec().steps, props.name));

  // Commit a single-cell edit: rebuild the constant's Uint8Array with byte
  // `i` replaced, then route through the store mutator.
  const commitByte = (i: number, next: number): void => {
    const out = Uint8Array.from(bytes());
    out[i] = next;
    editCipherConstant(props.name, out);
  };

  return (
    <div class="constant-row" data-constant-row={props.name}>
      <details class="param-section param-collapsible">
        <summary class="param-section-label">
          {props.name} — {bytes().length} bytes (click to expand)
        </summary>
        <div class="rcon-row">
          <Index each={bytes()}>
            {(byte, i) => <ByteCellInput value={byte()} onCommit={(next) => commitByte(i, next)} />}
          </Index>
        </div>
      </details>
      {/* Forward cross-ref — inline clickable consumer leaves. K's ~64
          fetch-K readers wrap rather than truncate (user pick). Clicking a
          consumer selects it (scrubs the trace + binds the leaf inspector,
          whose back-ref "reads constant: …" line closes the loop). */}
      <div class="constant-consumers muted small">
        <Show
          when={consumers().length > 0}
          fallback={<span>no consumers read aux["{props.name}"]</span>}
        >
          <span>consumed by ({consumers().length}): </span>
          <For each={consumers()}>
            {(id, i) => (
              <>
                <button
                  type="button"
                  class="constant-consumer-link"
                  onClick={() => setSelectedStepId(id)}
                  title={`Select ${id} (reads aux["${props.name}"])`}
                >
                  {id}
                </button>
                <Show when={i() < consumers().length - 1}>
                  <span>, </span>
                </Show>
              </>
            )}
          </For>
        </Show>
      </div>
    </div>
  );
};
