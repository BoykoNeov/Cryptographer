/**
 * Port-wiring editor — dropdown surface (universal-port plan Phase 4d-bis).
 *
 * For the selected leaf, renders one `<select>` per INPUT PORT, listing every
 * scope-legal upstream source the port may bind to (from `legalSourcesForInput`)
 * plus a "— unwired —" choice. Changing a select calls `bindPortInSpec`, which
 * rewires the active spec and lets the App's debounced effect re-run the trace.
 *
 * This is the keyboard/accessibility-complete rewire surface AND — for body-head
 * leaves whose only legal source is a container seed `port(group,"in")` that the
 * canvas draws no handle for — the SOLE rewire path. The canvas click-to-arm
 * gesture (Slice E) is a faster equivalent layered on the same store boundary.
 *
 * **Per-port, not per-leaf.** A multi-input leaf (`xor@1` → `operand0`,
 * `operand1`, …) gets one select per operand: "which source feeds which input"
 * is the whole point. The input-port list comes from
 * `resolvePortMap(registration.shape.inputs, leaf.params)`, so dynamic-arity
 * primitives (operand count varies with `params.inputCount`) enumerate
 * correctly.
 *
 * **Honest current value.** A `<select>` whose `value` matches no `<option>`
 * silently shows option 0 — so a port whose CURRENT binding is no longer
 * scope-legal (source deleted, or a binding gone out of scope) would lie about
 * what's wired. When the current binding isn't in the legal set we add an
 * explicit "⚠ current (unresolvable): X.Y" option and select it, mirroring the
 * validator's `port-input-unresolvable`. Option values are plain array indices
 * into the per-port option list, so no delimiter can collide with an id/port.
 */

import { resolvePortMap } from "@/core/port-projection";
import { type LegalSource, legalSourcesForInput } from "@/core/port-sources";
import { findStep } from "@/core/spec-mutations";
import type { PortBinding } from "@/core/types";
import { INPUT_SOURCE_ID } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { registry } from "../stores/registry";
import { bindPortInSpec, useSpec } from "../stores/spec";

type Props = {
  /** The leaf whose input ports we offer to rewire. `null` ⇒ render nothing. */
  stepId: string | null;
};

/** One row in a port's dropdown: a human label + the binding it sets (null = clear). */
type WiringOption = {
  readonly label: string;
  readonly binding: PortBinding | null;
};

/** Human-readable label for a scope-legal source option. */
const sourceLabel = (s: LegalSource): string => {
  const base = s.node === INPUT_SOURCE_ID ? "cipher input" : `${s.node}.${s.port}`;
  return s.compat === "coerce" ? `${base}  ⚠ size mismatch (coerces)` : base;
};

const sameBinding = (a: PortBinding | null, b: PortBinding | undefined): boolean =>
  a !== null && b !== undefined && a.node === b.node && a.port === b.port;

export const PortWiringEditor = (props: Props) => {
  const spec = useSpec();

  /** The declared input-port names of the selected leaf (empty ⇒ nothing to wire). */
  const inputPorts = createMemo<string[]>(() => {
    const id = props.stepId;
    if (!id) return [];
    const leaf = findStep(spec(), id);
    if (!leaf) return [];
    const registration = registry.getRegistration(leaf.type);
    if (registration === undefined) return [];
    return [...resolvePortMap(registration.shape.inputs, leaf.params).keys()];
  });

  return (
    <Show when={inputPorts().length > 0}>
      <div class="port-wiring-editor">
        <h3 class="port-wiring-title">Input wiring</h3>
        <p class="port-wiring-hint muted small">
          Rewire each input port to any upstream source in the same scope. Cross-scope sources
          aren't offered — they'd fail at run time.
        </p>
        <For each={inputPorts()}>
          {(portName) => {
            // The leaf's CURRENT binding for this port (undefined = unwired).
            const current = createMemo<PortBinding | undefined>(() => {
              const id = props.stepId;
              if (!id) return undefined;
              return findStep(spec(), id)?.portInputs?.[portName];
            });
            // The full ordered option list. Recomputed when the spec changes
            // (a rebind refreshes both the legal set and the current value).
            const options = createMemo<WiringOption[]>(() => {
              const legal = legalSourcesForInput(spec(), registry, props.stepId ?? "", portName);
              const list: WiringOption[] = [{ label: "— unwired —", binding: null }];
              // Honesty option: a current binding no longer in the legal set
              // still shows what's actually wired, flagged unresolvable.
              const c = current();
              if (c !== undefined && !legal.some((s) => sameBinding(c, s))) {
                list.push({
                  label: `⚠ current (unresolvable): ${c.node}.${c.port}`,
                  binding: { node: c.node, port: c.port },
                });
              }
              for (const s of legal) {
                list.push({ label: sourceLabel(s), binding: { node: s.node, port: s.port } });
              }
              return list;
            });
            // The index of the option matching the current binding (0 = unwired).
            const selectedIndex = createMemo<number>(() => {
              const c = current();
              if (c === undefined) return 0;
              const i = options().findIndex((o) => sameBinding(o.binding, c));
              return i >= 0 ? i : 0;
            });

            return (
              <label class="port-wiring-row">
                <span class="port-wiring-port-name">{portName}</span>
                <select
                  class="port-wiring-select"
                  aria-label={`Rewire input port ${portName}`}
                  value={String(selectedIndex())}
                  onChange={(e) => {
                    const chosen = options()[Number(e.currentTarget.value)];
                    if (chosen) bindPortInSpec(props.stepId ?? "", portName, chosen.binding);
                  }}
                >
                  <For each={options()}>
                    {(opt, i) => <option value={String(i())}>{opt.label}</option>}
                  </For>
                </select>
              </label>
            );
          }}
        </For>
      </div>
    </Show>
  );
};
