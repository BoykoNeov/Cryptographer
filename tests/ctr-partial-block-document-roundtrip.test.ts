/**
 * `allowPartialFinalBlock` survives the document round-trip — the Save/Load and
 * URL-share pin for CTR's ragged tail (2026-07-20).
 *
 * ## Why this file exists
 *
 * The flag is an **additive optional** field on `IterateGroup`, which needs no
 * `schemaVersion` bump. But "additive to the TypeScript type" and "survives
 * persistence" are two different claims, and only the first is free: the
 * document layer validates through Zod, and **Zod strips keys the schema does
 * not declare**. So a spec field that is never added to `document-schema.ts`
 * round-trips to `undefined` — silently.
 *
 * For this particular field the silent failure is nasty. A shared CTR link
 * would reopen with the flag gone, the iterate would go back to demanding a
 * whole-block multiple, and the app would start rejecting exactly the partial
 * input the link was built to demonstrate — with no error, no warning, and no
 * visual tell that anything was lost. The user would conclude the feature
 * doesn't work.
 *
 * The same trap already bit `cipherConstants` (Slice A1) and is called out in
 * the schema's own comments beside `seedInput` / `chainInput` / `chainOutput`.
 * This file is the assertion those fields each deserve and this one now has.
 *
 * The new step type needs no equivalent pin: `StepLeafSchema.type` is a plain
 * `z.string()`, so `truncate-to-reference@1` is carried like any other. Asserted
 * below anyway, because "no enum today" is a fact worth re-checking cheaply.
 */

import { aesCore } from "@/ciphers/aes-core";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildCtrSpec } from "@/ciphers/modes/ctr";
import { CipherDocumentSchema } from "@/core/document-schema";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY = "000102030405060708090a0b0c0d0e0f";
const IV = "000102030405060708090a0b0c0d0e0f";
/** 5 bytes — shorter than one AES block, so the flag is load-bearing. */
const SHORT_PT = "a1b2c3d4e5";

/** Find the CTR iterate node in a spec tree. */
const findIterate = (nodes: readonly StepNode[]): StepNode | undefined => {
  for (const n of nodes) {
    if (n.kind === "iterate") return n;
    if (n.kind === "group") {
      const inner = findIterate(n.children);
      if (inner !== undefined) return inner;
    }
  }
  return undefined;
};

const allStepTypes = (nodes: readonly StepNode[]): string[] => {
  const out: string[] = [];
  for (const n of nodes) {
    if (n.kind === "step") out.push(n.type);
    else out.push(...allStepTypes(n.children));
  }
  return out;
};

/** Serialize → validate → parse back, exactly as save-to-file / URL-share does. */
const roundTrip = (spec: CipherSpec): CipherSpec => {
  const doc = { schemaVersion: 3 as const, algorithm: "aes-128" as const, spec };
  // JSON round-trip first: this is what a .cipher.json file / share hash is.
  const reparsed = JSON.parse(JSON.stringify(doc));
  const result = CipherDocumentSchema.safeParse(reparsed);
  if (!result.success) throw new Error(`document failed validation: ${result.error.message}`);
  // Through `unknown`: the schema types `cipherConstants` as
  // `Record<string, string>` (its serialized hex form) while `CipherSpec` types
  // it as `Record<string, Uint8Array>` — the production loader does the same
  // widening. Irrelevant here (no CTR spec carries cipher constants), but the
  // direct cast doesn't typecheck.
  return result.data.spec as unknown as CipherSpec;
};

const runCtr = (spec: CipherSpec, inputHex: string): string => {
  const aux = new Map<string, AuxValue>([
    ["key", bytesFromHex(KEY)],
    ["iv", bytesFromHex(IV)],
  ]);
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: aux,
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return hexFromBytes(trace.finalState.bytes);
};

describe("CTR ragged tail survives the document round-trip", () => {
  const core = aesCore("aes-128");

  it("the iterate carries allowPartialFinalBlock BEFORE the round-trip (fixture sanity)", () => {
    // If this ever fails the rest of the file is vacuous — it would be
    // asserting that a flag which was never set stayed unset.
    const it0 = findIterate(buildCtrSpec(core, "encrypt").steps);
    expect(it0?.kind).toBe("iterate");
    if (it0?.kind !== "iterate") throw new Error("unreachable");
    expect(it0.allowPartialFinalBlock).toBe(true);
  });

  it("allowPartialFinalBlock is NOT stripped by the schema (the silent-revert guard)", () => {
    const after = findIterate(roundTrip(buildCtrSpec(core, "encrypt")).steps);
    expect(after?.kind).toBe("iterate");
    if (after?.kind !== "iterate") throw new Error("unreachable");
    // Before this field was declared in `document-schema.ts`, this read
    // `undefined` — and nothing else in the suite noticed.
    expect(after.allowPartialFinalBlock).toBe(true);
  });

  it("a reloaded CTR spec still encrypts a message shorter than one block", () => {
    // The behavioural form of the assertion above, and the one that matches
    // what a user would actually do: open a shared link, type 5 bytes, Run.
    // With the flag stripped this throws "not a multiple of blockByteLength".
    const reloaded = roundTrip(buildCtrSpec(core, "encrypt"));
    const ct = runCtr(reloaded, SHORT_PT);
    expect(ct.length / 2).toBe(5);
    // And byte-identical to the pre-round-trip spec — the reload changed nothing.
    expect(ct).toBe(runCtr(buildCtrSpec(core, "encrypt"), SHORT_PT));
  });

  it("the reloaded spec round-trips the short message back to plaintext", () => {
    const enc = roundTrip(buildCtrSpec(core, "encrypt"));
    const dec = roundTrip(buildCtrSpec(core, "decrypt"));
    expect(runCtr(dec, runCtr(enc, SHORT_PT))).toBe(SHORT_PT);
  });

  it("the truncate-to-reference@1 leaf survives (step types are not enum-gated)", () => {
    // `StepLeafSchema.type` is a plain `z.string()`, so a new step type needs no
    // schema change. Cheap to re-check; if this ever fails, every new step type
    // has acquired a persistence obligation.
    const after = roundTrip(buildCtrSpec(core, "encrypt"));
    expect(allStepTypes(after.steps)).toContain("truncate-to-reference@1");
  });

  it("ECB's iterate does NOT gain the flag through the round-trip", () => {
    // The absent case: an undeclared-but-optional field must come back absent,
    // not defaulted to `false`-ish or `true`. ECB relies on the throw.
    const ecbLike = buildCtrSpec(core, "encrypt");
    const stripped: CipherSpec = {
      ...ecbLike,
      steps: ecbLike.steps.map((n) => {
        if (n.kind !== "iterate") return n;
        // OMIT the key rather than setting it to `undefined`:
        // `exactOptionalPropertyTypes` distinguishes the two, and "absent" is
        // the state a pre-CTR saved document would actually be in.
        const { allowPartialFinalBlock: _omitted, ...withoutFlag } = n;
        return withoutFlag;
      }),
    };
    const after = findIterate(roundTrip(stripped).steps);
    if (after?.kind !== "iterate") throw new Error("unreachable");
    expect(after.allowPartialFinalBlock).toBeUndefined();
  });
});
