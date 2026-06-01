/**
 * Toy fixture for the port-mode `iterate` `chainOutput` harvest —
 * universal-port plan Phase 2 Slice 2.11a (2026-06-01).
 *
 * The port-mode `iterate` already folds N blocks while carrying a
 * cross-iteration value (`chainInput` bootstraps it, `chainFeedback`
 * advances it) — that's the CBC chain. CBC's *result* is the
 * concatenated per-block `bodyOutput`, so the carried chain is never
 * read back out. SHA-256 multi-block is the dual: it folds blocks into a
 * running hash and the digest is the chain's FINAL value, not the
 * per-block stream. `chainOutput` publishes that final chain on a named
 * output port.
 *
 * This toy is a 3-block running SUM (mod 2^32), the simplest fold that
 * exercises the harvest:
 *
 *     constant-load "blocks" → [0,0,0,1, 0,0,0,2, 0,0,0,3]  (3 × BE32)
 *     constant-load "iv"     → [0,0,0,0]                    (acc = 0)
 *     iterate "fold" (blockByteLength=4)
 *         seedInput     ← blocks/output
 *         chainInput    ← iv/output
 *         body: add-mod-32 "acc-add" (inputCount=2)
 *             operand0 ← port(fold,"in")    (this block)
 *             operand1 ← port(fold,"chain") (running acc)
 *         chainFeedback ← acc-add/output
 *         bodyOutput    ← acc-add/output
 *         chainOutput   = "acc"
 *     outputFrom = port(fold,"acc")
 *
 * Hand-computed fold (acc starts at 0):
 *   iter0: acc = 1 + 0 = 1  → [0,0,0,1]
 *   iter1: acc = 2 + 1 = 3  → [0,0,0,3]
 *   iter2: acc = 3 + 3 = 6  → [0,0,0,6]
 *
 * So `chainOutput`("acc") = [0,0,0,6] (the digest analogue), while the
 * default `out` port = the concatenated per-block stream
 * [0,0,0,1, 0,0,0,3, 0,0,0,6]. The per-block frames (`acc-add:b{i}`)
 * pin that the chain genuinely threads, not just the final harvest.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import type { CipherDocument } from "@/core/document";
import { CipherDocumentSchema } from "@/core/document-schema";
import { runSpec } from "@/core/runtime";
import type { BytesState, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const emptyBytes = (): BytesState => ({ shape: "bytes", bytes: new Uint8Array() });

const buildFoldSpec = (): CipherSpec => ({
  id: "toy-iterate-chain-output",
  name: "Iterate chainOutput fold toy (Slice 2.11a)",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "step",
      id: "blocks",
      type: "constant-load@1",
      params: { bytes: [0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3] },
    },
    {
      kind: "step",
      id: "iv",
      type: "constant-load@1",
      params: { bytes: [0, 0, 0, 0] },
    },
    {
      kind: "iterate",
      id: "fold",
      label: "Running sum fold",
      blockByteLength: 4,
      seedInput: { node: "blocks", port: "output" },
      chainInput: { node: "iv", port: "output" },
      chainFeedback: { node: "acc-add", port: "output" },
      bodyOutput: { node: "acc-add", port: "output" },
      chainOutput: "acc",
      children: [
        {
          kind: "step",
          id: "acc-add",
          type: "add-mod-32@1",
          params: { inputCount: 2 },
          portInputs: {
            operand0: { node: "fold", port: "in" },
            operand1: { node: "fold", port: "chain" },
          },
        },
      ],
    },
  ],
  outputFrom: { node: "fold", port: "acc" },
});

describe("port-mode iterate chainOutput (Slice 2.11a) — fold harvest", () => {
  it("finalState (via outputFrom = fold/acc) is the FINAL carried chain, not the per-block stream", () => {
    const trace = runSpec(buildFoldSpec(), buildDefaultRegistry(), {
      initialState: emptyBytes(),
    });
    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") throw new Error("unreachable");
    // [0,0,0,6] = 6 = 1 + 2 + 3, the running sum after the last block.
    expect(Array.from(trace.finalState.bytes)).toEqual([0, 0, 0, 6]);
  });

  it("the chain genuinely threads — per-block sums are 1, 3, 6", () => {
    const trace = runSpec(buildFoldSpec(), buildDefaultRegistry(), {
      initialState: emptyBytes(),
    });
    const byId = new Map(trace.frames.map((f) => [f.stepId, f]));
    // One add-mod-32 frame per block, suffixed :b0/:b1/:b2.
    const expected: ReadonlyArray<readonly [string, readonly number[]]> = [
      ["acc-add:b0", [0, 0, 0, 1]],
      ["acc-add:b1", [0, 0, 0, 3]],
      ["acc-add:b2", [0, 0, 0, 6]],
    ];
    for (const [stepId, want] of expected) {
      const frame = byId.get(stepId);
      expect(frame, `${stepId} must be a visible frame`).toBeDefined();
      expect(Array.from(frame?.portOutputs?.get("output") ?? [])).toEqual(want);
    }
  });
});

describe("port-mode iterate chainOutput (Slice 2.11a) — guard", () => {
  it("throws when chainOutput is set without chainInput/chainFeedback (no chain to harvest)", () => {
    const spec: CipherSpec = {
      id: "toy-chain-output-no-chain",
      name: "chainOutput without a chain (Slice 2.11a)",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        {
          kind: "step",
          id: "blocks",
          type: "constant-load@1",
          params: { bytes: [0, 0, 0, 1, 0, 0, 0, 2] },
        },
        {
          kind: "iterate",
          id: "fold",
          blockByteLength: 4,
          seedInput: { node: "blocks", port: "output" },
          bodyOutput: { node: "passthrough", port: "output" },
          // chainOutput set, but NO chainInput/chainFeedback.
          chainOutput: "acc",
          children: [
            {
              kind: "step",
              id: "passthrough",
              type: "xor@1",
              params: { inputCount: 1 },
              portInputs: { operand0: { node: "fold", port: "in" } },
            },
          ],
        },
      ],
    };
    expect(() => runSpec(spec, buildDefaultRegistry(), { initialState: emptyBytes() })).toThrow(
      /chainOutput requires chainInput\/chainFeedback/,
    );
  });
});

describe("port-mode iterate chainOutput (Slice 2.11a) — document round-trip", () => {
  // `chainOutput` is declared explicitly in `document-schema.ts` (Zod
  // strips undeclared keys — the same gotcha `seedInput`/`cipherConstants`
  // hit). Pin that it survives encode → decode so a saved multi-block
  // SHA-256 doc doesn't reload with the digest-harvest port stripped.
  it("a chainOutput-bearing iterate round-trips through CipherDocumentSchema unchanged", () => {
    const original: CipherDocument = {
      schemaVersion: 3,
      algorithm: "sha-256",
      spec: buildFoldSpec(),
    };
    const reparsed = JSON.parse(JSON.stringify(original));
    const result = CipherDocumentSchema.safeParse(reparsed);
    if (!result.success) {
      throw new Error(`document failed to validate: ${JSON.stringify(result.error.issues)}`);
    }
    const decodedSpec = result.data.spec as unknown as CipherSpec;
    const fold = decodedSpec.steps.find((n) => n.id === "fold");
    if (fold === undefined || fold.kind !== "iterate") {
      throw new Error("fold node missing or wrong kind in decoded spec");
    }
    expect(fold.chainOutput).toBe("acc");
  });
});
