/**
 * Phase 2a — run history store + spec-diff helpers.
 *
 * Tests cover three property classes:
 *   (1) ring-buffer behavior: ids monotonic, eviction at MAX_HISTORY+1.
 *   (2) delta computation: input byte diff, key byte diff, params-changed.
 *   (3) compareSpecs structural correctness: param-key enumeration, cipher
 *       swap marker, structural-change marker.
 *
 * Each test builds minimal CipherSpecs and Traces by hand so the property
 * is exercised independently of AES specifics. Universal — a future cipher
 * inherits the same guarantees.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { compareSpecs, updateStepParams } from "@/core/spec-mutations";
import type { CipherSpec, Json, State, Trace } from "@/core/types";
import {
  MAX_HISTORY,
  __resetHistoryForTests,
  clearHistory,
  pushSnapshot,
  toggleSnapshotHidden,
  useHistory,
} from "@/ui/stores/history";
import { beforeEach, describe, expect, it } from "vitest";

const emptyState = (): State => ({ shape: "bytes", bytes: new Uint8Array(0) });
const trivialTrace = (): Trace => ({
  frames: [],
  finalState: emptyState(),
  finalAux: new Map(),
});

const bytes = (...vals: number[]) => new Uint8Array(vals);

const baseInput = bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
const baseKey = bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

describe("run-history store", () => {
  beforeEach(() => {
    __resetHistoryForTests();
  });

  it("starts empty", () => {
    expect(useHistory()()).toEqual([]);
  });

  it("assigns monotonic ids starting at 1", () => {
    pushSnapshot({
      inputBytes: baseInput,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });
    pushSnapshot({
      inputBytes: bytes(...new Array(16).fill(1)),
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });

    const snaps = useHistory()();
    expect(snaps.map((s) => s.id)).toEqual([1, 2]);
  });

  it("first snapshot has null delta", () => {
    pushSnapshot({
      inputBytes: baseInput,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });
    expect(useHistory()()[0]?.delta).toBeNull();
  });

  it("computes input-byte deltas on the second snapshot", () => {
    pushSnapshot({
      inputBytes: baseInput,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });
    const newInput = new Uint8Array(baseInput);
    newInput[0] = 0x10;
    newInput[15] = 0xff;
    pushSnapshot({
      inputBytes: newInput,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });

    const snap2 = useHistory()()[1];
    expect(snap2?.delta?.inputChanged).toEqual([
      { index: 0, from: 0x00, to: 0x10 },
      { index: 15, from: 0x00, to: 0xff },
    ]);
    expect(snap2?.delta?.keyChanged).toEqual([]);
    expect(snap2?.delta?.paramsChanged).toEqual([]);
  });

  it("computes param-change deltas when the spec is edited between runs", () => {
    pushSnapshot({
      inputBytes: baseInput,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });
    const identitySbox = Array.from({ length: 256 }, (_, i) => i);
    const edited = updateStepParams(aes128Spec, "round.1.sub-bytes", {
      auxName: "(unused)",
      sbox: identitySbox,
    });
    pushSnapshot({
      inputBytes: baseInput,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: edited,
      trace: trivialTrace(),
    });

    const snap2 = useHistory()()[1];
    expect(snap2?.delta?.paramsChanged.length).toBeGreaterThan(0);
    expect(
      snap2?.delta?.paramsChanged.some(
        (c) => c.stepId === "round.1.sub-bytes" && c.paramName === "sbox",
      ),
    ).toBe(true);
  });

  it("dedups exact-duplicate consecutive pushes", () => {
    const args = {
      inputBytes: baseInput,
      keyBytes: baseKey,
      mode: "encrypt" as const,
      spec: aes128Spec,
      trace: trivialTrace(),
    };
    pushSnapshot(args);
    pushSnapshot(args); // identical → no-op
    pushSnapshot(args); // identical → no-op
    expect(useHistory()().length).toBe(1);
  });

  it("does NOT dedup when the input differs by one byte", () => {
    pushSnapshot({
      inputBytes: baseInput,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });
    const bumped = new Uint8Array(baseInput);
    bumped[0] = 1;
    pushSnapshot({
      inputBytes: bumped,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });
    expect(useHistory()().length).toBe(2);
  });

  it("evicts the oldest snapshot once length exceeds MAX_HISTORY", () => {
    // Push MAX_HISTORY + 1 distinct snapshots; expect length == MAX_HISTORY
    // and the first id to be (totalPushed - MAX_HISTORY + 1) = 2.
    for (let i = 0; i < MAX_HISTORY + 1; i++) {
      const input = new Uint8Array(baseInput);
      input[0] = i; // make each distinct
      pushSnapshot({
        inputBytes: input,
        keyBytes: baseKey,
        mode: "encrypt",
        spec: aes128Spec,
        trace: trivialTrace(),
      });
    }
    const snaps = useHistory()();
    expect(snaps.length).toBe(MAX_HISTORY);
    expect(snaps[0]?.id).toBe(2); // id 1 was evicted
    expect(snaps[snaps.length - 1]?.id).toBe(MAX_HISTORY + 1);
  });

  it("copies inputBytes so post-push mutation of the caller's buffer doesn't bleed in", () => {
    const live = new Uint8Array(baseInput);
    pushSnapshot({
      inputBytes: live,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });
    // Mutate the caller's array.
    live[0] = 0xff;
    // The stored snapshot must still see the value at push-time.
    expect(useHistory()()[0]?.inputBytes[0]).toBe(0x00);
  });

  it("toggleSnapshotHidden flips the per-snapshot view flag", () => {
    pushSnapshot({
      inputBytes: baseInput,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });
    const id = useHistory()()[0]?.id ?? -1;
    expect(useHistory()()[0]?.hidden).toBe(false);
    toggleSnapshotHidden(id);
    expect(useHistory()()[0]?.hidden).toBe(true);
    toggleSnapshotHidden(id);
    expect(useHistory()()[0]?.hidden).toBe(false);
  });

  it("clearHistory empties the buffer and resets the id counter", () => {
    pushSnapshot({
      inputBytes: baseInput,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });
    expect(useHistory()()[0]?.id).toBe(1);
    clearHistory();
    expect(useHistory()()).toEqual([]);
    pushSnapshot({
      inputBytes: baseInput,
      keyBytes: baseKey,
      mode: "encrypt",
      spec: aes128Spec,
      trace: trivialTrace(),
    });
    expect(useHistory()()[0]?.id).toBe(1);
  });
});

describe("compareSpecs", () => {
  it("returns empty array for reference-equal specs", () => {
    expect(compareSpecs(aes128Spec, aes128Spec)).toEqual([]);
  });

  it("returns empty array when two distinct spec objects have equal params", () => {
    // Re-applying the same params produces a different object reference but
    // semantically identical contents — compareSpecs should treat as equal.
    const target = "initial.add-round-key";
    const original = aes128Spec;
    const sameAgain = updateStepParams(aes128Spec, target, { auxName: "roundKey.0" });
    expect(compareSpecs(original, sameAgain)).toEqual([]);
  });

  it("identifies which top-level param key changed on which step", () => {
    const identitySbox = Array.from({ length: 256 }, (_, i) => i);
    const sub = aes128Spec;
    const edited = updateStepParams(sub, "round.1.sub-bytes", {
      auxName: "(unused)",
      sbox: identitySbox,
    });
    const diffs = compareSpecs(sub, edited);
    // The only step that changed is round.1.sub-bytes. Auxname value didn't
    // actually exist on the original — both keys may surface depending on
    // what the original params were. So we just assert at least the sbox
    // key surfaces under round.1.sub-bytes.
    expect(diffs.some((d) => d.stepId === "round.1.sub-bytes" && d.paramName === "sbox")).toBe(
      true,
    );
    // And only that step.
    expect(diffs.every((d) => d.stepId === "round.1.sub-bytes")).toBe(true);
  });

  it("emits a cipher-swapped marker when spec.id differs (e.g. encrypt ↔ decrypt)", () => {
    const diffs = compareSpecs(aes128Spec, aes128DecryptSpec);
    expect(diffs).toEqual([{ stepId: "*", paramName: "(cipher swapped)" }]);
  });

  it("emits a structure marker when a step's id mismatches at the same position", () => {
    // Hand-rolled minimal specs to trigger the structural-mismatch branch.
    const make = (firstId: string): CipherSpec => ({
      id: "test@1",
      name: "test",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [{ kind: "step", id: firstId, type: "test.noop@1", params: null as Json }],
    });
    const a = make("alpha");
    const b = make("beta");
    const diffs = compareSpecs(a, b);
    expect(diffs.some((d) => d.paramName === "(structure)")).toBe(true);
  });

  it("emits a length-mismatch marker when one spec has more steps than the other", () => {
    const longer: CipherSpec = {
      id: "test@1",
      name: "test",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "a", type: "test.noop@1", params: null as Json },
        { kind: "step", id: "b", type: "test.noop@1", params: null as Json },
      ],
    };
    const shorter: CipherSpec = { ...longer, steps: longer.steps.slice(0, 1) };
    const diffs = compareSpecs(shorter, longer);
    expect(diffs.some((d) => d.stepId === "*" && d.paramName === "(steps added/removed)")).toBe(
      true,
    );
  });
});
