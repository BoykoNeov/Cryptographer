/**
 * Tests for `speck.publish-round-keys@1` — the meta-bearing aux-publish
 * tail of the decomposed Speck32/64 key schedule
 * (key-schedule-decomposition K2a, 2026-06-01).
 *
 * Pins the two structural deltas vs `aes.publish-round-keys@1` flagged
 * by the K2 advisor pass:
 *   1. Emits EXACTLY `rounds` keys (not `rounds + 1`) — Speck has no
 *      initial pre-round key.
 *   2. Per-port `byteLength` is ABSENT (polymorphic across Speck
 *      variants), not hardcoded 16. The Speck32/64 caller passes 2-byte
 *      round keys; future Speck64/128 would pass 4-byte keys without a
 *      step-type change.
 *
 * Coverage: identity passthrough; port-name iteration order matches
 * insertion order (frame-parity invariant); meta.auxWritePorts emits
 * `${outputPrefix}.${r}` for `r in [0, rounds)`; param validation;
 * port-contract function-form exercise at rounds = 2, 5, 22 (the
 * Speck32/64 production case).
 */

import type { Json, StepContext } from "@/core/types";
import {
  speckPublishRoundKeys,
  speckPublishRoundKeysMeta,
  speckPublishRoundKeysPortContract,
  speckRoundKeyPortName,
} from "@/steps/speck-publish-round-keys";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const makeInputs = (rounds: number, byteLength = 2): Map<string, Uint8Array> => {
  const inputs = new Map<string, Uint8Array>();
  for (let r = 0; r < rounds; r++) {
    const bytes = new Uint8Array(byteLength);
    // Distinct value per round-key for identity-passthrough verification.
    bytes[0] = r & 0xff;
    if (byteLength > 1) bytes[1] = (r ^ 0x55) & 0xff;
    inputs.set(speckRoundKeyPortName(r), bytes);
  }
  return inputs;
};

const ctx = (): StepContext => ({ stepId: "speck-publish-test", path: [], aux: new Map() });

// ─── Executor — identity passthrough + count contract ────────────────────

describe("speck.publish-round-keys@1 — executor", () => {
  it("emits exactly `rounds` output ports (key0..key{rounds-1}), NOT rounds+1", () => {
    // The single most important structural pin vs the AES analog.
    const rounds = 22; // Speck32/64 production case
    const outputs = speckPublishRoundKeys(makeInputs(rounds), {
      outputPrefix: "roundKey",
      rounds,
    } as unknown as Json, ctx());

    expect(outputs.size).toBe(rounds);
    expect([...outputs.keys()]).toEqual([
      "key0", "key1", "key2", "key3", "key4", "key5", "key6", "key7",
      "key8", "key9", "key10", "key11", "key12", "key13", "key14",
      "key15", "key16", "key17", "key18", "key19", "key20", "key21",
    ]);
  });

  it("identity passthrough: each output byte-equals its input", () => {
    const rounds = 5;
    const inputs = makeInputs(rounds);
    const outputs = speckPublishRoundKeys(inputs, {
      outputPrefix: "roundKey",
      rounds,
    } as unknown as Json, ctx());

    for (let r = 0; r < rounds; r++) {
      const name = speckRoundKeyPortName(r);
      expect(outputs.get(name)).toEqual(inputs.get(name));
    }
  });

  it("port-name iteration order matches insertion order (frame-parity invariant)", () => {
    // Map iteration is insertion-ordered in JS; the frame-parity test
    // suite pins this across the codebase. Our executor inserts in
    // ascending r order; the resulting outputs map must reflect that.
    const rounds = 3;
    const outputs = speckPublishRoundKeys(makeInputs(rounds), {
      outputPrefix: "roundKey",
      rounds,
    } as unknown as Json, ctx());
    expect([...outputs.keys()]).toEqual(["key0", "key1", "key2"]);
  });

  it("accepts polymorphic byteLength (Speck32/64 = 2 bytes; sanity for 4-byte too)", () => {
    // Speck32/64 round keys are 2 bytes; Speck64/128 would be 4. The
    // port shape declares no fixed byteLength, so both work without a
    // step-type change.
    const inputs2 = makeInputs(3, 2);
    const out2 = speckPublishRoundKeys(inputs2, {
      outputPrefix: "rk",
      rounds: 3,
    } as unknown as Json, ctx());
    expect((out2.get("key0") as Uint8Array).length).toBe(2);

    const inputs4 = makeInputs(3, 4);
    const out4 = speckPublishRoundKeys(inputs4, {
      outputPrefix: "rk",
      rounds: 3,
    } as unknown as Json, ctx());
    expect((out4.get("key0") as Uint8Array).length).toBe(4);
  });

  it("throws when an expected round-key input port is missing", () => {
    const inputs = makeInputs(3);
    inputs.delete("key1");
    expect(() =>
      speckPublishRoundKeys(inputs, {
        outputPrefix: "roundKey",
        rounds: 3,
      } as unknown as Json, ctx()),
    ).toThrow(/input port "key1" must carry a round-key word/);
  });
});

// ─── Param validation ────────────────────────────────────────────────────

describe("speck.publish-round-keys@1 — param validation", () => {
  it("throws when params is not an object", () => {
    expect(() =>
      speckPublishRoundKeys(new Map(), null as unknown as Json, ctx()),
    ).toThrow(/params must be an object/);
  });

  it("throws when outputPrefix is missing", () => {
    expect(() =>
      speckPublishRoundKeys(new Map(), { rounds: 22 } as unknown as Json, ctx()),
    ).toThrow(/outputPrefix.*string/);
  });

  it("throws when rounds is missing", () => {
    expect(() =>
      speckPublishRoundKeys(new Map(), { outputPrefix: "rk" } as unknown as Json, ctx()),
    ).toThrow(/rounds.*positive integer/);
  });

  it("throws when rounds is 0", () => {
    expect(() =>
      speckPublishRoundKeys(new Map(), {
        outputPrefix: "rk",
        rounds: 0,
      } as unknown as Json, ctx()),
    ).toThrow(/positive integer/);
  });

  it("throws when rounds is non-integer", () => {
    expect(() =>
      speckPublishRoundKeys(new Map(), {
        outputPrefix: "rk",
        rounds: 22.5,
      } as unknown as Json, ctx()),
    ).toThrow(/positive integer/);
  });
});

// ─── PortContract function-form exercise ─────────────────────────────────

describe("speck.publish-round-keys@1 — PortContract", () => {
  if (
    typeof speckPublishRoundKeysPortContract.inputs !== "function" ||
    typeof speckPublishRoundKeysPortContract.outputs !== "function"
  ) {
    throw new Error("speck.publish-round-keys port contract must be function-form on both sides");
  }
  const inFn = speckPublishRoundKeysPortContract.inputs;
  const outFn = speckPublishRoundKeysPortContract.outputs;

  it("resolves to 2 ports at rounds=2", () => {
    expect([...inFn({ outputPrefix: "rk", rounds: 2 }).keys()]).toEqual(["key0", "key1"]);
    expect([...outFn({ outputPrefix: "rk", rounds: 2 }).keys()]).toEqual(["key0", "key1"]);
  });

  it("resolves to 22 ports at rounds=22 (Speck32/64 production case)", () => {
    const ports = [...inFn({ outputPrefix: "rk", rounds: 22 }).keys()];
    expect(ports.length).toBe(22);
    expect(ports[0]).toBe("key0");
    expect(ports[21]).toBe("key21");
    expect(ports).not.toContain("key22"); // NOT rounds+1
  });

  it("port shapes carry layout=raw, byteLength ABSENT (polymorphic across Speck variants)", () => {
    const map = inFn({ outputPrefix: "rk", rounds: 3 });
    for (const [, shape] of map) {
      expect(shape.layout).toBe("raw");
      expect(shape.byteLength).toBeUndefined();
    }
  });
});

// ─── meta.auxWritePorts ──────────────────────────────────────────────────

describe("speck.publish-round-keys@1 — meta.auxWritePorts", () => {
  it("maps `key${r}` → `${outputPrefix}.${r}` for r in [0, rounds)", () => {
    const fn = speckPublishRoundKeysMeta.auxWritePorts;
    if (typeof fn !== "function") {
      throw new Error("auxWritePorts must be function-form");
    }
    const bindings = fn({ outputPrefix: "roundKey", rounds: 22 });
    expect(bindings.size).toBe(22);
    expect(bindings.get("key0")).toBe("roundKey.0");
    expect(bindings.get("key21")).toBe("roundKey.21");
    expect(bindings.has("key22")).toBe(false); // NOT rounds+1
  });

  it("respects outputPrefix variation (`rk` instead of `roundKey`)", () => {
    const fn = speckPublishRoundKeysMeta.auxWritePorts;
    if (typeof fn !== "function") throw new Error("auxWritePorts must be function-form");
    const bindings = fn({ outputPrefix: "rk", rounds: 3 });
    expect(bindings.get("key0")).toBe("rk.0");
    expect(bindings.get("key2")).toBe("rk.2");
  });
});
