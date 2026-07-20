/**
 * ChaCha20 (RFC 8439) known-answer tests — the app's first stream cipher.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHY ROUND-TRIP IS RANKED LAST HERE.
 *
 * ChaCha20's message meets only an XOR, and XOR is its own inverse, so the
 * encrypt and decrypt specs are structurally IDENTICAL. That makes
 * "encrypt then decrypt returns the plaintext" a tautology: it holds by
 * construction even if the quarter-round is entirely wrong, the rotation
 * constants are backwards, the state layout is scrambled, and the counter
 * never advances. It is the same trap OFB documented, and it is why the
 * verification budget below goes almost entirely elsewhere.
 *
 * The tests are ordered by how much each actually discriminates:
 *
 *   1. §2.1.1 — the quarter round in isolation. Diagnoses the ARX core.
 *   2. §2.3.2 — the 64-byte block-function keystream. The primary anchor:
 *      one assertion pins the rotation constants, the state layout, the
 *      little-endian serialization AND the counter start simultaneously.
 *   3. §2.4.2 — full multi-block encryption of the RFC's own message.
 *   4. `node:crypto` across the length range — the partial-final-block path,
 *      which no published vector exercises at every boundary.
 *   5. Counter-advance contrast — block n's keystream must equal the block
 *      function at counter (initial + n). Catches a counter that fails to
 *      advance, which a single-block KAT structurally cannot see.
 *   6. Round-trip — last, and documented as proving nothing on its own.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ORACLE. `node:crypto`'s `chacha20` takes a 16-byte IV laid out as a
 * 4-byte little-endian counter followed by the 12-byte nonce — the same
 * layout this app's `aux["iv"]` uses, and the reason that layout was chosen.
 * It was verified against RFC 8439 §2.4.2 before any of these tests were
 * written, per the project's "external oracle before tests" rule.
 *
 * Note the counter in every RFC vector below starts at **1**, not 0. An
 * initial-counter off-by-one is the classic ChaCha implementation bug: it
 * produces perfectly plausible ciphertext that decrypts nowhere else.
 */

import { createCipheriv } from "node:crypto";
import { CHACHA20_BLOCK_BYTES, chacha20DecryptSpec, chacha20EncryptSpec } from "@/ciphers/chacha20";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const fromHex = (s: string): Uint8Array =>
  new Uint8Array((s.replace(/\s+/g, "").match(/../g) ?? []).map((h) => Number.parseInt(h, 16)));

const toHex = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

/** The RFC's running example key: bytes 00..1f. */
const RFC_KEY = new Uint8Array(32).map((_, i) => i);

/**
 * Pack the app's 16-byte IV blob: a 32-bit little-endian counter followed by
 * the 12-byte nonce. Deliberately hand-rolled here rather than imported, so a
 * change to the builder's layout has to be reflected in a test that fails.
 */
const packIv = (counter: number, nonceHex: string): Uint8Array => {
  const iv = new Uint8Array(16);
  new DataView(iv.buffer).setUint32(0, counter, true /* little-endian */);
  iv.set(fromHex(nonceHex), 4);
  return iv;
};

const run = (spec: CipherSpec, input: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: input },
    initialAux: new Map<string, AuxValue>([
      ["key", key],
      ["iv", iv],
    ]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");
  return trace.finalState.bytes;
};

/**
 * The keystream for a given (key, nonce, counter), read out of the cipher by
 * encrypting zeros: `0 ⊕ keystream === keystream`.
 */
const keystream = (key: Uint8Array, iv: Uint8Array, length: number): Uint8Array =>
  run(chacha20EncryptSpec, new Uint8Array(length), key, iv);

/** The external oracle. */
const nodeChaCha20 = (input: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array => {
  const c = createCipheriv("chacha20", key, iv);
  return new Uint8Array(Buffer.concat([c.update(input), c.final()]));
};

// ─── 1. RFC 8439 §2.1.1 — the quarter round in isolation ──────────────────

describe("RFC 8439 §2.1.1 — the quarter round", () => {
  it("maps the RFC's four test words to the RFC's four expected words", () => {
    // a = 0x11111111, b = 0x01020304, c = 0x9b8d6f43, d = 0x01234567
    //   ⇒ a = 0xea2a92f4, b = 0xcb1cf8ce, c = 0x4581472e, d = 0x5881c4bb
    //
    // Built here as a standalone spec from the SAME three step types and the
    // SAME param shapes the cipher's builder emits, so this fails if the ARX
    // primitives don't compose into a correct quarter round — one level below
    // where the block-function KAT would point.
    const words = ["11111111", "01020304", "9b8d6f43", "01234567"];
    const seeds = words.map((hex, i) => ({
      kind: "step" as const,
      id: `w${i}`,
      type: "constant-load@1",
      params: { bytes: Array.from(fromHex(hex)) },
    }));

    // Live bindings, rebound as each operation lands — the builder's own idiom.
    const live = [0, 1, 2, 3].map((i) => ({ node: `w${i}`, port: "output" }));
    const ops: [string, string, number, number, number][] = [
      // [id, kind, target, other, bits] — bits ignored for add/xor
      ["add-ab-1", "add", 0, 1, 0],
      ["xor-da-1", "xor", 3, 0, 0],
      ["rot-d-16", "rot", 3, 0, 16],
      ["add-cd-1", "add", 2, 3, 0],
      ["xor-bc-1", "xor", 1, 2, 0],
      ["rot-b-12", "rot", 1, 0, 12],
      ["add-ab-2", "add", 0, 1, 0],
      ["xor-da-2", "xor", 3, 0, 0],
      ["rot-d-8", "rot", 3, 0, 8],
      ["add-cd-2", "add", 2, 3, 0],
      ["xor-bc-2", "xor", 1, 2, 0],
      ["rot-b-7", "rot", 1, 0, 7],
    ];

    const steps = ops.map(([id, kind, target, other, bits]) => {
      const node =
        kind === "rot"
          ? {
              kind: "step" as const,
              id,
              type: "rotate-bits-left@1",
              params: { bits, wordBits: 32 },
              portInputs: { input: live[target] as { node: string; port: string } },
            }
          : {
              kind: "step" as const,
              id,
              type: kind === "add" ? "add-mod-32@1" : "xor@1",
              params: { inputCount: 2 },
              portInputs: {
                operand0: live[target] as { node: string; port: string },
                operand1: live[other] as { node: string; port: string },
              },
            };
      live[target] = { node: id, port: "output" };
      return node;
    });

    const spec: CipherSpec = {
      id: "qr-probe@1",
      name: "quarter round probe",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        ...seeds,
        ...steps,
        {
          kind: "step",
          id: "join",
          type: "concat@1",
          params: { inputCount: 4 },
          portInputs: Object.fromEntries(live.map((b, i) => [`input${i}`, b])),
        },
      ],
      outputFrom: { node: "join", port: "output" },
    };

    const out = run(spec, new Uint8Array(0), new Uint8Array(0), new Uint8Array(16));
    expect(toHex(out)).toBe("ea2a92f4" + "cb1cf8ce" + "4581472e" + "5881c4bb");
  });
});

// ─── 2. RFC 8439 §2.3.2 — the block function ──────────────────────────────

describe("RFC 8439 §2.3.2 — the block function", () => {
  it("produces the RFC's 64-byte keystream for its key, nonce and counter 1", () => {
    // The single most load-bearing assertion in this file. A wrong rotation
    // constant, a transposed state word, a big-endian serialization or a
    // counter starting at 0 each break it.
    const iv = packIv(1, "000000090000004a00000000");
    expect(toHex(keystream(RFC_KEY, iv, CHACHA20_BLOCK_BYTES))).toBe(
      "10f1e7e4d13b5915500fdd1fa32071c4" +
        "c7d1f4c733c068030422aa9ac3d46c4e" +
        "d2826446079faa0914c2d705d98b02a2" +
        "b5129cd1de164eb9cbd083e8a2503c4e",
    );
  });

  it("changes the whole keystream when the counter changes by one", () => {
    // Only one of sixteen state words differs between these two calls. If the
    // twenty rounds did their job, the outputs share no structure.
    const nonce = "000000090000004a00000000";
    const a = keystream(RFC_KEY, packIv(1, nonce), CHACHA20_BLOCK_BYTES);
    const b = keystream(RFC_KEY, packIv(2, nonce), CHACHA20_BLOCK_BYTES);
    expect(toHex(a)).not.toBe(toHex(b));
    // Roughly half the bits should differ; assert loosely to stay a smoke
    // test of diffusion rather than a brittle statistic.
    let differing = 0;
    for (let i = 0; i < a.length; i++)
      differing += ((a[i] as number) ^ (b[i] as number)) === 0 ? 0 : 1;
    expect(differing).toBeGreaterThan(60);
  });
});

// ─── 3. RFC 8439 §2.4.2 — full encryption ─────────────────────────────────

describe("RFC 8439 §2.4.2 — encrypting the RFC's own message", () => {
  const PLAINTEXT = new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  );
  const EXPECTED_CT =
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
    "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
    "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
    "5af90bbf74a35be6b40b8eedf2785e42874d";
  const IV = packIv(1, "000000000000004a00000000");

  it("encrypts to the published ciphertext", () => {
    expect(toHex(run(chacha20EncryptSpec, PLAINTEXT, RFC_KEY, IV))).toBe(EXPECTED_CT);
  });

  it("is 114 bytes in and 114 bytes out — no padding, and a short final block", () => {
    // 114 = one full 64-byte block plus a 50-byte remainder. A stream cipher
    // must emit exactly as many bytes as it consumed.
    const ct = run(chacha20EncryptSpec, PLAINTEXT, RFC_KEY, IV);
    expect(PLAINTEXT.length).toBe(114);
    expect(ct.length).toBe(114);
  });

  it("decrypts the published ciphertext back to the message", () => {
    expect(toHex(run(chacha20DecryptSpec, fromHex(EXPECTED_CT), RFC_KEY, IV))).toBe(
      toHex(PLAINTEXT),
    );
  });
});

// ─── 4. node:crypto across the length range ───────────────────────────────

describe("matches node:crypto's chacha20 across the block boundary", () => {
  const IV = packIv(7, "0f1e2d3c4b5a69788796a5b4");
  const KEY = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);

  // 1 byte is the case that only became representable with partial final
  // blocks; 63/65 and 127/129 straddle the two block boundaries.
  it.each([1, 2, 63, 64, 65, 127, 128, 129, 200])("agrees on a %i-byte message", (length) => {
    const pt = new Uint8Array(length).map((_, i) => (i * 31 + 11) & 0xff);
    expect(toHex(run(chacha20EncryptSpec, pt, KEY, IV))).toBe(toHex(nodeChaCha20(pt, KEY, IV)));
  });

  it("agrees on the keystream itself, not just on one message", () => {
    // Encrypting zeros reads the keystream out directly, so this compares the
    // generator rather than a particular XOR.
    expect(toHex(keystream(KEY, IV, 256))).toBe(toHex(nodeChaCha20(new Uint8Array(256), KEY, IV)));
  });
});

// ─── 5. The counter actually advances ─────────────────────────────────────

describe("the block counter advances by exactly one per block", () => {
  const NONCE = "000000090000004a00000000";

  it("block n of a long message equals the block function at counter (start + n)", () => {
    // The assertion a single-block KAT structurally cannot make. If the
    // counter never advanced, every 64-byte slice below would be identical;
    // if it advanced by the wrong amount, the slices would be misaligned.
    const long = keystream(RFC_KEY, packIv(1, NONCE), CHACHA20_BLOCK_BYTES * 4);
    for (let n = 0; n < 4; n++) {
      const standalone = keystream(RFC_KEY, packIv(1 + n, NONCE), CHACHA20_BLOCK_BYTES);
      const slice = long.subarray(n * CHACHA20_BLOCK_BYTES, (n + 1) * CHACHA20_BLOCK_BYTES);
      expect(toHex(slice)).toBe(toHex(standalone));
    }
  });

  it("consecutive blocks of one message are not the same bytes", () => {
    // The failure mode the previous test would also catch, stated directly:
    // a counter stuck at its initial value repeats the keystream, and XORing
    // two such ciphertext blocks would cancel it and leak both plaintexts.
    const ks = keystream(RFC_KEY, packIv(1, NONCE), CHACHA20_BLOCK_BYTES * 2);
    expect(toHex(ks.subarray(0, 64))).not.toBe(toHex(ks.subarray(64)));
  });
});

// ─── 6. Round-trip — ranked last, and deliberately so ─────────────────────

describe("round-trip (a tautology — see the file header)", () => {
  it("decrypt undoes encrypt", () => {
    // This passes even if every constant in the cipher is wrong, because
    // encrypt and decrypt are the SAME spec and XOR is self-inverse. It is
    // here to catch a wiring change that breaks the symmetry, and for nothing
    // else. The assertions above are what establish correctness.
    const pt = new Uint8Array(150).map((_, i) => (i * 13) & 0xff);
    const iv = packIv(1, "000000000000004a00000000");
    const ct = run(chacha20EncryptSpec, pt, RFC_KEY, iv);
    expect(toHex(run(chacha20DecryptSpec, ct, RFC_KEY, iv))).toBe(toHex(pt));
  });

  it("encrypt and decrypt are the same WIRING — only the prose differs", () => {
    // Pins the claim the test above rests on. Strip `narrationOverride` (the
    // one thing `direction` is allowed to change) and the two specs must be
    // byte-identical trees: same steps, same params, same port bindings.
    //
    // If these ever diverge, the round-trip test above silently stops being a
    // tautology and starts carrying real weight — and this test is what tells
    // you that happened.
    const stripProse = (node: unknown): unknown => {
      if (Array.isArray(node)) return node.map(stripProse);
      if (node === null || typeof node !== "object") return node;
      return Object.fromEntries(
        Object.entries(node as Record<string, unknown>)
          .filter(([k]) => k !== "narrationOverride")
          .map(([k, v]) => [k, stripProse(v)]),
      );
    };

    expect(JSON.stringify(stripProse(chacha20EncryptSpec.steps))).toBe(
      JSON.stringify(stripProse(chacha20DecryptSpec.steps)),
    );
  });
});
