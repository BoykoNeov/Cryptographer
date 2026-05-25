// @vitest-environment jsdom

/**
 * Integration tests for Slice 5 of the 2D editor plan — File save/load UI.
 *
 * What's tested (and why each case):
 *
 *   1. Save with `include session` OFF produces a spec-only document that
 *      parses back to the same spec. The "share a custom AES variant"
 *      minimum — no plaintext / key leak, no selector capture.
 *
 *   2. Save with `include session` ON captures all six selector values
 *      plus inputBytes + keyBytes, AND reloading the same file from a
 *      blank slate restores everything: spec equality, every selector,
 *      and the trace re-runs to the same final state. This is the
 *      headline round-trip the slice unblocks.
 *
 *   3. Loading malformed JSON shows a friendly inline error and leaves
 *      the spec untouched — no crash, no half-applied state.
 *
 *   4. Loading a document with a future schemaVersion (≥3) shows the "this file
 *      is from a newer app version" message (forward-compat anchor).
 *
 *   5. Loading a v1 document restores the byteFormat BEFORE formatting
 *      the input/key bytes — i.e. the bytes are rendered in the doc's
 *      format, not the format that was active before load.
 *
 * Test mechanics:
 *
 *   • Save is driven by clicking the [save] button + a spy on
 *     URL.createObjectURL that captures the resulting Blob. The Blob's
 *     text is what gets asserted (this is also what would land on disk).
 *
 *   • Load is driven by constructing a `File`, injecting it into the
 *     hidden file input's `files` property via `Object.defineProperty`
 *     (FileList is read-only in jsdom; this is the standard workaround),
 *     and firing a `change` event. The handler reads `file.text()` which
 *     is a promise, so each load test awaits a `waitFor` assertion.
 */

import { parseDocument } from "@/core/document";
import { App } from "@/ui/App";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests, useCipher } from "@/ui/stores/cipher";
import { __resetCipherModeForTests, useCipherMode } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests, useByteFormat } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import {
  __resetLayoutsForTests,
  getLayoutForSpec,
  setNodePosition,
  toggleCollapse,
} from "@/ui/stores/layout";
import { __resetPaddingForTests, usePaddingScheme } from "@/ui/stores/padding";
import { __resetSpecForTests, useMode, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, getTrace, useTraceVersion } from "@/ui/stores/trace";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ─── DOM query helpers ────────────────────────────────────────────────────

const findButton = (container: HTMLElement, text: string): HTMLButtonElement => {
  const buttons = Array.from(container.querySelectorAll("button"));
  const target = buttons.find((b) => b.textContent?.trim().toLowerCase().startsWith(text));
  if (!target) throw new Error(`button "${text}" not found`);
  return target as HTMLButtonElement;
};

const findFileInput = (container: HTMLElement): HTMLInputElement => {
  const el = container.querySelector('input[type="file"]') as HTMLInputElement | null;
  if (!el) throw new Error("file input not found");
  return el;
};

const findIncludeSessionCheckbox = (container: HTMLElement): HTMLInputElement => {
  const label = container.querySelector(".include-session-toggle");
  if (!label) throw new Error("include-session-toggle not found");
  const cb = label.querySelector("input[type='checkbox']");
  if (!cb) throw new Error("include-session checkbox not found");
  return cb as HTMLInputElement;
};

// ─── Save-side helpers ───────────────────────────────────────────────────

type SaveCapture = {
  /** Every Blob the App has handed to URL.createObjectURL since install,
   * in chronological order. Most tests want the latest; the byte-stability
   * test wants both. Using an array sidesteps TS's control-flow narrowing
   * (`saveCapture.blob = null; saveCapture.blob.text()` narrows to `never`). */
  readonly blobs: Blob[];
  /** Original implementation, restored in afterEach. */
  originalCreate: typeof URL.createObjectURL;
  originalRevoke: typeof URL.revokeObjectURL;
};

const installSaveSpy = (): SaveCapture => {
  const capture: SaveCapture = {
    blobs: [],
    originalCreate: URL.createObjectURL,
    originalRevoke: URL.revokeObjectURL,
  };
  URL.createObjectURL = vi.fn((b: Blob | MediaSource): string => {
    if (b instanceof Blob) capture.blobs.push(b);
    return "blob:test-stub";
  }) as typeof URL.createObjectURL;
  URL.revokeObjectURL = vi.fn() as typeof URL.revokeObjectURL;
  return capture;
};

const uninstallSaveSpy = (capture: SaveCapture): void => {
  URL.createObjectURL = capture.originalCreate;
  URL.revokeObjectURL = capture.originalRevoke;
};

const latestBlob = (c: SaveCapture): Blob => {
  const b = c.blobs.at(-1);
  if (!b) throw new Error("save did not produce a Blob");
  return b;
};

// ─── Load-side helpers ───────────────────────────────────────────────────

/**
 * Drive a Load by injecting a `File` into the hidden file input and firing
 * the `change` event. The App handler reads `file.text()` asynchronously,
 * so callers must `await` for the post-load state to settle.
 *
 * jsdom's `FileList` is read-only; `Object.defineProperty` is the standard
 * workaround (this is what @testing-library does internally for similar
 * scenarios). We construct a real `File` object since `File.text()` works
 * in jsdom 22+.
 */
const driveLoad = (container: HTMLElement, text: string): void => {
  const file = new File([text], "test.cipher.json", { type: "application/json" });
  const input = findFileInput(container);
  Object.defineProperty(input, "files", {
    value: [file],
    configurable: true,
  });
  fireEvent.change(input);
};

// ─── Reset orchestration ─────────────────────────────────────────────────

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetHistoryForTests();
  __resetTraceForTests();
  __resetLayoutsForTests();
};

// ─── Tests ───────────────────────────────────────────────────────────────

describe("App — Save/Load (Slice 5)", () => {
  let saveCapture: SaveCapture;

  beforeEach(() => {
    resetAll();
    saveCapture = installSaveSpy();
  });

  afterEach(() => {
    uninstallSaveSpy(saveCapture);
    cleanup();
    resetAll();
  });

  it("renders the Save and Load buttons + the include-session checkbox", () => {
    const { container } = render(() => <App />);
    expect(findButton(container, "save")).toBeTruthy();
    expect(findButton(container, "load")).toBeTruthy();
    const cb = findIncludeSessionCheckbox(container);
    // Default off — protects the user's first impulse-save from leaking
    // plaintext bytes to disk.
    expect(cb.checked).toBe(false);
  });

  it("Save with include-session OFF produces a spec-only document", async () => {
    const { container } = render(() => <App />);
    fireEvent.click(findButton(container, "save"));

    const text = await latestBlob(saveCapture).text();
    const parsed = parseDocument(text);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    // Spec is captured.
    expect(parsed.doc.spec.id).toBe("aes-128@1");
    // No session sidecar — the user opted out.
    expect(parsed.doc.session).toBeUndefined();
    // No metadata either — spec-only saves are byte-stable so Slice 7
    // (URL hash share) can hash them deterministically. A stamped
    // createdAt would defeat that.
    expect(parsed.doc.metadata).toBeUndefined();
  });

  it("spec-only Save is byte-stable across repeated saves of the same spec", async () => {
    const { container } = render(() => <App />);

    fireEvent.click(findButton(container, "save"));
    fireEvent.click(findButton(container, "save"));
    expect(saveCapture.blobs.length).toBe(2);
    const firstBlob = saveCapture.blobs[0];
    const secondBlob = saveCapture.blobs[1];
    if (!firstBlob || !secondBlob) throw new Error("expected two captured Blobs");

    const firstText = await firstBlob.text();
    const secondText = await secondBlob.text();
    expect(firstText).toBe(secondText);
  });

  it("Save with include-session ON captures all selector values + bytes", async () => {
    const { container } = render(() => <App />);

    // Tick the checkbox.
    fireEvent.click(findIncludeSessionCheckbox(container));
    expect(findIncludeSessionCheckbox(container).checked).toBe(true);

    fireEvent.click(findButton(container, "save"));

    const text = await latestBlob(saveCapture).text();
    const parsed = parseDocument(text);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    const session = parsed.doc.session;
    expect(session).toBeDefined();
    if (!session) return;
    expect(session.mode).toBe("encrypt");
    expect(session.cipher).toBe("aes-128");
    expect(session.cipherMode).toBe("single-block");
    expect(session.padding).toBe("none");
    expect(session.byteFormat).toBe("hex");
    // Default FIPS-197 sequential bytes for AES-128 plaintext + key.
    expect(session.inputBytes).toEqual([
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
      0xff,
    ]);
    expect(session.keyBytes).toEqual([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
      0x0f,
    ]);
  });

  it("Save → Load round-trip restores spec, selectors, bytes, and trace", async () => {
    // Phase A — set up a non-default configuration, save it with session.
    const { container, unmount } = render(() => <App />);

    // Pick AES-192 + ASCII format so we have something distinct from defaults.
    const cipherSel = container.querySelector('select[title*="AES variant"]') as HTMLSelectElement;
    fireEvent.change(cipherSel, { target: { value: "aes-192" } });
    // Format toggle: ASCII.
    const asciiBtn = Array.from(container.querySelectorAll(".format-toggle button")).find(
      (b) => b.textContent?.trim() === "ASCII",
    ) as HTMLButtonElement;
    fireEvent.click(asciiBtn);

    // Run once so we have a trace to compare against later.
    fireEvent.click(findButton(container, "run"));
    const traceBeforeSave = getTrace();
    if (!traceBeforeSave) throw new Error("initial run did not produce a trace");
    const finalStateBefore = traceBeforeSave.finalState;

    // Tick include-session, save, capture the serialized text.
    fireEvent.click(findIncludeSessionCheckbox(container));
    fireEvent.click(findButton(container, "save"));
    const savedText = await latestBlob(saveCapture).text();

    // Phase B — fully reset stores + remount. Verify defaults are back.
    unmount();
    cleanup();
    resetAll();

    const { container: c2 } = render(() => <App />);
    expect(useCipher()()).toBe("aes-128");
    expect(useByteFormat()()).toBe("hex");

    // Phase C — load the saved file. State should snap back to AES-192 +
    // ASCII + identical trace.
    driveLoad(c2, savedText);

    await waitFor(() => {
      expect(useCipher()()).toBe("aes-192");
    });
    expect(useByteFormat()()).toBe("ascii");
    expect(useMode()()).toBe("encrypt");
    expect(useCipherMode()()).toBe("single-block");
    expect(usePaddingScheme()()).toBe("none");
    // Trace re-ran on load (the handler calls run() synchronously after
    // applying the document, so this should be deterministic).
    void useTraceVersion()(); // tick reactivity
    const traceAfterLoad = getTrace();
    if (!traceAfterLoad) throw new Error("load did not produce a trace");
    // Final state bytes match — same plaintext + key under same spec
    // produces the same ciphertext (FIPS-197 §A.2 / §C.2 territory).
    expect(traceAfterLoad.finalState.shape).toBe(finalStateBefore.shape);
    if (
      finalStateBefore.shape === "matrix4x4-bytes" &&
      traceAfterLoad.finalState.shape === "matrix4x4-bytes"
    ) {
      expect(Array.from(traceAfterLoad.finalState.bytes)).toEqual(
        Array.from(finalStateBefore.bytes),
      );
    }
  });

  it("Load with malformed JSON shows a friendly error and leaves spec untouched", async () => {
    const { container } = render(() => <App />);
    const specBefore = useSpec()();
    driveLoad(container, "this is not json {");

    await waitFor(() => {
      const err = container.querySelector(".error");
      expect(err).not.toBeNull();
      expect(err?.textContent).toContain("Could not load this file");
      expect(err?.textContent).toContain("invalid JSON");
    });
    // Spec is the same reference — load failed before any mutation.
    expect(useSpec()()).toBe(specBefore);
  });

  it("Load with a future schemaVersion (≥3) shows the version-mismatch error", async () => {
    const { container } = render(() => <App />);
    const specBefore = useSpec()();
    // Phase 4 of `docs/plans/des-feistel.md` bumped the current schema
    // from 1 to 2, so a "future" doc now needs to claim 3+ to trip the
    // forward-compat error. Bare doc; we don't care about its other
    // fields because the pre-check fires BEFORE the full Zod schema.
    driveLoad(container, JSON.stringify({ schemaVersion: 3, spec: {} }));

    await waitFor(() => {
      const err = container.querySelector(".error");
      expect(err).not.toBeNull();
      expect(err?.textContent).toContain("schemaVersion 3 is not supported");
    });
    expect(useSpec()()).toBe(specBefore);
  });

  // ─── Slice 6 — layout sidecar in Save/Load ──────────────────────────────
  // These three cases extend the Slice 5 envelope:
  //   • Spec-only Save with NO drag/collapse continues to omit the layout
  //     sidecar entirely → byte-stable (the existing repeat-save test
  //     above already pins this; this one makes the absence explicit).
  //   • Spec-only Save WITH a pinned position emits the layout sidecar.
  //   • Save → reset → Load restores the pinned positions + collapsed set
  //     into the layout store, keyed by the loaded spec's id.

  it("Save with no layout customization omits the layout sidecar", async () => {
    const { container } = render(() => <App />);
    fireEvent.click(findButton(container, "save"));

    const text = await latestBlob(saveCapture).text();
    const parsed = parseDocument(text);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    // No drag, no collapse → no `layout` key at all (this is what keeps
    // spec-only saves byte-stable for Slice 7's URL hash).
    expect(parsed.doc.layout).toBeUndefined();
  });

  it("Save after dragging a container includes the layout sidecar", async () => {
    const { container } = render(() => <App />);

    // Pin round.5 + collapse round.7 directly via the store. The drag
    // pathway has its own tests in graph-view-drag.test.tsx; we're
    // verifying the Save side here, not the drag side.
    const specId = useSpec()().id;
    setNodePosition(specId, "round.5", 400, 80);
    toggleCollapse(specId, "round.7", false);

    fireEvent.click(findButton(container, "save"));

    const text = await latestBlob(saveCapture).text();
    const parsed = parseDocument(text);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    expect(parsed.doc.layout).toBeDefined();
    expect(parsed.doc.layout?.positions["round.5"]).toEqual({ x: 400, y: 80 });
    expect(parsed.doc.layout?.collapsedGroups).toEqual(["round.7"]);
    expect(parsed.doc.layout?.flowDirection).toBe("ltr");
  });

  it("Save → Load round-trip restores layout into the per-spec store", async () => {
    const { container, unmount } = render(() => <App />);

    // Drag + collapse via the store directly (drag plumbing tested elsewhere).
    const specId = useSpec()().id;
    setNodePosition(specId, "round.5", 400, 80);
    toggleCollapse(specId, "round.7", false);

    fireEvent.click(findButton(container, "save"));
    const savedText = await latestBlob(saveCapture).text();

    // Full reset (including layouts) + remount.
    unmount();
    cleanup();
    resetAll();
    const { container: c2 } = render(() => <App />);

    // Pre-Load: no layout for this spec.
    expect(getLayoutForSpec(specId)).toBeNull();

    driveLoad(c2, savedText);

    await waitFor(() => {
      const layout = getLayoutForSpec(specId);
      expect(layout).not.toBeNull();
    });
    const layout = getLayoutForSpec(specId);
    expect(layout?.positions["round.5"]).toEqual({ x: 400, y: 80 });
    expect(layout?.collapsedGroups).toEqual(["round.7"]);
  });

  it("Load applies byteFormat BEFORE formatting inputBytes/keyBytes", async () => {
    // The advisor flagged this ordering: if we format the bytes using
    // the OLD byteFormat (because setByteFormat hasn't fired yet), the
    // restored fields show the wrong representation. We verify the
    // ordering by saving in ASCII, then loading from a hex-default
    // session and checking that the input field renders in ASCII.
    const { container } = render(() => <App />);

    // Build a session that pins byteFormat=ascii + the FIPS-197 plaintext.
    const doc = {
      schemaVersion: 2,
      spec: useSpec()(), // current AES-128 spec
      session: {
        mode: "encrypt",
        cipher: "aes-128",
        cipherMode: "single-block",
        padding: "none",
        byteFormat: "ascii",
        // Bytes for "appleappleapple!" — 16 ASCII chars, valid AES block.
        inputBytes: [
          0x61, 0x70, 0x70, 0x6c, 0x65, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x61, 0x70, 0x70, 0x6c, 0x65,
          0x21,
        ],
        keyBytes: [
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
          0x0f,
        ],
      },
    };
    driveLoad(container, JSON.stringify(doc));

    await waitFor(() => {
      expect(useByteFormat()()).toBe("ascii");
    });
    // Plaintext field shows the ASCII-rendered bytes (not the hex bytes
    // that would have been formatted under the OLD byteFormat).
    const labels = Array.from(container.querySelectorAll("label"));
    const ptLabel = labels.find((l) => l.textContent?.trim().startsWith("plaintext"));
    expect(ptLabel).toBeDefined();
    const ptInput = ptLabel?.querySelector("input") as HTMLInputElement;
    expect(ptInput.value).toBe("appleappleapple!");
  });
});
