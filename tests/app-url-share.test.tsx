// @vitest-environment jsdom

/**
 * Integration tests for Slice 7 of the 2D editor plan — URL hash share.
 *
 * Two pathways exercised end-to-end through the App:
 *
 *   1. **Share** — clicking [share…] encodes the current document and
 *      writes a `${origin}${path}#doc=…` URL to the clipboard. The
 *      include-session toggle controls the spec-only vs full-session
 *      variant the same way it does for Save.
 *
 *   2. **Boot decode** — when the App mounts with a `#doc=…` payload in
 *      `window.location.hash`, the URL's literal document wins over
 *      whatever localStorage hydrated the stores with at module import
 *      time. The hash is cleared from the address bar on success so a
 *      refresh doesn't re-apply (which would clobber subsequent edits).
 *
 * Test mechanics worth preserving:
 *
 *   • jsdom's `navigator.clipboard.writeText` isn't a function by default;
 *     we stub it explicitly per test and capture the URL it was called with.
 *
 *   • To set up the boot pathway, we encode a document with the same
 *     pipeline App uses, write it to `location.hash`, then `render(App)`.
 *     The boot decode is async (CompressionStream is stream-based), so
 *     `waitFor` polls for the spec-store snap.
 */

import { aes256Spec } from "@/ciphers/aes-256";
import { CURRENT_SCHEMA_VERSION, type CipherDocument } from "@/core/document";
import { App } from "@/ui/App";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests, useCipher } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests, useByteFormat } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests, getLayoutForSpec } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { buildShareHash, encodeDocumentToHash } from "@/ui/stores/url-share";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ─── Reset orchestration (same shape as file-save-load.test.tsx) ──────────

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

// ─── DOM query helpers ────────────────────────────────────────────────────

const findButton = (container: HTMLElement, text: string): HTMLButtonElement => {
  const buttons = Array.from(container.querySelectorAll("button"));
  const target = buttons.find((b) => b.textContent?.trim().toLowerCase().startsWith(text));
  if (!target) throw new Error(`button "${text}" not found`);
  return target as HTMLButtonElement;
};

const findIncludeSessionCheckbox = (container: HTMLElement): HTMLInputElement => {
  const label = container.querySelector(".include-session-toggle");
  if (!label) throw new Error("include-session-toggle not found");
  const cb = label.querySelector("input[type='checkbox']");
  if (!cb) throw new Error("include-session checkbox not found");
  return cb as HTMLInputElement;
};

// ─── Clipboard helpers ────────────────────────────────────────────────────
// jsdom doesn't provide navigator.clipboard by default. We Object.define it
// for the duration of the test and capture the URL it was called with.

type ClipboardCapture = {
  readonly calls: string[];
};

const installClipboardSpy = (): ClipboardCapture => {
  const capture: ClipboardCapture = { calls: [] };
  Object.defineProperty(navigator, "clipboard", {
    value: {
      writeText: vi.fn(async (text: string) => {
        capture.calls.push(text);
      }),
    },
    configurable: true,
  });
  return capture;
};

const uninstallClipboardSpy = (): void => {
  // navigator.clipboard is a read-only property in jsdom — direct
  // assignment throws. Re-define via Object.defineProperty (same path
  // install uses) with value `undefined`, so the next test's install
  // overwrites a known-clean slot.
  Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
};

// Pull an indexed element with a runtime check — biome forbids `!` on
// indexing under noUncheckedIndexedAccess. Throws with a useful test
// label so a regression points at the missing entry, not at undefined.
const at = <T,>(arr: readonly T[], i: number, label: string): T => {
  const v = arr[i];
  if (v === undefined) throw new Error(`expected ${label} at index ${i}`);
  return v;
};

const payloadOf = (url: string): string => {
  const [, payload] = url.split("#doc=");
  if (payload === undefined) throw new Error(`expected #doc= in ${url}`);
  return payload;
};

// ─── Tests ────────────────────────────────────────────────────────────────

describe("App — Share (Slice 7)", () => {
  let clipboard: ClipboardCapture;

  beforeEach(() => {
    resetAll();
    clipboard = installClipboardSpy();
    // Clear any prior #doc= hash from a previous test's boot pathway so
    // share tests don't accidentally trigger the boot decode.
    window.history.replaceState(null, "", window.location.pathname);
  });

  afterEach(() => {
    uninstallClipboardSpy();
    cleanup();
    resetAll();
  });

  it("renders the [share…] button next to save/load", () => {
    const { container } = render(() => <App />);
    expect(findButton(container, "share")).toBeTruthy();
  });

  it("clicking share copies a `#doc=…` URL to the clipboard", async () => {
    const { container } = render(() => <App />);
    fireEvent.click(findButton(container, "share"));

    await waitFor(() => {
      expect(clipboard.calls.length).toBe(1);
    });
    const url = at(clipboard.calls, 0, "first clipboard call");
    // The URL is `${origin}${pathname}#doc=…`. jsdom defaults to
    // about:blank so origin can be empty; just check the hash portion.
    expect(url).toContain("#doc=");
    const payload = payloadOf(url);
    // Payload is non-empty, base64url-ish.
    expect(payload.length).toBeGreaterThan(100);
    expect(payload).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("share with include-session ON produces a longer payload than spec-only", async () => {
    // Sanity check that the toggle actually affects what gets shared.
    const { container } = render(() => <App />);

    fireEvent.click(findButton(container, "share"));
    await waitFor(() => expect(clipboard.calls.length).toBe(1));
    const specOnlyUrl = at(clipboard.calls, 0, "spec-only clipboard call");

    fireEvent.click(findIncludeSessionCheckbox(container));
    fireEvent.click(findButton(container, "share"));
    await waitFor(() => expect(clipboard.calls.length).toBe(2));
    const sessionOnUrl = at(clipboard.calls, 1, "session-on clipboard call");

    const specOnlyPayload = payloadOf(specOnlyUrl);
    const sessionOnPayload = payloadOf(sessionOnUrl);
    // Session-on carries extra bytes (selectors + inputs + key + metadata),
    // so it MUST be strictly longer. If they're equal, the toggle wasn't
    // actually honored.
    expect(sessionOnPayload.length).toBeGreaterThan(specOnlyPayload.length);
  });

  it("share shows the inline success status after copying", async () => {
    const { container } = render(() => <App />);
    fireEvent.click(findButton(container, "share"));

    await waitFor(() => {
      const status = container.querySelector(".share-status-success");
      expect(status).not.toBeNull();
      expect(status?.textContent).toMatch(/link copied/);
    });
  });
});

describe("App — Boot decode (Slice 7)", () => {
  beforeEach(() => {
    resetAll();
    window.history.replaceState(null, "", window.location.pathname);
  });

  afterEach(() => {
    cleanup();
    resetAll();
    window.history.replaceState(null, "", window.location.pathname);
  });

  it("loads spec from the URL hash on mount and clears the hash", async () => {
    // Build an AES-256 spec-only document, encode it, and stash in the
    // hash BEFORE render. The boot onMount hook should pick it up and
    // call applyDocument(), snapping the spec store from its localStorage
    // default (aes-128) to the URL's aes-256.
    const doc: CipherDocument = {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      spec: aes256Spec,
    };
    const encoded = await encodeDocumentToHash(doc);
    window.history.replaceState(null, "", `${window.location.pathname}${buildShareHash(encoded)}`);
    expect(window.location.hash).toContain("#doc=");

    render(() => <App />);

    await waitFor(() => {
      expect(useSpec()().id).toBe("aes-256@1");
    });
    // Hash cleared so a refresh doesn't re-apply (which would clobber
    // any subsequent edits the user made since the initial load).
    expect(window.location.hash).toBe("");
  });

  it("applies the session sidecar — selectors + bytes — on boot", async () => {
    // Build a session-on AES-128 + ASCII byteFormat doc so we can verify
    // the boot path drives the same applyDocument boundary file-load uses.
    // The boot test for file-load already pins the byteFormat-before-
    // formatBytes ordering; this one verifies the URL-share path inherits it.
    const doc: CipherDocument = {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      spec: useSpec()(), // AES-128 default
      session: {
        mode: "encrypt",
        cipher: "aes-128",
        cipherMode: "single-block",
        padding: "none",
        byteFormat: "ascii",
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
    const encoded = await encodeDocumentToHash(doc);
    window.history.replaceState(null, "", `${window.location.pathname}${buildShareHash(encoded)}`);

    const { container } = render(() => <App />);

    await waitFor(() => {
      expect(useByteFormat()()).toBe("ascii");
    });
    // Spec id unchanged (same AES-128) but byteFormat snapped to ASCII.
    expect(useSpec()().id).toBe("aes-128@1");
    // Plaintext field renders the bytes through ASCII (would be hex if
    // the ordering bug from Slice 5 had regressed).
    const labels = Array.from(container.querySelectorAll("label"));
    const ptLabel = labels.find((l) => l.textContent?.trim().startsWith("plaintext"));
    const ptInput = ptLabel?.querySelector("input") as HTMLInputElement;
    expect(ptInput.value).toBe("appleappleapple!");
  });

  it("restores layout sidecar on boot", async () => {
    // The boot path goes through applyDocument, which routes through
    // setLayoutForSpec — the same boundary file-load uses. Test that
    // a pinned position survives the share → boot round-trip.
    const doc: CipherDocument = {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      spec: aes256Spec,
      layout: {
        positions: { "round.5": { x: 400, y: 80 } },
        collapsedGroups: ["round.7"],
        flowDirection: "ltr",
      },
    };
    const encoded = await encodeDocumentToHash(doc);
    window.history.replaceState(null, "", `${window.location.pathname}${buildShareHash(encoded)}`);

    render(() => <App />);

    await waitFor(() => {
      expect(useSpec()().id).toBe("aes-256@1");
    });
    const layout = getLayoutForSpec("aes-256@1");
    expect(layout).not.toBeNull();
    expect(layout?.positions["round.5"]).toEqual({ x: 400, y: 80 });
    expect(layout?.collapsedGroups).toEqual(["round.7"]);
  });

  it("keeps the hash and shows an error when the payload is malformed", async () => {
    // Garbled payload — base64url decode fails. Hash should stay so the
    // user can show it to a maintainer; an inline error appears.
    window.history.replaceState(null, "", `${window.location.pathname}#doc=!!!not-valid-base64!!!`);

    const { container } = render(() => <App />);

    await waitFor(() => {
      const err = container.querySelector(".error");
      expect(err).not.toBeNull();
      expect(err?.textContent).toContain("Could not load shared link");
    });
    // Hash is preserved on failure (for forensic value).
    expect(window.location.hash).toContain("#doc=");
  });

  it("noop boot when the hash is empty or doesn't carry the prefix", async () => {
    // Standard page load — no hash, or an unrelated `#section` anchor.
    // Boot should not touch the spec / not produce errors.
    window.history.replaceState(null, "", `${window.location.pathname}#some-section`);
    const cipherBefore = useCipher()();

    const { container } = render(() => <App />);

    // Wait one tick so any erroneous async decode would have run.
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    expect(useCipher()()).toBe(cipherBefore);
    expect(container.querySelector(".error")).toBeNull();
    // (Note: pre-2026-05-14 this also asserted `getTrace() === null` as a
    // side-channel signal that boot decode hadn't applied a doc. The
    // trace-coupling fix added an unconditional boot-time `run()` for the
    // no-hash branch, so the trace is now non-null after any App render.
    // The substantive signals — cipher unchanged + no error — still pin
    // the no-hash-decode-applied invariant.)
  });
});
