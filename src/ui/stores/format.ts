/**
 * Byte format store. One signal: which format every byte-rendering site
 * in the app uses (hex / decimal / ASCII). Persisted in localStorage so
 * the user's pick survives a reload — the toggle changes how their input
 * field looks, and resetting that on reload would be surprising.
 *
 * Read from anywhere via `useByteFormat()`; write via `setByteFormat`.
 * The App component owns the in-place text-rewrite on format change
 * (parse with old format → re-format with new), because the inputs live
 * there and the store has no business knowing about plaintext fields.
 */

import { ALL_BYTE_FORMATS, type ByteFormat } from "@/core/format";
import { createSignal } from "solid-js";

const STORAGE_KEY = "cryptographer.byteFormat";

const loadInitial = (): ByteFormat => {
  // localStorage is unavailable in some test environments (vitest's node
  // environment, SSR if we ever add it). Guard so import-time doesn't
  // throw — default to hex if read fails.
  try {
    if (typeof localStorage === "undefined") return "hex";
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw && (ALL_BYTE_FORMATS as readonly string[]).includes(raw)) {
      return raw as ByteFormat;
    }
  } catch {
    // Storage access denied (private mode, disabled cookies). Fall through.
  }
  return "hex";
};

const [byteFormat, setByteFormatSignal] = createSignal<ByteFormat>(loadInitial());

export const useByteFormat = () => byteFormat;

export const setByteFormat = (fmt: ByteFormat): void => {
  setByteFormatSignal(fmt);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, fmt);
    }
  } catch {
    // Persist failed; the in-memory signal still updated, so the session
    // works — just won't survive reload. Not worth surfacing to the user.
  }
};
