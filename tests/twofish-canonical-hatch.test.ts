// @vitest-environment jsdom
//
// The canonical 4-rail Twofish layout is gated behind a URL hatch (2026-07-12):
// OFF by default so Twofish rounds render the generic vertical stack (the
// "original" view), ON via `?twofish4rail=1`. These pin the flag semantics; the
// GraphView memos (`twofishRoundsById`, `twofishRoundNeverModes`) consult
// `isTwofishCanonicalEnabledForLayout`, so the default here is what decides
// whether a fresh page load shows the 4-rail cell or the generic stack.

import {
  __setTwofishCanonicalEnabledForTest,
  isTwofishCanonicalEnabled,
  isTwofishCanonicalEnabledForLayout,
} from "@/ui/stores/twofish-canonical-hatch";
import { afterEach, describe, expect, it } from "vitest";

const setSearch = (search: string): void => {
  window.history.replaceState({}, "", `/${search}`);
};

describe("twofish canonical-layout hatch", () => {
  afterEach(() => {
    __setTwofishCanonicalEnabledForTest(null);
    setSearch("");
  });

  it("is OFF by default (no query param → generic layout)", () => {
    setSearch("");
    expect(isTwofishCanonicalEnabled()).toBe(false);
    expect(isTwofishCanonicalEnabledForLayout()).toBe(false);
  });

  it("turns ON with ?twofish4rail=1", () => {
    setSearch("?twofish4rail=1");
    expect(isTwofishCanonicalEnabled()).toBe(true);
    expect(isTwofishCanonicalEnabledForLayout()).toBe(true);
  });

  it("stays OFF for any other value of the param", () => {
    setSearch("?twofish4rail=0");
    expect(isTwofishCanonicalEnabled()).toBe(false);
    setSearch("?twofish4rail=true");
    expect(isTwofishCanonicalEnabled()).toBe(false);
  });

  it("test override wins over the URL, and null restores URL parsing", () => {
    setSearch(""); // URL says OFF
    __setTwofishCanonicalEnabledForTest(true);
    expect(isTwofishCanonicalEnabledForLayout()).toBe(true);
    __setTwofishCanonicalEnabledForTest(false);
    expect(isTwofishCanonicalEnabledForLayout()).toBe(false);
    __setTwofishCanonicalEnabledForTest(null);
    expect(isTwofishCanonicalEnabledForLayout()).toBe(false); // back to URL (OFF)
  });
});
