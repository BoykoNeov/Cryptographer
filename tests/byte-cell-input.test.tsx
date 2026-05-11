// @vitest-environment jsdom

/**
 * Component test for ByteCellInput. Verifies the trickiest piece of Phase
 * 3 wiring at the cell level: the input must re-render its draft when the
 * upstream byte value OR the global byte format changes. Forgetting either
 * leaves stale text on screen after a format toggle.
 *
 * Other behavior covered: format-aware parsing on commit, invalid input
 * snaps back to the upstream value, the maxLength shrinks/grows with the
 * format (hex=2, decimal=3, ASCII=4).
 */

import { ByteCellInput } from "@/ui/components/ByteCellInput";
import { __resetByteFormatForTests, setByteFormat } from "@/ui/stores/format";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

describe("ByteCellInput — format-aware rendering", () => {
  beforeEach(() => {
    __resetByteFormatForTests();
  });
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("renders the value as 2 hex chars by default", () => {
    const { container } = render(() => <ByteCellInput value={0xff} onCommit={() => {}} />);
    const input = container.querySelector("input.byte-cell") as HTMLInputElement;
    expect(input.value).toBe("ff");
    expect(input.maxLength).toBe(2);
  });

  it("re-renders the value when the global format changes mid-session", () => {
    // The lastFmt sync logic inside ByteCellInput is the load-bearing
    // piece — without it, switching format would leave each cell stuck
    // in its old format until next focus.
    const { container } = render(() => <ByteCellInput value={0xff} onCommit={() => {}} />);
    const input = container.querySelector("input.byte-cell") as HTMLInputElement;
    expect(input.value).toBe("ff");

    setByteFormat("decimal");
    expect(input.value).toBe("255");
    expect(input.maxLength).toBe(3);

    setByteFormat("ascii");
    // 0xff is non-printable → \xff escape (4 chars).
    expect(input.value).toBe("\\xff");
    expect(input.maxLength).toBe(4);
  });

  it("commits a parsed value on blur (decimal format)", () => {
    setByteFormat("decimal");
    const onCommit = vi.fn();
    const { container } = render(() => <ByteCellInput value={0} onCommit={onCommit} />);
    const input = container.querySelector("input.byte-cell") as HTMLInputElement;

    fireEvent.input(input, { target: { value: "200" } });
    fireEvent.blur(input);

    expect(onCommit).toHaveBeenCalledWith(200);
  });

  it("snaps back to the upstream value when input is invalid for the current format", () => {
    setByteFormat("decimal");
    const onCommit = vi.fn();
    const { container } = render(() => <ByteCellInput value={42} onCommit={onCommit} />);
    const input = container.querySelector("input.byte-cell") as HTMLInputElement;

    // 256 > 255: invalid in decimal mode.
    fireEvent.input(input, { target: { value: "256" } });
    fireEvent.blur(input);

    expect(onCommit).not.toHaveBeenCalled();
    expect(input.value).toBe("42");
  });

  it("re-renders when the upstream value prop changes (e.g. spec reset)", () => {
    // The original HexCellInput already had this behavior; preserve it.
    const [getValue, setValue] = createSignal(0x10);
    const { container } = render(() => <ByteCellInput value={getValue()} onCommit={() => {}} />);
    const input = container.querySelector("input.byte-cell") as HTMLInputElement;
    expect(input.value).toBe("10");

    setValue(0xab);
    expect(input.value).toBe("ab");
  });
});
