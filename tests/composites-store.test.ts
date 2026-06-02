/**
 * Composites store ("my elements" library) — universal-port Phase 4f.
 *
 * Node-env CRUD + validation. localStorage is absent here, so the store runs
 * in-memory (persist no-ops) — the persistence round-trip is the same
 * read/write pattern proven by `stores/layout.ts` and is exercised live by the
 * Slice E Playwright smoke (save → reload → still there). The module-scope
 * signal is shared across cases, so each test deletes what it created.
 */

import type { StepGroup } from "@/core/types";
import {
  type CompositeDefinition,
  deleteComposite,
  getComposite,
  listComposites,
  renameComposite,
  saveComposite,
} from "@/ui/stores/composites";
import { afterEach, describe, expect, it, vi } from "vitest";

/** A minimal saved template (as `captureCompositeFromGroup` would produce). */
const template = (name: string): StepGroup => ({
  kind: "group",
  id: "round.1",
  label: name, // capture sets label = the user's chosen name
  defaultCollapsed: true,
  bodyOutput: { node: "round.1.x", port: "output" },
  children: [{ kind: "step", id: "round.1.x", type: "permute@1", params: {} }],
});

const created: string[] = [];
const track = (def: CompositeDefinition): CompositeDefinition => {
  created.push(def.id);
  return def;
};

afterEach(() => {
  for (const id of created.splice(0)) deleteComposite(id);
  vi.restoreAllMocks();
});

describe("saveComposite / listComposites / getComposite", () => {
  it("saves a template under a fresh id, surfacing the label as the name", () => {
    const def = track(saveComposite(template("AES Round")));
    expect(def.name).toBe("AES Round");
    expect(def.group.label).toBe("AES Round");
    expect(typeof def.createdAt).toBe("number");

    expect(getComposite(def.id)).toEqual(def);
    expect(listComposites().some((c) => c.id === def.id)).toBe(true);
  });

  it("rejects an empty or non-group template", () => {
    const empty: StepGroup = { kind: "group", id: "g", label: "G", children: [] };
    expect(() => saveComposite(empty)).toThrow(/non-empty group/);
    // @ts-expect-error — deliberately wrong kind to prove the runtime guard.
    expect(() => saveComposite({ kind: "step", id: "x", type: "t", params: {} })).toThrow();
  });

  it("orders the list oldest-first by createdAt", () => {
    const now = vi.spyOn(Date, "now");
    now.mockReturnValue(1000);
    const first = track(saveComposite(template("First")));
    now.mockReturnValue(2000);
    const second = track(saveComposite(template("Second")));

    const ours = listComposites().filter((c) => c.id === first.id || c.id === second.id);
    expect(ours.map((c) => c.name)).toEqual(["First", "Second"]);
  });
});

describe("deleteComposite / renameComposite", () => {
  it("deletes a composite (and no-ops on an unknown id)", () => {
    const def = saveComposite(template("Doomed"));
    deleteComposite(def.id);
    expect(getComposite(def.id)).toBeUndefined();
    expect(() => deleteComposite("composite.nope")).not.toThrow();
  });

  it("renames a composite, updating both name and the template label", () => {
    const def = track(saveComposite(template("Old Name")));
    renameComposite(def.id, "New Name");
    const after = getComposite(def.id);
    expect(after?.name).toBe("New Name");
    expect(after?.group.label).toBe("New Name");
  });
});
