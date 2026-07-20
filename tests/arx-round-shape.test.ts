/**
 * The shared **ARX double-round envelope** (`src/core/arx-round-shape.ts`).
 *
 * `chacha-shape.ts`'s own 43 tests already exercise every line of this module
 * end-to-end — but they exercise it through exactly ONE caller, which cannot
 * distinguish "extracted a reusable envelope" from "moved ChaCha's code into a
 * file with a generic-sounding name". These tests check the two properties that
 * the extraction actually claims, and that a second ARX cipher will depend on:
 *
 * 1. `anchorBits` is a real parameter, not decoration — the envelope must
 *    DECLINE ChaCha's own rounds when told to anchor on Salsa's `<<< 18`.
 * 2. The per-cipher walk is a real seam — a caller's own matcher is what
 *    produces the descriptors, and the envelope's partition gate judges it
 *    without knowing what it matched.
 *
 * Written before Salsa20 exists on purpose: if the seam is fake, that is much
 * cheaper to learn now than after a cipher has been built on top of it.
 */

import { chacha20EncryptSpec } from "@/ciphers/chacha20";
import {
  ARX_OPS_PER_QUARTER_ROUND,
  ARX_QUARTER_ROUNDS_PER_DOUBLE_ROUND,
  analyzeArxDoubleRound,
  rotateBits,
} from "@/core/arx-round-shape";
import { analyzeChaChaDoubleRound } from "@/core/chacha-shape";
import type { CipherSpec, StepGroup, StepLeaf, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

/** Every group in a spec, depth-first — the double rounds live inside the iterate. */
const allGroups = (spec: CipherSpec): StepGroup[] => {
  const out: StepGroup[] = [];
  const walk = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "group") {
        out.push(n);
        walk(n.children);
      } else if (n.kind === "iterate") {
        walk(n.children);
      }
    }
  };
  walk(spec.steps);
  return out;
};

const chachaDoubleRounds = (): StepGroup[] =>
  allGroups(chacha20EncryptSpec).filter((g) => analyzeChaChaDoubleRound(g) !== null);

describe("analyzeArxDoubleRound — the envelope shared by every ARX cipher", () => {
  it("declines ChaCha's rounds when anchored on Salsa's rotation constant", () => {
    // The single most important property of the extraction. ChaCha ends each
    // quarter round on `<<< 7`; Salsa ends on `<<< 18`. If `anchorBits` were
    // decoration — if the envelope still looked for 7 internally — this would
    // find eight anchors and match. It must find zero and return null.
    const rounds = chachaDoubleRounds();
    expect(rounds.length).toBeGreaterThan(0);
    for (const group of rounds) {
      expect(
        analyzeArxDoubleRound(group, {
          anchorBits: 18,
          matchQuarterRound: () => {
            throw new Error("the walk must never run: there are no `<<< 18` anchors here");
          },
        }),
      ).toBeNull();
    }
  });

  it("runs the caller's own walk, once per anchor, and returns what it built", () => {
    // A deliberately non-ChaCha matcher: it claims the twelve leaves reachable
    // from its anchor by ChaCha's known member list, but describes them with a
    // shape of its own. The envelope must hand back those descriptors untouched
    // — it has no opinion about what a quarter round contains.
    const group = chachaDoubleRounds()[0] as StepGroup;
    const reference = analyzeChaChaDoubleRound(group);
    expect(reference).not.toBeNull();
    const membersByAnchor = new Map(
      (reference?.quarterRounds ?? []).map((qr) => [qr.id, qr.memberIds] as const),
    );

    let walks = 0;
    const shape = analyzeArxDoubleRound(group, {
      anchorBits: 7,
      matchQuarterRound: (anchor: StepLeaf) => {
        walks += 1;
        const memberIds = membersByAnchor.get(anchor.id);
        if (!memberIds) return null;
        return {
          id: anchor.id,
          memberIds,
          ops: memberIds.map((nodeId) => ({ nodeId })),
          // A field the envelope has never heard of, to prove `Q` rides through.
          myOwnFact: `anchored on ${anchor.id}`,
        };
      },
    });

    expect(walks).toBe(ARX_QUARTER_ROUNDS_PER_DOUBLE_ROUND);
    expect(shape?.quarterRounds).toHaveLength(ARX_QUARTER_ROUNDS_PER_DOUBLE_ROUND);
    expect(shape?.quarterRounds[0]?.myOwnFact).toContain("anchored on");
    // Structural facts the envelope itself derived, not the walk.
    expect(shape?.roundId).toBe(group.id);
    expect(shape?.concatId).toBe(group.bodyOutput?.node);
  });

  it("applies the partition gate to whatever the walk returns", () => {
    // The walk here under-claims: it reports only half of each quarter round's
    // leaves. Every individual match "succeeds", so only the envelope's gate can
    // catch it — which is exactly the protection a new cipher's walk inherits
    // for free.
    const group = chachaDoubleRounds()[0] as StepGroup;
    const reference = analyzeChaChaDoubleRound(group);
    const membersByAnchor = new Map(
      (reference?.quarterRounds ?? []).map((qr) => [qr.id, qr.memberIds] as const),
    );

    const shape = analyzeArxDoubleRound(group, {
      anchorBits: 7,
      matchQuarterRound: (anchor: StepLeaf) => {
        const memberIds = membersByAnchor.get(anchor.id)?.slice(0, 6);
        if (!memberIds) return null;
        return { id: anchor.id, memberIds, ops: memberIds.map((nodeId) => ({ nodeId })) };
      },
    });
    expect(shape).toBeNull();
  });

  it("agrees with ChaCha's adapter on the anchors it finds", () => {
    // Ties the generic constants to the real spec: eight anchors of twelve ops
    // is not a number this module invented, it is what the shipped cipher has.
    for (const group of chachaDoubleRounds()) {
      const anchors = group.children.filter(
        (c): c is StepLeaf => c.kind === "step" && rotateBits(c) === 7,
      );
      expect(anchors).toHaveLength(ARX_QUARTER_ROUNDS_PER_DOUBLE_ROUND);
      for (const qr of analyzeChaChaDoubleRound(group)?.quarterRounds ?? []) {
        expect(qr.memberIds).toHaveLength(ARX_OPS_PER_QUARTER_ROUND);
      }
    }
  });
});
