// @vitest-environment jsdom

/**
 * **Architectural-invariant enumeration test (Slice S1 of
 * docs/plans/sha-256-density-polish.md).** Walks every leaf type appearing
 * in any shipped cipher/hash spec and asserts that rendering a
 * `<ParamEditor>` for a leaf of that type does NOT produce the raw-JSON
 * fallback string.
 *
 * The principle this test locks in (from the polish plan's S1 pass/fail
 * gate): "the literal string 'no editor for step type' should never render
 * on a registered step type." Without this test, a new cipher or new
 * port-native primitive could silently regress the param-editor surface —
 * SHA-256 was exactly this regression for the universal-port plan's Phase
 * 2 (every `rotate-bits-right@1`, `xor@1`, `aux-load-bytes@1` leaf rendered
 * the JSON dump because no ParamEditor block existed for those types).
 *
 * When this test fails, the assertion message names the cipher/hash, the
 * step type, AND the leaf id so the fix path is obvious: add a `<Match>`
 * block in `ParamEditor.tsx` for that type, or extend an existing one.
 *
 * Scoping: we walk only step types appearing in SHIPPED specs (the cipher
 * + hash defaults table), NOT every registered type. The polish plan
 * scopes to "leaves a user actually sees"; a registered-but-unused type
 * (e.g. `feistel.toy-add-k@1`, used only as a future Feistel oracle) is
 * unreachable from the UI and doesn't need an editor today.
 *
 * **Mode scope.** `useSpec()` returns the active-mode spec; we never flip to
 * decrypt, so decrypt-only step types (`speck.round-inverse@1`, the unpad
 * variants of `pkcs7`/`zero-pad`/`iso7816-4`) aren't traversed here. All
 * have ParamEditor blocks today (covered by other tests + the cross-mode
 * mirror coverage); accepting encrypt-only scope keeps this test fast on
 * the cold-jsdom path. If a future regression drops a `Match` for an unpad
 * step, it'll surface via the manual decrypt-mode smoke, not here.
 */

import { CIPHER_IDS, HASH_IDS } from "@/core/document-schema";
import type { StepLeaf, StepNode } from "@/core/types";
import { ParamEditor } from "@/ui/components/ParamEditor";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetSpecForTests, setAsymmetric, setCipher, setHash, useSpec } from "@/ui/stores/spec";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const FALLBACK_RE = /no editor for step type/i;

const collectLeavesByType = (nodes: readonly StepNode[], out: Map<string, StepLeaf>): void => {
  for (const node of nodes) {
    if (node.kind === "step") {
      if (!out.has(node.type)) out.set(node.type, node);
    } else {
      collectLeavesByType(node.children, out);
    }
  }
};

describe("ParamEditor coverage — no raw-JSON fallback on shipped specs", () => {
  beforeEach(() => {
    __resetCipherForTests();
    __resetSpecForTests();
  });

  afterEach(() => {
    cleanup();
  });

  for (const cipherId of CIPHER_IDS) {
    it(`every leaf type in ${cipherId} renders a real editor (not the JSON fallback)`, () => {
      setCipher(cipherId);
      const leavesByType = new Map<string, StepLeaf>();
      collectLeavesByType(useSpec()().steps, leavesByType);

      for (const [type, leaf] of leavesByType) {
        const { queryByText, unmount } = render(() => <ParamEditor stepId={leaf.id} />);
        const fallback = queryByText(FALLBACK_RE);
        expect(
          fallback,
          `${cipherId}: step type "${type}" (leaf "${leaf.id}") renders the raw-JSON fallback — add a <Match> block in ParamEditor.tsx for this type`,
        ).toBeNull();
        unmount();
      }
    });
  }

  for (const hashId of HASH_IDS) {
    it(`every leaf type in ${hashId} renders a real editor (not the JSON fallback)`, () => {
      setHash(hashId);
      const leavesByType = new Map<string, StepLeaf>();
      collectLeavesByType(useSpec()().steps, leavesByType);

      for (const [type, leaf] of leavesByType) {
        const { queryByText, unmount } = render(() => <ParamEditor stepId={leaf.id} />);
        const fallback = queryByText(FALLBACK_RE);
        expect(
          fallback,
          `${hashId}: step type "${type}" (leaf "${leaf.id}") renders the raw-JSON fallback — add a <Match> block in ParamEditor.tsx for this type`,
        ).toBeNull();
        unmount();
      }
    });
  }

  // RSA is the lone asymmetric family — not in CIPHER_IDS/HASH_IDS, so the loops
  // above don't reach it. The five big-integer primitives (`mul@1` … `mod-
  // inverse@1`) deliberately keep the raw-JSON fallback in v1 (plan-deferred —
  // their params are read-only scalars), so a full RSA walk would (correctly)
  // trip the assertion. The Phase-2 publish tail, however, ships its OWN block
  // (RsaPublishKeyParamsBlock) — assert it specifically renders, not the
  // fallback, so the new component can't silently regress to a JSON dump.
  it("rsa.publish-key-params@1 renders its real block (public/private key split)", () => {
    setAsymmetric("rsa"); // store → kind:"asymmetric", active spec = rsaEncryptSpec
    const { queryByText, unmount } = render(() => <ParamEditor stepId="publish-key" />);
    expect(queryByText(FALLBACK_RE)).toBeNull();
    // The block's distinctive content — the public-key (n, e) / private-key
    // (n, d) split — proves RsaPublishKeyParamsBlock rendered, not a sibling.
    expect(queryByText(/Public key/)).not.toBeNull();
    expect(queryByText(/Private key/)).not.toBeNull();
    unmount();
  });
});
