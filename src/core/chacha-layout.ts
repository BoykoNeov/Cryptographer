/**
 * Canonical ChaCha20 DOUBLE-ROUND layout — now a thin alias over the shared ARX
 * layout in `arx-round-layout.ts`.
 *
 * The placement never knew anything ChaCha-specific: it reads only `splitId`,
 * `concatId` and `ops[].nodeId`, and its 3×4-block / two-tier arrangement is
 * equally the shape of Salsa20's double round. So when the ARX family was
 * extracted (plan `shiny-wandering-conway.md`, phase S1) the whole module moved
 * verbatim and this file survives purely so `GraphView` and the existing tests
 * keep importing the name they always did.
 *
 * New ARX ciphers should import `arxDoubleRoundPlacement` directly.
 */

export {
  arxDoubleRoundPlacement as chachaDoubleRoundPlacement,
  type ArxChildOffset as ChaChaChildOffset,
  type ArxPlacement as ChaChaPlacement,
  type ArxPlacementOpts as ChaChaPlacementOpts,
} from "./arx-round-layout";
