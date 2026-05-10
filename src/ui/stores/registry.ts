/**
 * UI-side singleton step registry. Built once at module-load and shared
 * by every component that needs to look up an executor or step doc.
 *
 * The runtime intentionally takes a registry *parameter* (not this
 * singleton), so tests can build their own; this singleton is purely a
 * convenience for the UI layer where we want one consistent set of
 * registered step types and their docs.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";

export const registry = buildDefaultRegistry();
