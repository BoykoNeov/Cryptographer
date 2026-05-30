import type { State } from "../types";
import { cloneBytes } from "./bytes";

// Post-Slice-5.1 the only State shape is `bytes` (the `matrix4x4-bytes`
// variant was retired with the test-only matrix AES primitives). Kept as a
// thin alias over `cloneBytes` so the many call sites that clone a State
// don't churn; it collapses entirely once the State union is removed in 5.3.
export const cloneState = (s: State): State => cloneBytes(s);
