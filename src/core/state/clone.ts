import type { State } from "../types";
import { cloneBytes } from "./bytes";
import { cloneMatrix } from "./matrix";

export const cloneState = (s: State): State => {
  switch (s.shape) {
    case "bytes":
      return cloneBytes(s);
    case "matrix4x4-bytes":
      return cloneMatrix(s);
  }
};
