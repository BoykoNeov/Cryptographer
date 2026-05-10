/**
 * Load-bearing contracts. Saved CipherSpec JSON references these shapes
 * forever — changes here are breaking for any spec on disk.
 */

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

// ─── State ────────────────────────────────────────────────────────────────
// Discriminated union. Each variant carries the bytes plus enough shape
// metadata for the UI to pick the right view without a runtime cast.

export type StateShape = "bytes" | "matrix4x4-bytes" | "bitvec" | "bigint";

export type BytesState = {
  readonly shape: "bytes";
  readonly bytes: Uint8Array;
};

export type MatrixState = {
  readonly shape: "matrix4x4-bytes";
  /** Column-major, 16 bytes. AES convention: state[r + 4*c]. */
  readonly bytes: Uint8Array;
};

export type BitVecState = {
  readonly shape: "bitvec";
  readonly bits: Uint8Array; // packed; length in bits stored separately
  readonly bitLength: number;
};

export type BigIntState = {
  readonly shape: "bigint";
  readonly value: bigint;
};

export type State = BytesState | MatrixState | BitVecState | BigIntState;

// ─── Auxiliary lanes ──────────────────────────────────────────────────────
// Some steps need data alongside the main state — round keys, IVs, counters.
// They live in a typed `aux` map so executors stay pure of side channels.

export type AuxValue = State | Uint8Array | number | bigint;
export type Aux = ReadonlyMap<string, AuxValue>;

// ─── Spec ─────────────────────────────────────────────────────────────────

export type StepLeaf = {
  readonly kind: "step";
  readonly id: string; // unique within spec; UI references this
  readonly type: string; // registry key, e.g. "aes.sub-bytes@1"
  readonly params: Json;
};

export type StepGroup = {
  readonly kind: "group";
  readonly id: string;
  readonly label: string; // "Round 1", "Key Expansion"
  readonly children: readonly StepNode[];
};

export type StepNode = StepLeaf | StepGroup;

export type CipherSpec = {
  readonly id: string; // "aes-128@1"
  readonly name: string;
  readonly stateShape: StateShape;
  /** Inputs the runtime needs to seed the state and aux map. */
  readonly inputs: {
    readonly plaintext: { readonly shape: StateShape };
    readonly key: { readonly byteLength: number };
  };
  readonly steps: readonly StepNode[];
};

// ─── Trace ────────────────────────────────────────────────────────────────

export type TraceFrame = {
  /** Monotonic frame index across the whole trace. */
  readonly index: number;
  /** Path of group ids from root to this leaf, then the leaf's id. */
  readonly path: readonly string[];
  readonly stepId: string;
  readonly stepType: string;
  readonly params: Json;
  readonly stateBefore: State;
  readonly stateAfter: State;
  /** Aux entries that were read or written by this step. */
  readonly auxRead: ReadonlyMap<string, AuxValue>;
  readonly auxWritten: ReadonlyMap<string, AuxValue>;
};

export type Trace = {
  readonly frames: readonly TraceFrame[];
  readonly finalState: State;
  readonly finalAux: Aux;
};

// ─── Executor contract ────────────────────────────────────────────────────

export type StepContext = {
  readonly stepId: string;
  readonly path: readonly string[];
  readonly aux: Aux;
};

export type StepResult = {
  readonly state: State;
  /** Aux changes; merged into the live aux map by the runtime. */
  readonly auxWrites?: ReadonlyMap<string, AuxValue>;
  /** Aux keys this executor consumed (for trace bookkeeping). */
  readonly auxReads?: readonly string[];
};

export type StepExecutor = (state: State, params: Json, ctx: StepContext) => StepResult;
