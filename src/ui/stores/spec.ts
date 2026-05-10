import { aes128Spec } from "@/ciphers/aes-128";
import type { CipherSpec } from "@/core/types";
import { createSignal } from "solid-js";

const [spec, setSpec] = createSignal<CipherSpec>(aes128Spec);

export const useSpec = () => spec;
export const replaceSpec = (next: CipherSpec) => setSpec(next);
