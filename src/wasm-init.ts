// Isolates the wasm import/instantiate story in one file: everything else in this package talks
// to `getSession()`/`WasmSshSession`, never to `../pkg` directly. If the bundling strategy ever
// needs to change (e.g. base64-inlined fallback instead of a real `.wasm` file import), this is
// the only file that needs to change.
//
// `--target web` + `initSync({ module })` is deliberate, not `--target bundler`: verified via a
// real `wrangler dev` run that `--target bundler`'s output (`import * as wasm from "*.wasm"`,
// expecting the import to already be an instantiated exports object) does not work under
// Wrangler's esbuild-based bundler - it treats a `.wasm` import as a `WebAssembly.Module`
// (default import), which is exactly what the `--target web` output's `initSync` expects.
import wasmModule from "../pkg/ssh_wasm_bg.wasm";
// @ts-ignore - generated file, present only after `npm run build:wasm`
import { initSync, WasmSshSession as WasmSshSessionClass } from "../pkg/ssh_wasm.js";

export type { WasmSshSessionClass as WasmSshSession };

let initialized = false;

/**
 * Idempotent. Consumers should call this once per isolate, ideally at Worker module top level
 * (predictable one-time cold-start cost) - `createWasmSession()` also calls it lazily as a
 * safety net for callers who forget.
 */
export function initWasmSshClient(): void {
  if (initialized) return;
  initSync({ module: wasmModule });
  initialized = true;
}

export function createWasmSession(): InstanceType<typeof WasmSshSessionClass> {
  initWasmSshClient();
  return new WasmSshSessionClass();
}
