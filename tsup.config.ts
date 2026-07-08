import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/index.ts", cloudflare: "src/cloudflare.ts", "node-adapter": "src/node-adapter.ts" },
  format: ["esm"],
  target: "es2022",
  platform: "neutral",
  dts: true,
  clean: true,
  esbuildOptions(options) {
    // esbuild's "copy" loader copies the .wasm file into the output dir and rewrites the import
    // to point at it verbatim - it does NOT try to parse/inline it the way the default loader
    // would (which would fail outright on a binary file). This is what lets wasm-init.ts's
    // `import wasmModule from "../pkg/ssh_wasm_bg.wasm"` survive bundling into `dist/`.
    options.loader = { ...options.loader, ".wasm": "copy" };
  },
});
