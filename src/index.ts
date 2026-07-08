export { initWasmSshClient } from "./wasm-init.js";
export { SshClient } from "./client.js";
export {
  SshError,
  SshHostKeyError,
  SshAuthError,
  SshProtocolError,
  SshChannelError,
  SshTimeoutError,
  SshConnectionClosedError,
} from "./errors.js";
export type { SocketLike, HostKeyInfo, HostKeyVerifier, PtyOptions, SshClientOptions, ExecResult, SocketConnectOptions } from "./types.js";

// Socket-wrapping `connect()` deliberately lives under `wasm-ssh-client/cloudflare` (and is
// re-exported from `wasm-ssh-client/node`), not here - see socket-connect.ts's doc comment. Import
// it from one of those two subpaths instead of expecting it at the package root.
