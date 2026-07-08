// `wasm-ssh-client/cloudflare` - a convenience wrapper for the common case of using this
// library from a Cloudflare Worker/Pages Function against a `cloudflare:sockets` `Socket`.
// Named as its own subpath (mirroring `wasm-ssh-client/node`) partly so `connect` here doesn't
// collide with `connect` from `cloudflare:sockets` itself when both are imported side by side.
//
// The implementation is transport-agnostic (see `socket-connect.ts`) - the same `connect()`
// works with a Node `net.Socket` wrapped via `wasm-ssh-client/node`'s adapter too.
export { connect } from "./socket-connect.js";
export { SshClient } from "./client.js";
export type { SocketConnectOptions, SocketLike } from "./types.js";
