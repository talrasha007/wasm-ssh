# wasm-ssh

A WebAssembly SSHv2 client (Rust core, wasm-bindgen JS bindings) designed to run inside Cloudflare Workers/Pages.

## Architecture

- `ssh-core/` — sans-io SSH protocol state machine (transport, kex, userauth, connection/channels). Pure Rust, no tokio, no `std::net`/`std::thread`/`std::fs`. Driven by feeding bytes in and draining bytes/events out; never owns a socket.
- `wasm-ssh-bindgen/` — thin wasm-bindgen shell exposing `ssh-core` to JS. Owns the `getrandom`/`wasm_js` RNG backend wiring.
- `ssh-core-testkit/` — native-only (std, real sockets/subprocess OK) test support crate: in-process fake SSH server + test vectors.
- `src/` — hand-written TypeScript: the npm-published pump loop, public API, error types, Node test adapter.
- `tests/`, `examples/` — integration tests and a minimal smoke-test Worker.

Why sans-io: Workers/Pages run on `workerd`, single-threaded per request, no raw sockets from WASM. JS owns the actual TCP socket (via `cloudflare:sockets`) and pumps bytes to/from the wasm engine.

See the plan file for full phase breakdown and design rationale (crate choices, algorithm scope, testing strategy) if present in `.claude`/plan history.

## Scope (v1)

Auth: password + publickey (ed25519, rsa-sha2-256/512). Interaction: exec + interactive shell/PTY. KEX: curve25519-sha256, diffie-hellman-group14-sha256. Ciphers: chacha20-poly1305@openssh.com, aes256-gcm@openssh.com. Out of scope: SFTP, port/agent/X11 forwarding, keyboard-interactive auth, mid-session rekey.

## Testing notes

No Docker available in some dev environments — real-peer interop/E2E tests use the `ssh2` npm package's server implementation as a local SSH server substitute instead of a Docker `sshd` container.
