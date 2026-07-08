# wasm-ssh-client

An SSHv2 client, implemented in Rust and compiled to WebAssembly, for use inside Cloudflare
Workers and Pages Functions (or Node, via the bundled adapter).

Cloudflare Workers/Pages give JS access to raw outbound TCP sockets via `connect()` from
`cloudflare:sockets`, but nothing understands SSH on top of that socket. This library is the SSH
protocol engine. `SshClient` never touches a socket itself - it takes bytes in and hands bytes
back out via callbacks - so it's entirely up to the caller how those bytes reach the network. Two
ways to use it:

1. **Manual wiring** - construct `SshClient` directly and wire `onSendToServer`/`feedFromServer`
   to a `cloudflare:sockets` `Socket` (or anything else) yourself. Gives full control; the natural
   fit for bridging an interactive shell to a WebSocket.
2. **`connect()` convenience wrapper** - from `wasm-ssh-client/cloudflare` (or `wasm-ssh-client/node`
   for local testing) - does that wiring for you and resolves once authenticated. The right choice
   for a one-shot `exec()`.

## Install

```
npm install wasm-ssh-client
```

## Manual wiring (interactive shell -> WebSocket)

```js
import { connect } from "cloudflare:sockets";
import { initWasmSshClient, SshClient } from "wasm-ssh-client";

initWasmSshClient(); // once per isolate, ideally at module top level

const sshClient = new SshClient(env.SSH_USERNAME, env.SSH_PRIVATE_KEY_OR_PASSWORD);

const socket = connect({ hostname: env.SSH_TARGET_HOST, port: 22 });
const writer = socket.writable.getWriter();
const reader = socket.readable.getReader();

// wasm does the handshake/auth internally; whatever bytes it needs sent go to the TCP writer.
sshClient.onSendToServer((bytes) => writer.write(bytes));
// Parsed shell output - forward it wherever it needs to go (a WebSocket, here).
sshClient.onTerminalOutput((data) => server.send(data));

// TCP bytes from the server feed back into wasm for parsing.
(async () => {
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    sshClient.feedFromServer(value);
  }
})();

// Browser keystrokes -> the shell's stdin.
server.addEventListener("message", (e) => sshClient.sendInput(new TextEncoder().encode(e.data)));
```

`SshClient`'s constructor is `new SshClient(username, privateKeyOrPassword?, options?)`.
`privateKeyOrPassword` auto-adapts to whatever you pass:
- **An OpenSSH-formatted private key** (contains a `PRIVATE KEY` PEM marker) -> publickey auth.
  The public key used in the handshake is always derived from it automatically.
- **Any other non-empty string** -> sent directly as the SSH password, no prompt.
- **Omitted** (`undefined`/`""`) -> a password typed interactively instead: once the handshake
  reaches the auth phase, a `"Password: "` prompt is sent through `onTerminalOutput`, and
  keystrokes fed through `sendInput` are captured (not echoed, like a real terminal password
  prompt) until Enter submits the line as the SSH password. (Only available via direct `SshClient`
  construction, not the `connect()` convenience wrapper below - `connect()` resolves once
  authenticated, and there's no `SshClient` handle yet at that point for a caller to type into.)

Whenever an attempt is rejected and the server still allows password auth, this always falls back
to (or continues) the interactive prompt - so a failed publickey or a wrong hardcoded password
both end up letting a human type one in, the same way a real `ssh` CLI drops from a failed
publickey attempt into a password prompt rather than just giving up.

- By default it opens an interactive shell automatically once authenticated (`options.autoShell`,
  default `true`; set `pty: { term, cols, rows }` to configure it). Set `autoShell: false` if you
  only want `exec()`.
- `options.verifyHostKey` - **optional**. If omitted, the host key is trusted unconditionally -
  Workers has no filesystem for `known_hosts`, so this is always a callback rather than a file
  lookup; leaving it unset is a real MITM exposure for anything other than a fixed, already-trusted
  target. Register/override it later with `onHostKey(cb)`.

See [`examples/cloudflare-worker-terminal`](examples/cloudflare-worker-terminal) for the complete,
runnable version of the above (a full WebSocket-to-SSH-shell bridge).

## `connect()` convenience wrapper (one-shot exec)

```js
import { connect as connectSocket } from "cloudflare:sockets";
import { initWasmSshClient } from "wasm-ssh-client";
import { connect } from "wasm-ssh-client/cloudflare";

initWasmSshClient();

export default {
  async fetch(request, env) {
    const socket = connectSocket({ hostname: env.SSH_HOST, port: 22 });
    const client = await connect(socket, {
      username: env.SSH_USERNAME,
      privateKeyOrPassword: env.SSH_PRIVATE_KEY_OR_PASSWORD, // private key or literal password
      autoShell: false, // exec() doesn't need the auto-opened shell
      verifyHostKey: (info) => info.fingerprintSha256 === env.EXPECTED_HOST_KEY_FINGERPRINT,
    });

    const { stdout, exitCode } = await client.exec("uptime");
    client.close();
    return new Response(new TextDecoder().decode(stdout), { status: exitCode === 0 ? 200 : 502 });
  },
};
```

`connect()` is named under `wasm-ssh-client/cloudflare` (rather than the package root) so it
doesn't collide with `connect` from `cloudflare:sockets` itself when both are imported side by
side. Its implementation is transport-agnostic - the same function is re-exported from
`wasm-ssh-client/node` and works with a Node `net.Socket` wrapped via that module's adapter.

See [`examples/cloudflare-worker-exec`](examples/cloudflare-worker-exec) for the complete,
runnable version.

## Node (local testing)

```js
import { connectViaNode, connect } from "wasm-ssh-client/node";

const socket = await connectViaNode("localhost", 22);
const client = await connect(socket, { username: "...", privateKeyOrPassword: "..." });
```

## Supported algorithms

| Category | Algorithms |
|---|---|
| Key exchange | `curve25519-sha256` (preferred), `diffie-hellman-group14-sha256` |
| Host key | `ssh-ed25519` (preferred), `rsa-sha2-512`, `rsa-sha2-256` (verification only) |
| Cipher | `chacha20-poly1305@openssh.com` (preferred), `aes256-gcm@openssh.com` |

No compression, no CBC ciphers, no `ssh-rsa` (SHA-1), no DSA. Client-side RSA signatures (for
publickey auth) are always `rsa-sha2-512`.

## v1 limitations

- Publickey and password auth only - no `keyboard-interactive`.
- No OpenSSH certificate-based auth (CA-signed short-lived certs).
- No SFTP, no port/agent/X11 forwarding.
- No mid-session rekeying (a very long-lived connection will eventually need one per RFC 4253,
  but nothing currently triggers it).
- `exec()` buffers stdout/stderr fully in memory - fine for typical command output, not for very
  large output. Use the auto-opened shell and `onTerminalOutput` and stream the result yourself
  for that case.

## Development

- `npm run build:wasm` - compiles the Rust crate and generates JS bindings into `pkg/`.
- `npm run build:ts` - bundles `src/` (plus the wasm asset) into `dist/` via tsup.
- `npm run build` - both, in order.
- `cargo test --workspace` - Rust unit + in-process end-to-end handshake tests (no network
  required - see `ssh-core-testkit`'s `FakeServer`, which reuses the client's own crypto/framing
  code from the server's side of a real handshake).
- `npm run test:unit` - JS-side unit tests (vitest).

No Docker/system `sshd` is assumed anywhere in this repo's test setup; real-network verification
(`wrangler dev` against a real SSH server) is a manual/CI-only step, not part of the fast local
loop.
