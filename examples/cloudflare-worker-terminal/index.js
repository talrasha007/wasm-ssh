// Bridges a browser WebSocket to an interactive SSH shell on a target host, using the low-level
// `SshClient` directly (constructor + onSendToServer/onTerminalOutput) rather than the
// `wasm-ssh-client/cloudflare` convenience wrapper - useful when, like here, you want manual
// control over the TCP <-> wasm <-> WebSocket byte plumbing instead of a promise that just
// resolves once ready, and it's required for password auth typed interactively into the
// terminal (see the `SshClient` construction below) since `connect()` needs the private key
// up front.
import { connect } from "cloudflare:sockets";
import { initWasmSshClient, SshClient } from "wasm-ssh-client";

initWasmSshClient();

export default {
  async fetch(request, env) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected a WebSocket upgrade", { status: 426 });
    }

    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();

    // `env.SSH_PRIVATE_KEY_OR_PASSWORD` can be an OpenSSH private key (publickey auth), a literal
    // password (sent directly, no prompt), or left unset entirely to authenticate with a password
    // typed interactively instead - a "Password: " prompt is then sent through `onTerminalOutput`
    // automatically, and keystrokes routed through `sendInput` (below) are captured for it rather
    // than echoed. See `SshClient`'s constructor doc for exactly how it tells these apart.
    const sshClient = new SshClient(env.SSH_USERNAME, env.SSH_PRIVATE_KEY_OR_PASSWORD, {
      pty: { term: "xterm-256color", cols: 80, rows: 24 },
      // No `verifyHostKey` configured: trusts the target host unconditionally. Fine for a fixed,
      // already-trusted internal host; add one (checking a fingerprint from KV/D1) for anything
      // reachable by an untrusted hostname.
    });

    // Establish the raw TCP connection to the target SSH server.
    const socket = connect({ hostname: env.SSH_TARGET_HOST, port: 22 });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    // wasm produces handshake/auth/shell bytes -> write them to the TCP socket.
    sshClient.onSendToServer((bytes) => {
      writer.write(bytes).catch(() => sshClient.close());
    });
    // wasm parses shell output out of the TCP stream -> forward it to the browser.
    sshClient.onTerminalOutput((data) => server.send(data));

    sshClient.onError((err) => server.send(`\r\n[ssh error] ${err.message}\r\n`));
    sshClient.onClose(() => {
      try {
        server.close(1011, "SSH session ended");
      } catch {
        /* already closed */
      }
    });

    // TCP socket produces bytes (server's handshake/auth/shell responses) -> feed them to wasm.
    (async () => {
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) {
            sshClient.close();
            return;
          }
          sshClient.feedFromServer(value);
        }
      } catch {
        sshClient.close();
      }
    })();

    // Browser keystrokes -> the shell's stdin.
    server.addEventListener("message", (event) => {
      if (typeof event.data === "string") {
        sshClient.sendInput(new TextEncoder().encode(event.data));
      } else {
        sshClient.sendInput(new Uint8Array(event.data));
      }
    });
    server.addEventListener("close", () => sshClient.close());

    return new Response(null, { status: 101, webSocket: client });
  },
};
