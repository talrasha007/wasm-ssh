import { connect as connectSocket } from "cloudflare:sockets";
import { initWasmSshClient } from "wasm-ssh-client";
import { connect } from "wasm-ssh-client/cloudflare";
import { SshAuthError, SshHostKeyError, SshProtocolError } from "wasm-ssh-client";

// One-time per isolate; safe to call at module top level.
initWasmSshClient();

export default {
  async fetch(request, env) {
    const socket = connectSocket({ hostname: env.SSH_HOST, port: Number(env.SSH_PORT ?? 22) });

    try {
      const client = await connect(socket, {
        username: env.SSH_USERNAME,
        // Either an OpenSSH private key or a literal password - auto-detected, see SshClient's
        // constructor doc.
        privateKeyOrPassword: env.SSH_PRIVATE_KEY_OR_PASSWORD,
        autoShell: false, // this example only runs one command, no interactive shell needed
        // Workers has no filesystem for a known_hosts file - trust decisions are always a
        // callback. A real deployment would check this fingerprint against a value stored in KV
        // or D1; omitting `verifyHostKey` (as this smoke test does) trusts the host unconditionally.
        verifyHostKey: env.SSH_HOST_KEY_FINGERPRINT
          ? (info) => info.fingerprintSha256 === env.SSH_HOST_KEY_FINGERPRINT
          : undefined,
        readyTimeoutMs: 10_000,
      });

      try {
        const result = await client.exec(env.SSH_COMMAND ?? "uptime");
        return new Response(new TextDecoder().decode(result.stdout), {
          status: result.exitCode === 0 ? 200 : 502,
          headers: { "content-type": "text/plain" },
        });
      } finally {
        client.close();
      }
    } catch (err) {
      if (err instanceof SshAuthError) return new Response(`auth failed: ${err.message}`, { status: 401 });
      if (err instanceof SshHostKeyError) return new Response(`host key rejected: ${err.message}`, { status: 502 });
      if (err instanceof SshProtocolError) return new Response(`protocol error: ${err.message}`, { status: 502 });
      throw err;
    }
  },
};
