import { connect } from "cloudflare:sockets";
import { SshClient } from "../../../dist/cloudflare.js";

export default {
  async fetch(request, env) {
    const sshClient = new SshClient(env.SSH_USERNAME ?? "root", env.SSH_PRIVATE_KEY, {
      autoShell: false,
    });

    const socket = connect({ hostname: env.SSH_TARGET_HOST ?? "127.0.0.1", port: 22 });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    let firstOutgoingChunk = null;
    sshClient.onSendToServer((bytes) => {
      if (!firstOutgoingChunk) firstOutgoingChunk = bytes;
      writer.write(bytes).catch(() => {});
    });
    sshClient.onTerminalOutput((text) => {
      // would normally be: server.send(text) to forward to a WebSocket
    });

    // Just prove construction + callback wiring produces the client's real SSH identification
    // line, matching the exact API shape requested (constructor + onSendToServer/onTerminalOutput),
    // without actually needing a reachable SSH server for this smoke test.
    await new Promise((r) => setTimeout(r, 0));
    const identLine = firstOutgoingChunk ? new TextDecoder().decode(firstOutgoingChunk) : "(none)";
    return new Response("client_ident=" + identLine.trim());
  },
};
