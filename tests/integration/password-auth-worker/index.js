import { connect } from "cloudflare:sockets";
import { SshClient } from "../../../dist/cloudflare.js";

// Drives two real auth flows against `fake_sshd` (ssh-core-testkit's FakeServer wrapped in a
// real TCP listener) over a real socket via `cloudflare:sockets` (proxied to real local TCP by
// `wrangler dev`) - the two pieces of the auto-adapting `privateKeyOrPassword` parameter that
// aren't covered by Rust-side tests, since they're pure JS-side logic in `SshClient`:
//
// 1. Omitted entirely -> interactive prompt: the prompt appearing, a wrong password causing
//    exactly one retry prompt, and the correct password eventually succeeding.
// 2. A literal password string passed directly -> authenticates immediately with no prompt at
//    all.
async function runScenario({ port, username, password, credential }) {
  const sshClient = new SshClient(username, credential, { autoShell: false });

  const socket = connect({ hostname: "127.0.0.1", port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  const events = [];
  let promptCount = 0;
  let sentWrong = false;
  let sentRight = false;

  const done = new Promise((resolve) => {
    sshClient.onReady(() => {
      events.push("ready");
      resolve();
    });
    sshClient.onClose((err) => {
      events.push("closed:" + (err ? err.message : "clean"));
      resolve();
    });
  });

  sshClient.onSendToServer((bytes) => {
    writer.write(bytes).catch(() => {});
  });

  sshClient.onTerminalOutput((data) => {
    const text = new TextDecoder().decode(data);
    if (text.includes("Password:")) {
      promptCount++;
      // Only exercised when `credential` was omitted (scenario 1) - a literal password
      // (scenario 2) should authenticate immediately and never reach this branch at all.
      if (!sentWrong) {
        sentWrong = true;
        sshClient.sendInput(new TextEncoder().encode("wrong-password\r"));
      } else if (!sentRight) {
        sentRight = true;
        sshClient.sendInput(new TextEncoder().encode(password + "\r"));
      }
    }
  });

  (async () => {
    try {
      for (;;) {
        const { done: readDone, value } = await reader.read();
        if (readDone) return;
        sshClient.feedFromServer(value);
      }
    } catch {
      /* connection torn down below regardless */
    }
  })();

  const timeout = new Promise((resolve) => setTimeout(() => resolve(), 8000));
  await Promise.race([done, timeout]);

  sshClient.close();
  return { promptCount, events, isClosed: sshClient.isClosed };
}

export default {
  async fetch(request, env) {
    const port = Number(env.FAKE_SSHD_PORT ?? 2299);
    const username = env.FAKE_SSHD_USERNAME ?? "bob";
    const password = env.FAKE_SSHD_PASSWORD ?? "hunter2";

    const interactivePrompt = await runScenario({ port, username, password, credential: undefined });
    const literalPassword = await runScenario({ port, username, password, credential: password });

    return new Response(JSON.stringify({ interactivePrompt, literalPassword }));
  },
};
