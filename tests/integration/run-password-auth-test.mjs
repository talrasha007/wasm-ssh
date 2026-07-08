// Orchestrates the one integration test that needs a real socket end-to-end: builds `fake_sshd`
// (a real TCP listener wrapping ssh-core-testkit's FakeServer), starts it, starts `wrangler dev`
// against tests/integration/password-auth-worker (which drives two real `SshClient` auth flows
// over `cloudflare:sockets` - an omitted credential falling back to an interactive prompt, and a
// literal password string passed directly), asserts on the result, and tears both down
// unconditionally. This is the one thing Rust-side tests can't cover: the JS-side
// detection/buffering/retry logic in `SshClient`'s `privateKeyOrPassword` handling.
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..", "..");
const PORT = 2299;
const WORKER_PORT = 18793;

function waitForStdout(child, marker, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out waiting for "${marker}"`)), timeoutMs);
    const onData = (chunk) => {
      if (chunk.toString().includes(marker)) {
        clearTimeout(timer);
        child.stdout.off("data", onData);
        resolve();
      }
    };
    child.stdout.on("data", onData);
  });
}

async function main() {
  console.log("Building fake_sshd...");
  await run("cargo", ["build", "-p", "ssh-core-testkit", "--bin", "fake_sshd"], repoRoot);

  const sshdBin = path.join(repoRoot, "target", "debug", process.platform === "win32" ? "fake_sshd.exe" : "fake_sshd");
  const sshd = spawn(sshdBin, [String(PORT), "bob", "hunter2"]);
  sshd.stderr.pipe(process.stderr);
  try {
    await waitForStdout(sshd, "LISTENING", 5000);
    console.log("fake_sshd ready on port", PORT);

    const workerDir = path.join(repoRoot, "tests", "integration", "password-auth-worker");
    const wrangler = spawn("npx", ["--yes", "wrangler@4", "dev", "--port", String(WORKER_PORT)], {
      cwd: workerDir,
      shell: process.platform === "win32",
    });
    wrangler.stderr.pipe(process.stderr);
    let wranglerOutput = "";
    wrangler.stdout.on("data", (c) => (wranglerOutput += c.toString()));
    try {
      await waitForStdoutText(() => wranglerOutput, "Ready on", 20000);
      await delay(1000); // small settle margin beyond the "Ready on" log line

      const res = await fetch(`http://127.0.0.1:${WORKER_PORT}/`, { signal: AbortSignal.timeout(20000) });
      const body = await res.json();
      console.log("Result:", body);

      const { interactivePrompt, literalPassword } = body;

      assert(
        interactivePrompt.promptCount === 2,
        `expected exactly 2 password prompts (initial + 1 retry), got ${interactivePrompt.promptCount}`,
      );
      assert(
        interactivePrompt.events.includes("ready"),
        `expected interactive-prompt auth to eventually succeed (onReady), got events: ${JSON.stringify(interactivePrompt.events)}`,
      );

      assert(
        literalPassword.promptCount === 0,
        `expected a literal password to authenticate with no prompt at all, got ${literalPassword.promptCount} prompt(s)`,
      );
      assert(
        literalPassword.events.includes("ready"),
        `expected literal-password auth to succeed (onReady), got events: ${JSON.stringify(literalPassword.events)}`,
      );

      console.log("PASS: both the interactive password prompt/retry/success flow and the literal-password (no-prompt) flow work end-to-end.");
    } finally {
      wrangler.kill();
    }
  } finally {
    sshd.kill();
  }
}

function assert(cond, message) {
  if (!cond) throw new Error("Assertion failed: " + message);
}

function waitForStdoutText(getText, marker, timeoutMs) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const poll = setInterval(() => {
      if (getText().includes(marker)) {
        clearInterval(poll);
        resolve();
      } else if (Date.now() - start > timeoutMs) {
        clearInterval(poll);
        reject(new Error(`timed out waiting for "${marker}" in wrangler output`));
      }
    }, 200);
  });
}

function run(cmd, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, stdio: "inherit", shell: process.platform === "win32" });
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} exited with code ${code}`))));
  });
}

main().catch((err) => {
  console.error("FAIL:", err.message);
  process.exitCode = 1;
});
