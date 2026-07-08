import { SshClient } from "./client.js";
import { SshTimeoutError } from "./errors.js";
import type { SocketConnectOptions, SocketLike } from "./types.js";

const DEFAULT_READY_TIMEOUT_MS = 15_000;

/**
 * Wraps a {@link SocketLike} (a `cloudflare:sockets` `Socket`, a Node `net.Socket` via
 * `wasm-ssh-client/node`'s adapter, or anything else with the same shape) around an
 * {@link SshClient}: reads from `socket.readable` and feeds them in, writes whatever the client
 * produces to `socket.writable`. This is the only part of the wiring that's actually
 * transport-specific - `SshClient` itself never touches a socket - which is why the exact same
 * implementation works for both Cloudflare and Node sockets; it's exported from
 * `wasm-ssh-client/cloudflare` because that's the primary target, not because anything here is
 * Cloudflare-only.
 *
 * Resolves once authenticated (or rejects on failure/timeout) - which is why
 * `options.privateKeyOrPassword` is required here even though `SshClient` itself accepts
 * omitting it for an interactively-typed password: there's no `SshClient` handle yet at that
 * point in `connect()` for a caller to type one into via `sendInput`. For interactive password
 * auth, construct an `SshClient` directly (see its class doc) and wire
 * `onSendToServer`/`feedFromServer` yourself instead of using `connect()`.
 */
export async function connect(socket: SocketLike, options: SocketConnectOptions): Promise<SshClient> {
  const client = new SshClient(options.username, options.privateKeyOrPassword, options);

  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();

  client.onSendToServer((bytes) => {
    void writer.write(bytes).catch(() => client.close());
  });

  void (async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          client.close();
          return;
        }
        if (value && value.length > 0) {
          client.feedFromServer(value);
        }
      }
    } catch {
      client.close();
    }
  })();

  const timeoutMs = options.readyTimeoutMs ?? DEFAULT_READY_TIMEOUT_MS;
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new SshTimeoutError("timed out before authentication completed")), timeoutMs);
    client.onReady(() => {
      clearTimeout(timer);
      resolve();
    });
    client.onClose((err) => {
      clearTimeout(timer);
      reject(err ?? new Error("connection closed before authentication completed"));
    });
  }).catch(async (err) => {
    try {
      await reader.cancel();
    } catch {
      /* ignore */
    }
    try {
      await writer.close();
    } catch {
      /* ignore */
    }
    try {
      await socket.close?.();
    } catch {
      /* ignore */
    }
    throw err;
  });

  return client;
}
