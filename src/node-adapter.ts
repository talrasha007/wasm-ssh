// Separate entry point (`wasm-ssh-client/node`) so Node builtins never get pulled into a
// Workers bundle via the package's default import.
import type { Socket } from "node:net";
import { connect as netConnect } from "node:net";
import { Readable, Writable } from "node:stream";
import type { SocketLike } from "./types.js";

// Re-exported for convenience: `connect()`'s implementation is transport-agnostic (see
// `socket-connect.ts`), so the exact same helper used by `wasm-ssh-client/cloudflare` works here
// against a `createNodeSocketAdapter`-wrapped socket.
export { connect } from "./socket-connect.js";
export { SshClient } from "./client.js";

export function createNodeSocketAdapter(socket: Socket): SocketLike {
  const readable = Readable.toWeb(socket) as unknown as ReadableStream<Uint8Array>;
  const writable = Writable.toWeb(socket) as unknown as WritableStream<Uint8Array>;
  const closed = new Promise<void>((resolve) => socket.once("close", () => resolve()));
  return {
    readable,
    writable,
    closed,
    close: () => {
      socket.destroy();
    },
  };
}

export function connectViaNode(host: string, port: number): Promise<SocketLike> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host, port });
    socket.once("connect", () => resolve(createNodeSocketAdapter(socket)));
    socket.once("error", reject);
  });
}
