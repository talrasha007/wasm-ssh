import type { HostKeyInfo } from "./types.js";

export class SshError extends Error {
  code: string;
  cause?: unknown;

  constructor(message: string, code = "SSH_ERROR", cause?: unknown) {
    super(message);
    this.name = "SshError";
    this.code = code;
    this.cause = cause;
  }
}

export class SshHostKeyError extends SshError {
  hostKey?: HostKeyInfo;
  constructor(message: string, hostKey?: HostKeyInfo) {
    super(message, "SSH_HOST_KEY_ERROR");
    this.name = "SshHostKeyError";
    this.hostKey = hostKey;
  }
}

export class SshAuthError extends SshError {
  remainingMethods?: string[];
  constructor(message: string, remainingMethods?: string[]) {
    super(message, "SSH_AUTH_ERROR");
    this.name = "SshAuthError";
    this.remainingMethods = remainingMethods;
  }
}

export class SshProtocolError extends SshError {
  constructor(message: string) {
    super(message, "SSH_PROTOCOL_ERROR");
    this.name = "SshProtocolError";
  }
}

export class SshChannelError extends SshError {
  constructor(message: string) {
    super(message, "SSH_CHANNEL_ERROR");
    this.name = "SshChannelError";
  }
}

export class SshTimeoutError extends SshError {
  constructor(message: string) {
    super(message, "SSH_TIMEOUT");
    this.name = "SshTimeoutError";
  }
}

export class SshConnectionClosedError extends SshError {
  constructor(message = "SSH connection closed") {
    super(message, "SSH_CONNECTION_CLOSED");
    this.name = "SshConnectionClosedError";
  }
}

/**
 * Translates one JSON-encoded event from the wasm engine (`{"type":"Unrecoverable",...}` /
 * `{"type":"Disconnected",...}`) into a typed error. This is the single place coupled to the
 * Rust `Event`/`SshError` taxonomy's exact shape, so a change there only needs updating here.
 */
export function mapEventToError(event: Record<string, unknown>): SshError {
  const type = event.type as string;
  if (type === "Disconnected") {
    return new SshProtocolError(`server disconnected (reason ${event.reasonCode}): ${event.description}`);
  }
  if (type === "Unrecoverable") {
    const message = String(event.message ?? "unknown error");
    if (message.includes("host key")) {
      return new SshHostKeyError(message);
    }
    if (message.includes("auth")) {
      return new SshAuthError(message);
    }
    return new SshProtocolError(message);
  }
  return new SshError(`unexpected event: ${JSON.stringify(event)}`);
}
