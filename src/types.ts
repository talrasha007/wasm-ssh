/** Minimal duck-type both a Cloudflare `Socket` and a Node `net.Socket` adapter satisfy. */
export interface SocketLike {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  closed?: Promise<void>;
  close?(): void | Promise<void>;
}

export interface HostKeyInfo {
  algorithm: string;
  fingerprintSha256: string;
  rawBlob: Uint8Array;
}

/** Return (or resolve to) `true` to trust the host key, `false` to reject and disconnect. */
export type HostKeyVerifier = (info: HostKeyInfo) => boolean | Promise<boolean>;

export interface PtyOptions {
  term?: string;
  cols?: number;
  rows?: number;
}

export interface SshClientOptions {
  /** Passphrase for an encrypted `privateKey`, if any. */
  passphrase?: string;
  /**
   * Verifies the server's host key. **If omitted, the host key is trusted unconditionally** -
   * fine for a fixed, already-trusted target, a real MITM exposure otherwise. Workers has no
   * filesystem for a `known_hosts` file, so this is always a callback rather than a file lookup.
   */
  verifyHostKey?: HostKeyVerifier;
  /** Opens an interactive shell automatically once authenticated. Default `true`. */
  autoShell?: boolean;
  /** PTY size/type for the auto-opened shell. Ignored if `autoShell` is `false`. */
  pty?: PtyOptions;
}

export interface ExecResult {
  stdout: Uint8Array;
  stderr: Uint8Array;
  exitCode: number | null;
  exitSignal?: string;
}

/** Options for {@link cloudflareConnect} (`wasm-ssh-client/cloudflare`). */
export interface SocketConnectOptions extends SshClientOptions {
  username: string;
  /**
   * An OpenSSH-formatted private key or a literal password - see `SshClient`'s constructor doc
   * for how it's told apart. Required here (unlike `SshClient`'s constructor): `connect()`
   * resolves once authenticated, so there's no `SshClient` handle yet at that point for a caller
   * to type a password into interactively the way omitting this entirely would otherwise trigger.
   */
  privateKeyOrPassword: string;
  /** Milliseconds to wait for the connection to reach an authenticated state. Default 15000. */
  readyTimeoutMs?: number;
}
