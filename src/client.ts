import { createWasmSession } from "./wasm-init.js";
import { mapEventToError, SshChannelError, SshError } from "./errors.js";
import type { ExecResult, HostKeyInfo, HostKeyVerifier, PtyOptions, SshClientOptions } from "./types.js";

type WasmEvent = { type: string; [key: string]: unknown };
type OutputStream = "stdout" | "stderr";

interface ExecState {
  stdout: Uint8Array[];
  stderr: Uint8Array[];
  exitCode: number | null;
  exitSignal?: string;
  resolve: (result: ExecResult) => void;
  reject: (err: unknown) => void;
  settled: boolean;
}

/**
 * A socket-agnostic SSH session: it never touches a socket itself. The host feeds it bytes read
 * from wherever the transport is ({@link SshClient.feedFromServer}) and registers a callback for
 * the bytes it needs sent back ({@link SshClient.onSendToServer}) - this is what lets the exact
 * same engine drive a raw `cloudflare:sockets` `Socket`, a Node `net.Socket`, or anything else
 * with a byte stream, with the wiring done entirely by the caller. `wasm-ssh-client/cloudflare`'s
 * `connect()` is a convenience helper that does this wiring automatically for a `SocketLike`.
 *
 * Handshake, authentication, and (by default) opening an interactive shell all happen
 * automatically as the underlying bytes flow; interactive output arrives via
 * {@link SshClient.onTerminalOutput}, and `sendInput`/`resize` drive it. For a single
 * non-interactive command, use {@link SshClient.exec} instead (works regardless of `autoShell`).
 *
 * Authentication auto-adapts to what `privateKeyOrPassword` looks like:
 * - An OpenSSH-formatted private key (contains a `PRIVATE KEY` PEM marker) -> publickey auth.
 * - Any other non-empty string -> sent directly as an SSH password, no prompt.
 * - Omitted entirely -> a password typed interactively through the same terminal channel: a
 *   "Password: " prompt is sent via `onTerminalOutput` once the handshake reaches the auth
 *   phase, keystrokes fed through `sendInput` are buffered (not echoed, matching a real
 *   terminal's password prompt) until Enter, and the buffered line is sent as the SSH password.
 *
 * Whenever an attempt fails and the server still allows password auth, this always falls back
 * to (or continues) the interactive prompt - mirroring how a real `ssh` CLI drops from a failed
 * publickey attempt into a password prompt rather than just giving up.
 */
export class SshClient {
  private readonly session = createWasmSession();

  private sendToServerCb?: (bytes: Uint8Array) => void;
  private terminalOutputCb?: (data: Uint8Array, stream: OutputStream) => void;
  private hostKeyCb?: HostKeyVerifier;
  private readyCb?: () => void;
  private closeCb?: (err?: SshError) => void;
  private errorCb?: (err: SshError) => void;

  private shellChannelId?: number;
  private readonly execs = new Map<number, ExecState>();
  private closed = false;
  private intentionalClose = false;

  private awaitingPasswordInput = false;
  private passwordBuffer: number[] = [];

  /**
   * @param username
   * @param privateKeyOrPassword An OpenSSH-formatted private key, a literal password, or
   *   `undefined` - see the class doc for how each is handled.
   */
  constructor(
    private readonly username: string,
    private readonly privateKeyOrPassword: string | undefined,
    private readonly options: SshClientOptions = {},
  ) {
    if (this.options.verifyHostKey) {
      this.hostKeyCb = this.options.verifyHostKey;
    }
  }

  /** Registers the sink for bytes the engine needs written to the transport. Flushes
   * immediately: the engine already has its identification line queued from construction. */
  onSendToServer(cb: (bytes: Uint8Array) => void): void {
    this.sendToServerCb = cb;
    this.flushOutgoing();
  }

  /** Registers the sink for the auto-opened interactive shell's output (see `autoShell`). Has
   * no effect on {@link SshClient.exec}, which resolves with its own buffered output instead. */
  onTerminalOutput(cb: (data: Uint8Array, stream: OutputStream) => void): void {
    this.terminalOutputCb = cb;
  }

  /** Overrides the `verifyHostKey` constructor option; see its doc for the "no callback ->
   * trust unconditionally" default. */
  onHostKey(cb: HostKeyVerifier): void {
    this.hostKeyCb = cb;
  }

  /** Fires once authentication succeeds (before the auto-shell, if any, finishes opening). */
  onReady(cb: () => void): void {
    this.readyCb = cb;
  }

  /** Fires once, when the session terminates for any reason (including a clean `close()`). */
  onClose(cb: (err?: SshError) => void): void {
    this.closeCb = cb;
  }

  /** Fires on any protocol/auth/host-key error. Also see `onClose`, which fires right after for
   * fatal errors. */
  onError(cb: (err: SshError) => void): void {
    this.errorCb = cb;
  }

  /** Feed bytes read from the transport (e.g. a `cloudflare:sockets` `Socket`'s `readable`). */
  feedFromServer(bytes: Uint8Array): void {
    if (this.closed) return;
    this.session.feed_incoming(bytes);
    this.pump();
  }

  /** Write bytes to the auto-opened shell's stdin, or - while a password prompt is pending (see
   * the class doc) - to the buffered password line instead. No-op once closed; before a shell is
   * open and no password prompt is pending, input is simply dropped (nothing to send it to). */
  sendInput(bytes: Uint8Array): void {
    if (this.closed) return;
    if (this.awaitingPasswordInput) {
      this.handlePasswordInput(bytes);
      return;
    }
    if (this.shellChannelId === undefined) return;
    this.session.channel_send(this.shellChannelId, bytes);
    this.flushOutgoing();
  }

  /** Resize the auto-opened shell's PTY. No-op if no shell is open. */
  resize(cols: number, rows: number): void {
    if (this.shellChannelId === undefined || this.closed) return;
    this.session.resize_pty(this.shellChannelId, cols, rows);
    this.flushOutgoing();
  }

  /** Run one non-interactive command and buffer its output, independent of the auto-shell. */
  exec(command: string): Promise<ExecResult> {
    if (this.closed) return Promise.reject(new SshError("session is closed", "SSH_CONNECTION_CLOSED"));
    const id = this.session.open_exec(command);
    return new Promise<ExecResult>((resolve, reject) => {
      this.execs.set(id, { stdout: [], stderr: [], exitCode: null, resolve, reject, settled: false });
      this.flushOutgoing();
    });
  }

  /** Tears down the session (and, if the caller wired transport closing into `onClose`, the
   * underlying socket too). Idempotent. */
  close(): void {
    if (this.closed) return;
    // `notify_transport_closed` makes the engine emit a terminal event synchronously; the
    // `intentionalClose` flag tells the handler below to report this to `onClose` as a clean
    // shutdown (`undefined`) rather than the literal "transport closed unexpectedly" error text.
    this.intentionalClose = true;
    this.session.notify_transport_closed();
    this.pump();
  }

  get isClosed(): boolean {
    return this.closed;
  }

  // ---- internals ----------------------------------------------------------------------------

  /** Only called once, in response to the first `ReadyForAuth` - retries after a failed attempt
   * always go through {@link SshClient.promptForPassword} instead (see the class doc), never
   * back through here, so a bad hardcoded password/key can't loop forever retrying itself. */
  private attemptInitialAuth(): void {
    const credential = this.privateKeyOrPassword;
    if (!credential) {
      this.promptForPassword();
      return;
    }
    if (looksLikePrivateKey(credential)) {
      try {
        this.session.authenticate_publickey(this.username, credential, this.options.passphrase);
      } catch (err) {
        this.shutdown(err instanceof Error ? new SshError(err.message, "SSH_AUTH_ERROR", err) : new SshError(String(err)));
        return;
      }
    } else {
      this.session.authenticate_password(this.username, credential);
    }
    this.flushOutgoing();
  }

  private promptForPassword(): void {
    this.awaitingPasswordInput = true;
    this.passwordBuffer = [];
    this.terminalOutputCb?.(new TextEncoder().encode("Password: "), "stdout");
  }

  /** Buffers raw bytes typed while a password prompt is pending, without echoing them back
   * (matching a real terminal's password prompt), until Enter submits the line or Ctrl-C
   * cancels authentication entirely. Backspace/Delete edit the buffer by byte, which can corrupt
   * a multi-byte UTF-8 character if backspaced mid-sequence - an accepted edge case, since
   * passwords are overwhelmingly ASCII. */
  private handlePasswordInput(bytes: Uint8Array): void {
    for (const byte of bytes) {
      if (byte === 0x0d || byte === 0x0a) {
        this.awaitingPasswordInput = false;
        const password = new TextDecoder().decode(new Uint8Array(this.passwordBuffer));
        this.passwordBuffer = [];
        this.terminalOutputCb?.(new TextEncoder().encode("\r\n"), "stdout");
        this.session.authenticate_password(this.username, password);
        this.flushOutgoing();
        return;
      }
      if (byte === 0x7f || byte === 0x08) {
        this.passwordBuffer.pop();
        continue;
      }
      if (byte === 0x03) {
        this.awaitingPasswordInput = false;
        this.passwordBuffer = [];
        this.shutdown(new SshError("authentication cancelled by user", "SSH_AUTH_ERROR"));
        return;
      }
      this.passwordBuffer.push(byte);
    }
  }

  private flushOutgoing(): void {
    if (!this.sendToServerCb) return;
    for (;;) {
      const chunk = this.session.take_outgoing();
      if (!chunk || chunk.length === 0) break;
      this.sendToServerCb(chunk);
    }
  }

  private pump(): void {
    this.flushOutgoing();
    for (;;) {
      const raw = this.session.poll_event();
      if (raw === undefined) break;
      this.handleEvent(JSON.parse(raw) as WasmEvent);
    }
    this.flushOutgoing();
  }

  private handleEvent(event: WasmEvent): void {
    switch (event.type) {
      case "HostKeyVerify": {
        const rawBlob = this.session.take_event_data();
        const info: HostKeyInfo = {
          algorithm: String(event.algorithm),
          fingerprintSha256: String(event.fingerprintSha256),
          rawBlob,
        };
        if (!this.hostKeyCb) {
          this.session.provide_host_key_decision(true);
          this.flushOutgoing();
          break;
        }
        Promise.resolve(this.hostKeyCb(info)).then((accept) => {
          this.session.provide_host_key_decision(Boolean(accept));
          this.flushOutgoing();
          if (!accept) {
            this.shutdown(new SshError(`host key rejected (${info.algorithm} ${info.fingerprintSha256})`, "SSH_HOST_KEY_ERROR"));
          }
        });
        break;
      }
      case "ReadyForAuth": {
        this.attemptInitialAuth();
        break;
      }
      case "AuthFailure": {
        const methods = (event.remainingMethods as string[]) ?? [];
        if (methods.includes("password")) {
          this.terminalOutputCb?.(new TextEncoder().encode("Permission denied, please try again.\r\n"), "stdout");
          this.promptForPassword();
          break;
        }
        this.shutdown(new SshError(`authentication failed (remaining methods: ${methods.join(", ") || "none"})`, "SSH_AUTH_ERROR"));
        break;
      }
      case "AuthSuccess": {
        this.readyCb?.();
        if (this.options.autoShell !== false) {
          const pty = this.options.pty;
          this.shellChannelId = this.session.open_shell(pty?.term ?? "xterm-256color", pty?.cols ?? 80, pty?.rows ?? 24);
          this.flushOutgoing();
        }
        break;
      }
      case "ChannelOpenFailed": {
        const id = Number(event.id);
        const err = new SshChannelError(`channel ${id} failed to open: ${event.description}`);
        this.execs.get(id)?.reject(err);
        this.execs.delete(id);
        if (id === this.shellChannelId) {
          this.shellChannelId = undefined;
          this.errorCb?.(err);
        }
        break;
      }
      case "ChannelData": {
        const id = Number(event.id);
        const data = this.session.take_event_data();
        const stream: OutputStream = event.stream === "stderr" ? "stderr" : "stdout";
        const exec = this.execs.get(id);
        if (exec) {
          (stream === "stderr" ? exec.stderr : exec.stdout).push(data);
        } else if (id === this.shellChannelId) {
          this.terminalOutputCb?.(data, stream);
        }
        break;
      }
      case "ChannelExitStatus": {
        const id = Number(event.id);
        const exec = this.execs.get(id);
        if (exec) {
          exec.exitCode = (event.code as number | null) ?? null;
          exec.exitSignal = event.signal as string | undefined;
        }
        break;
      }
      case "ChannelClosed": {
        const id = Number(event.id);
        const exec = this.execs.get(id);
        if (exec && !exec.settled) {
          exec.settled = true;
          exec.resolve({
            stdout: concatChunks(exec.stdout),
            stderr: concatChunks(exec.stderr),
            exitCode: exec.exitCode,
            exitSignal: exec.exitSignal,
          });
        }
        this.execs.delete(id);
        if (id === this.shellChannelId) {
          this.shellChannelId = undefined;
        }
        break;
      }
      case "Disconnected":
      case "Unrecoverable": {
        this.shutdown(this.intentionalClose ? undefined : mapEventToError(event));
        break;
      }
      default:
        break;
    }
  }

  /** Common path for both a deliberate `close()` and any fatal error: notifies `onError` (only
   * for real errors), rejects any in-flight `exec()` calls, and fires `onClose` exactly once. */
  private shutdown(err: SshError | undefined): void {
    if (err) this.errorCb?.(err);
    const execError = err ?? new SshError("session closed", "SSH_CONNECTION_CLOSED");
    for (const exec of this.execs.values()) {
      if (!exec.settled) {
        exec.settled = true;
        exec.reject(execError);
      }
    }
    this.execs.clear();
    if (!this.closed) {
      this.closed = true;
      this.closeCb?.(err);
    }
  }
}

/** OpenSSH-formatted private keys (and, incidentally, every other common PEM private-key armor -
 * PKCS#8, legacy RSA/DSA/EC) all contain this marker; a real password containing it is
 * astronomically unlikely. */
function looksLikePrivateKey(value: string): boolean {
  return value.includes("PRIVATE KEY");
}

function concatChunks(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}
