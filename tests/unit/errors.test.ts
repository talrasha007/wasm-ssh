import { describe, expect, it } from "vitest";
import { mapEventToError, SshHostKeyError, SshProtocolError } from "../../src/errors.js";

describe("mapEventToError", () => {
  it("maps Disconnected events to SshProtocolError with reason/description", () => {
    const err = mapEventToError({ type: "Disconnected", reasonCode: 11, description: "bye" });
    expect(err).toBeInstanceOf(SshProtocolError);
    expect(err.message).toContain("11");
    expect(err.message).toContain("bye");
  });

  it("maps a host-key-flavored Unrecoverable message to SshHostKeyError", () => {
    const err = mapEventToError({ type: "Unrecoverable", message: "host key rejected by caller" });
    expect(err).toBeInstanceOf(SshHostKeyError);
  });

  it("maps other Unrecoverable messages to SshProtocolError", () => {
    const err = mapEventToError({ type: "Unrecoverable", message: "framing error: bad length" });
    expect(err).toBeInstanceOf(SshProtocolError);
    expect(err.message).toContain("framing error");
  });
});
