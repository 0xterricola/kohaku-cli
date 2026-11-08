import { randomBytes, timingSafeEqual } from "node:crypto";

export const SHELL_QR_CHALLENGE_LENGTH = 16;
export const SHELL_QR_TAG_LENGTH = 32;
export const SHELL_QR_REQUEST_LENGTH = 21;
export const SHELL_QR_RESPONSE_LENGTH = 53;

const REQUEST_MAGIC = Buffer.from("KKQ1", "ascii");
const RESPONSE_MAGIC = Buffer.from("KKR1", "ascii");
const OP_DERIVE = 0x01;

function requireLength(
  value: Uint8Array,
  length: number,
  name: string,
): void {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${name} must be exactly ${length} bytes`);
  }
}

export function encodeShellQrRequest(
  challenge: Uint8Array,
): Buffer {
  requireLength(challenge, SHELL_QR_CHALLENGE_LENGTH, "Challenge");

  return Buffer.concat([
    REQUEST_MAGIC,
    Buffer.from([OP_DERIVE]),
    Buffer.from(challenge),
  ]);
}

export function createShellQrRequest(): Buffer {
  return encodeShellQrRequest(
    randomBytes(SHELL_QR_CHALLENGE_LENGTH),
  );
}

export function decodeShellQrRequest(
  payload: Uint8Array,
): { challenge: Buffer } {
  requireLength(payload, SHELL_QR_REQUEST_LENGTH, "Request");

  const bytes = Buffer.from(payload);

  if (!bytes.subarray(0, 4).equals(REQUEST_MAGIC)) {
    throw new Error("Unsupported request magic or version");
  }

  if (bytes[4] !== OP_DERIVE) {
    throw new Error("Unsupported request operation");
  }

  return { challenge: Buffer.from(bytes.subarray(5, 21)) };
}

export function encodeShellQrResponse(
  challenge: Uint8Array,
  tag: Uint8Array,
): Buffer {
  requireLength(challenge, SHELL_QR_CHALLENGE_LENGTH, "Challenge");
  requireLength(tag, SHELL_QR_TAG_LENGTH, "Receipt tag");

  return Buffer.concat([
    RESPONSE_MAGIC,
    Buffer.from([OP_DERIVE]),
    Buffer.from(challenge),
    Buffer.from(tag),
  ]);
}

export function decodeShellQrResponse(
  payload: Uint8Array,
): { challenge: Buffer; tag: Buffer } {
  requireLength(payload, SHELL_QR_RESPONSE_LENGTH, "Response");

  const bytes = Buffer.from(payload);

  if (!bytes.subarray(0, 4).equals(RESPONSE_MAGIC)) {
    throw new Error("Unsupported response magic or version");
  }

  if (bytes[4] !== OP_DERIVE) {
    throw new Error("Unsupported response operation");
  }

  return {
    challenge: Buffer.from(bytes.subarray(5, 21)),
    tag: Buffer.from(bytes.subarray(21, 53)),
  };
}

export function createShellQrResponseSession(
  request: Uint8Array,
) {
  const expected = decodeShellQrRequest(request).challenge;
  let completed = false;

  return {
    accept(response: Uint8Array): Buffer {
      if (completed) {
        throw new Error("Response already consumed");
      }

      const parsed = decodeShellQrResponse(response);

      if (!timingSafeEqual(expected, parsed.challenge)) {
        throw new Error("Response challenge mismatch");
      }

      completed = true;
      return parsed.tag;
    },
  };
}
