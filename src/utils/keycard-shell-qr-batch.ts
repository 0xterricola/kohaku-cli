import { createECDH, createHash, randomBytes } from "node:crypto";
import { validateShellDerivePath } from "./keycard-shell-qr-derive.js";

const REQUEST_PREFIX = Buffer.from("KKQ3\x03", "binary");

export const SHELL_BATCH_MAX_PATHS = 2;
export const SHELL_BATCH_MAX_REQUEST_LENGTH = 196;

export function decodeShellBatchRequest(payload: Uint8Array) {
  const bytes = Buffer.from(payload);

  if (
    bytes.length < 89 ||
    bytes.length > SHELL_BATCH_MAX_REQUEST_LENGTH ||
    !bytes.subarray(0, 5).equals(REQUEST_PREFIX)
  ) {
    throw new Error("Invalid Shell batch request");
  }

  const count = bytes[86];

  if (count < 1 || count > SHELL_BATCH_MAX_PATHS) {
    throw new Error("Invalid derivation count");
  }

  const paths: string[] = [];
  let offset = 87;

  for (let i = 0; i < count; i++) {
    if (offset >= bytes.length) {
      throw new Error("Truncated derivation path");
    }

    const length = bytes[offset++];

    if (!length || offset + length > bytes.length) {
      throw new Error("Invalid derivation path length");
    }

    const path = bytes
      .subarray(offset, offset + length)
      .toString("ascii");

    validateShellDerivePath(path);
    paths.push(path);
    offset += length;
  }

  if (
    offset !== bytes.length ||
    new Set(paths).size !== paths.length
  ) {
    throw new Error("Invalid or duplicate derivation paths");
  }

  const hostPublicKey = Buffer.from(bytes.subarray(21, 86));

  if (hostPublicKey[0] !== 0x04) {
    throw new Error("Invalid host public key encoding");
  }

  return {
    challenge: Buffer.from(bytes.subarray(5, 21)),
    hostPublicKey,
    paths,
  };
}

export function createShellBatchRequest(paths: readonly string[]) {
  if (
    paths.length < 1 ||
    paths.length > SHELL_BATCH_MAX_PATHS ||
    new Set(paths).size !== paths.length
  ) {
    throw new Error("Expected one or two distinct paths");
  }

  const encodedPaths = paths.map((path) => {
    validateShellDerivePath(path);
    const bytes = Buffer.from(path, "ascii");
    return Buffer.concat([Buffer.from([bytes.length]), bytes]);
  });

  const ecdh = createECDH("secp256k1");
  ecdh.generateKeys();

  const hostPublicKey = ecdh.getPublicKey(
    undefined,
    "uncompressed",
  );

  const request = Buffer.concat([
    REQUEST_PREFIX,
    randomBytes(16),
    hostPublicKey,
    Buffer.from([paths.length]),
    ...encodedPaths,
  ]);

  if (request.length > SHELL_BATCH_MAX_REQUEST_LENGTH) {
    throw new Error("Batch exceeds single-frame QR limit");
  }

  let consumed = false;

  return {
    request,
    fingerprint: createHash("sha256")
      .update(hostPublicKey)
      .digest("hex")
      .slice(0, 16),
    deriveSharedSecret(shellPublicKey: Uint8Array) {
      if (consumed) {
        throw new Error("Shell QR session already consumed");
      }
      consumed = true;
      return ecdh.computeSecret(Buffer.from(shellPublicKey));
    },
  };
}
