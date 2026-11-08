import { createECDH, createHash, randomBytes } from "node:crypto";

export const SHELL_DERIVE_CHALLENGE_LENGTH = 16;
export const SHELL_DERIVE_PUBLIC_KEY_LENGTH = 65;
export const SHELL_DERIVE_MAX_PATH_LENGTH = 96;

const REQUEST_PREFIX = Buffer.from([
  0x4b, 0x4b, 0x51, 0x32, 0x02,
]);

const R3_PATH =
  new RegExp("^m/28784'/1'/(0|[1-9][0-9]*)'/([012])'/(0|[1-9][0-9]*)'/(0|[1-9][0-9]*)'$");

export function validateShellDerivePath(path: string): void {
  const bytes = Buffer.from(path, "utf8");
  const match = R3_PATH.exec(path);

  if (
    bytes.length > SHELL_DERIVE_MAX_PATH_LENGTH ||
    !match ||
    [match[1], match[3], match[4]].some(
      (index) => BigInt(index) > 0x7fffffffn,
    )
  ) {
    throw new Error("Invalid V3-R3 Privacy Pools derivation path");
  }
}

export function decodeShellDeriveRequest(payload: Uint8Array) {
  const bytes = Buffer.from(payload);
  const minimumLength = 5 + 16 + 65 + 1;

  if (
    bytes.length < minimumLength ||
    !bytes.subarray(0, 5).equals(REQUEST_PREFIX)
  ) {
    throw new Error("Invalid Shell derivation request");
  }

  const pathLength = bytes[86];

  if (
    pathLength === 0 ||
    pathLength > SHELL_DERIVE_MAX_PATH_LENGTH ||
    bytes.length !== minimumLength + pathLength
  ) {
    throw new Error("Invalid derivation request length");
  }

  const publicKey = bytes.subarray(21, 86);

  if (publicKey[0] !== 0x04) {
    throw new Error("Expected uncompressed secp256k1 public key");
  }

  const path = bytes.subarray(87).toString("ascii");
  validateShellDerivePath(path);

  return {
    challenge: Buffer.from(bytes.subarray(5, 21)),
    hostPublicKey: Buffer.from(publicKey),
    path,
  };
}

export function createShellDeriveRequest(path: string) {
  validateShellDerivePath(path);

  const ecdh = createECDH("secp256k1");
  ecdh.generateKeys();

  const challenge = randomBytes(SHELL_DERIVE_CHALLENGE_LENGTH);
  const publicKey = ecdh.getPublicKey(undefined, "uncompressed");
  const pathBytes = Buffer.from(path, "ascii");

  const request = Buffer.concat([
    REQUEST_PREFIX,
    challenge,
    publicKey,
    Buffer.from([pathBytes.length]),
    pathBytes,
  ]);

  const fingerprint = createHash("sha256")
    .update(publicKey)
    .digest("hex")
    .slice(0, 12);

  return {
    request,
    fingerprint,
    deriveSharedSecret(shellPublicKey: Uint8Array) {
      return ecdh.computeSecret(Buffer.from(shellPublicKey));
    },
  };
}
