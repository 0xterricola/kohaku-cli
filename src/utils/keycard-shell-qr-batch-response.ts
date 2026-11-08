import {
  createDecipheriv,
  timingSafeEqual,
} from "node:crypto";

import {
  decodeShellBatchRequest,
} from "./keycard-shell-qr-batch.js";

import {
  deriveShellDeriveAesKey,
} from "./keycard-shell-qr-derive-response.js";

const RESPONSE_PREFIX = Buffer.from([
  0x4b, 0x4b, 0x52, 0x33, 0x03,
]);

const CREDENTIAL_LENGTH = 32;
const TAG_LENGTH = 8;
const NONCE_LENGTH = 13;
const PUBLIC_KEY_LENGTH = 65;

export function decryptShellBatchResponse(
  session: {
    request: Uint8Array;
    deriveSharedSecret(publicKey: Uint8Array): Buffer;
  },
  response: Uint8Array,
): Buffer[] {
  const request = Buffer.from(session.request);
  const { challenge, paths } = decodeShellBatchRequest(request);
  const bytes = Buffer.from(response);

  const headerLength =
    5 + 16 + PUBLIC_KEY_LENGTH + NONCE_LENGTH;

  const plaintextLength = 1 + paths.length * CREDENTIAL_LENGTH;

  if (
    bytes.length !== headerLength + plaintextLength + TAG_LENGTH ||
    !bytes.subarray(0, 5).equals(RESPONSE_PREFIX)
  ) {
    throw new Error("Invalid Shell batch response");
  }

  if (!timingSafeEqual(challenge, bytes.subarray(5, 21))) {
    throw new Error("Shell batch challenge mismatch");
  }

  const shellPublicKey = bytes.subarray(21, 86);
  const nonce = bytes.subarray(86, 99);
  const ciphertext = bytes.subarray(
    headerLength,
    headerLength + plaintextLength,
  );
  const tag = bytes.subarray(headerLength + plaintextLength);

  if (shellPublicKey[0] !== 0x04) {
    throw new Error("Invalid Shell public key");
  }

  const sharedSecret = session.deriveSharedSecret(shellPublicKey);
  let key: Buffer | undefined;

  try {
    key = deriveShellDeriveAesKey(
      sharedSecret,
      request,
      shellPublicKey,
      nonce,
    );

    const decipher = createDecipheriv(
      "aes-128-ccm",
      key,
      nonce,
      { authTagLength: TAG_LENGTH },
    );

    decipher.setAuthTag(tag);

    const plaintext = decipher.update(ciphertext);

    try {
      decipher.final();

      if (
        plaintext.length !== plaintextLength ||
        plaintext[0] !== paths.length
      ) {
        throw new Error("Invalid decrypted credential batch");
      }

      return paths.map((_, index) => {
        const start = 1 + index * CREDENTIAL_LENGTH;
        return Buffer.from(
          plaintext.subarray(start, start + CREDENTIAL_LENGTH),
        );
      });
    } finally {
      plaintext.fill(0);
    }
  } finally {
    sharedSecret.fill(0);
    key?.fill(0);
  }
}
