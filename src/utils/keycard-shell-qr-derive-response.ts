import {
  createDecipheriv,
  createHash,
  hkdfSync,
  timingSafeEqual,
} from "node:crypto";

export const SHELL_DERIVE_RESPONSE_LENGTH = 139;
const RESPONSE_PREFIX = Buffer.from("KKR2\x02", "binary");
const SALT_DOMAIN = Buffer.from(
  "kohaku-key/v4-qr-derive-v1/salt\0",
  "ascii",
);
const KEY_DOMAIN = Buffer.from(
  "kohaku-key/v4-qr-derive-v1/aes128-ccm",
  "ascii",
);

export function deriveShellDeriveAesKey(
  sharedSecret: Uint8Array,
  request: Uint8Array,
  shellPublicKey: Uint8Array,
  nonce: Uint8Array,
): Buffer {
  if (
    sharedSecret.length !== 32 ||
    shellPublicKey.length !== 65 ||
    nonce.length !== 13
  ) {
    throw new Error("Invalid Shell encryption parameters");
  }

  const salt = createHash("sha256")
    .update(SALT_DOMAIN)
    .update(request)
    .update(shellPublicKey)
    .update(nonce)
    .digest();

  try {
    return Buffer.from(
      hkdfSync("sha256", sharedSecret, salt, KEY_DOMAIN, 16),
    );
  } finally {
    salt.fill(0);
  }
}

export function decryptShellDeriveResponse(
  session: {
    request: Uint8Array;
    deriveSharedSecret(publicKey: Uint8Array): Buffer;
  },
  response: Uint8Array,
): Buffer {
  const bytes = Buffer.from(response);
  const request = Buffer.from(session.request);

  if (
    bytes.length !== SHELL_DERIVE_RESPONSE_LENGTH ||
    !bytes.subarray(0, 5).equals(RESPONSE_PREFIX) ||
    request.length < 87
  ) {
    throw new Error("Invalid Shell derivation response");
  }

  if (
    !timingSafeEqual(
      request.subarray(5, 21),
      bytes.subarray(5, 21),
    )
  ) {
    throw new Error("Shell response challenge mismatch");
  }

  const shellPublicKey = bytes.subarray(21, 86);
  const nonce = bytes.subarray(86, 99);
  const ciphertext = bytes.subarray(99, 131);
  const tag = bytes.subarray(131, 139);

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
      { authTagLength: 8 },
    );

    decipher.setAuthTag(tag);

    const credential = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    if (credential.length !== 32) {
      credential.fill(0);
      throw new Error("Invalid credential length");
    }

    return credential;
  } finally {
    sharedSecret.fill(0);
    key?.fill(0);
  }
}
