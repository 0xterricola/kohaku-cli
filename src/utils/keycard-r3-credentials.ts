import { createHmac } from "node:crypto";

import {
  SecretManager as PrivacyPoolsSecretManager,
} from "@kohaku-eth/privacy-pools";

/**
 * Frozen Kohaku Key V3-R3 derivation contract.
 *
 * Keycard BIP-85 root -> versioned HMAC deriveAt adapter
 * -> legacy Privacy Pools SecretManager.
 *
 * This is not BIP-32, and it must not silently switch
 * to the SDK's SignatureSecretManager.
 */
export const KEYCARD_R3_HMAC_DOMAIN =
  "kohaku-key/v3-r3/privacy-pools-v1/deriveAt";

const R3_PATH =
  /^m\/28784'\/1'(?:\/[0-9]+')+$/;

export type KeycardR3CredentialProvider = {
  readonly secretManager:
    ReturnType<typeof PrivacyPoolsSecretManager>;

  deriveAt(path: string): Promise<`0x${string}`>;

  /**
   * Best-effort clearing of the adapter's own root copy.
   * JavaScript cannot guarantee erasure of all memory copies.
   */
  dispose(): void;
};

export function createKeycardR3CredentialProvider(
  bip85Root: Uint8Array,
  options: { accountIndex?: number } = {},
): KeycardR3CredentialProvider {
  if (
    !(bip85Root instanceof Uint8Array) ||
    bip85Root.byteLength !== 32
  ) {
    throw new Error("R3 requires a 32-byte BIP-85 root");
  }

  const accountIndex = options.accountIndex ?? 0;

  if (
    !Number.isSafeInteger(accountIndex) ||
    accountIndex < 0
  ) {
    throw new Error("Invalid R3 account index");
  }

  // Own a separate buffer so the caller can clear its IPC input.
  const key = Buffer.from(bip85Root);
  let disposed = false;

  const deriveAt = async (
    path: string,
  ): Promise<`0x${string}`> => {
    if (disposed) {
      throw new Error("R3 credential provider disposed");
    }

    if (!R3_PATH.test(path)) {
      throw new Error(
        "Derivation path outside R3 Privacy Pools namespace"
      );
    }

    const digest = createHmac("sha256", key)
      .update(KEYCARD_R3_HMAC_DOMAIN)
      .update("\0")
      .update(path)
      .digest("hex");

    return `0x${digest}`;
  };

  let secretManager:
    ReturnType<typeof PrivacyPoolsSecretManager>;

  try {
    // The legacy SDK manager consumes deriveAt(path).
    // No mnemonic or software-wallet fallback is provided.
    secretManager = PrivacyPoolsSecretManager({
      host: {
        keystore: { deriveAt },
      } as unknown as Parameters<
        typeof PrivacyPoolsSecretManager
      >[0]["host"],
      accountIndex,
    });
  } catch (error) {
    key.fill(0);
    disposed = true;
    throw error;
  }

  return {
    secretManager,
    deriveAt,

    dispose() {
      if (disposed) return;
      disposed = true;
      key.fill(0);
    },
  };
}
