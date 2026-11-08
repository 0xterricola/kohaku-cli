import {
  SecretManager as PrivacyPoolsSecretManager,
} from "@kohaku-eth/privacy-pools";

import {
  createShellBatchRequest,
} from "./keycard-shell-qr-batch.js";

import {
  decryptShellBatchResponse,
} from "./keycard-shell-qr-batch-response.js";

export type ShellQrExchange = (
  request: Uint8Array,
  fingerprint: string,
) => Promise<Uint8Array>;

function checkIndex(index: number): void {
  if (
    !Number.isSafeInteger(index) ||
    index < 0 ||
    index > 0x7fffffff
  ) {
    throw new Error("Invalid Privacy Pools derivation index");
  }
}

export function createShellQrR3Provider(
  exchange: ShellQrExchange,
  options: { accountIndex?: number } = {},
) {
  const accountIndex = options.accountIndex ?? 0;
  checkIndex(accountIndex);

  const prefix = `m/28784'/1'/${accountIndex}'`;
  const pending = new Map<string, Buffer>();

  let busy = false;
  let disposed = false;

  const path = (
    secretType: 0 | 1 | 2,
    depositIndex: number,
    secretIndex: number,
  ) => {
    checkIndex(depositIndex);
    checkIndex(secretIndex);
    return `${prefix}/${secretType}'/${depositIndex}'/${secretIndex}'`;
  };

  const deriveAt = async (requested: string): Promise<`0x${string}`> => {
    if (disposed) {
      throw new Error("Shell QR provider disposed");
    }

    const credential = pending.get(requested);
    if (!credential) {
      throw new Error("Credential not authorized for this QR exchange");
    }

    pending.delete(requested);

    try {
      return `0x${credential.toString("hex")}`;
    } finally {
      credential.fill(0);
    }
  };

  const legacy = PrivacyPoolsSecretManager({
    host: {
      keystore: { deriveAt },
    } as unknown as Parameters<
      typeof PrivacyPoolsSecretManager
    >[0]["host"],
    accountIndex,
  });

  const clearPending = () => {
    for (const credential of pending.values()) {
      credential.fill(0);
    }
    pending.clear();
  };

  const withBatch = async <T>(
    paths: string[],
    execute: () => Promise<T>,
  ): Promise<T> => {
    if (disposed || busy) {
      throw new Error("Shell QR provider unavailable");
    }

    busy = true;

    try {
      const session = createShellBatchRequest(paths);
      const response = await exchange(
        session.request,
        session.fingerprint,
      );

      const credentials = decryptShellBatchResponse(
        session,
        response,
      );

      try {
        for (let i = 0; i < paths.length; i++) {
          pending.set(paths[i], Buffer.from(credentials[i]));
        }
      } finally {
        credentials.forEach((credential) => credential.fill(0));
      }

      return await execute();
    } finally {
      clearPending();
      busy = false;
    }
  };

  const secretManager: ReturnType<
    typeof PrivacyPoolsSecretManager
  > = {
    ...legacy,

    getDepositSecrets: (coordinates) =>
      withBatch(
        [
          path(1, coordinates.depositIndex, 0),
          path(0, coordinates.depositIndex, 0),
        ],
        () => legacy.getDepositSecrets(coordinates),
      ),

    getSecrets: (coordinates) =>
      withBatch(
        [
          path(1, coordinates.depositIndex, coordinates.withdrawIndex),
          path(0, coordinates.depositIndex, coordinates.withdrawIndex),
        ],
        () => legacy.getSecrets(coordinates),
      ),

    deriveEphemeralSigner: (coordinates) =>
      withBatch(
        [
          path(2, coordinates.depositIndex, coordinates.withdrawIndex),
        ],
        () => legacy.deriveEphemeralSigner(coordinates),
      ),

    deriveDelegatorSigner: async () => {
      throw new Error(
        "Classical wallet derivation unsupported by Shell QR R3",
      );
    },
  };

  return {
    accountIndex,
    secretManager,
    dispose() {
      disposed = true;
      clearPending();
    },
  };
}
