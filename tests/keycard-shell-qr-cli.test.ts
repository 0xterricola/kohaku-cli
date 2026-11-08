import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createCipheriv,
  createECDH,
  createHash,
  createHmac,
  randomBytes,
} from "node:crypto";
import { Command } from "commander";

import {
  registerKeycardShellQrCommand,
} from "../src/commands/keycard-shell-qr.js";
import {
  decodeShellBatchRequest,
} from "../src/utils/keycard-shell-qr-batch.js";
import {
  deriveShellDeriveAesKey,
} from "../src/utils/keycard-shell-qr-derive-response.js";

test("CLI credential modes use encrypted Shell exchange", async () => {
  const root = Buffer.alloc(32, 0x42);
  const requested: string[][] = [];
  const logs: string[] = [];
  const originalLog = console.log;

  console.log = (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  };

  try {
    for (const mode of ["deposit", "withdrawal", "signer"]) {
      const program = new Command();

      registerKeycardShellQrCommand(
        program,
        async (request, fingerprint) => {
          const parsed = decodeShellBatchRequest(request);
          requested.push(parsed.paths);

          assert.equal(
            fingerprint,
            createHash("sha256")
              .update(parsed.hostPublicKey)
              .digest("hex")
              .slice(0, 16),
          );

          const shell = createECDH("secp256k1");
          shell.generateKeys();

          const publicKey = shell.getPublicKey(
            undefined,
            "uncompressed",
          );
          const shared = shell.computeSecret(parsed.hostPublicKey);
          const nonce = randomBytes(13);
          const key = deriveShellDeriveAesKey(
            shared,
            request,
            publicKey,
            nonce,
          );

          const credentials = parsed.paths.map((path) =>
            createHmac("sha256", root)
              .update("kohaku-key/v3-r3/privacy-pools-v1/deriveAt")
              .update("\0")
              .update(path)
              .digest(),
          );

          const plaintext = Buffer.concat([
            Buffer.from([credentials.length]),
            ...credentials,
          ]);

          try {
            const cipher = createCipheriv(
              "aes-128-ccm",
              key,
              nonce,
              { authTagLength: 8 },
            );

            const ciphertext = Buffer.concat([
              cipher.update(plaintext),
              cipher.final(),
            ]);

            return Buffer.concat([
              Buffer.from("KKR3\x03", "binary"),
              parsed.challenge,
              publicKey,
              nonce,
              ciphertext,
              cipher.getAuthTag(),
            ]);
          } finally {
            shared.fill(0);
            key.fill(0);
            plaintext.fill(0);
            credentials.forEach((credential) => credential.fill(0));
          }
        },
      );

      const args = [
        "keycard-shell-qr",
        "--credential-mode", mode,
        "--entrypoint",
        "0x0000000000000000000000000000000000000001",
        "--deposit-index", "17",
      ];

      if (mode !== "deposit") {
        args.push("--withdraw-index", "1");
      }

      await program.parseAsync(args, { from: "user" });

      assert.ok(
        logs.some((line) =>
          line.includes(`PASS: ${mode} credentials derived`),
        ),
      );
    }

    assert.deepEqual(requested, [
      [
        "m/28784'/1'/0'/1'/17'/0'",
        "m/28784'/1'/0'/0'/17'/0'",
      ],
      [
        "m/28784'/1'/0'/1'/17'/1'",
        "m/28784'/1'/0'/0'/17'/1'",
      ],
      [
        "m/28784'/1'/0'/2'/17'/1'",
      ],
    ]);

    assert.ok(
      logs.every((line) => !/0x[0-9a-f]{64}/i.test(line)),
      "CLI must not print credential values",
    );
  } finally {
    console.log = originalLog;
    root.fill(0);
  }
});
