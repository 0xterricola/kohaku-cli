import assert from "node:assert/strict";
import { test } from "node:test";
import {
  mkdtempSync, writeFileSync, readFileSync,
  rmSync, chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  hashMessage, parseSignature, recoverMessageAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createKeycardAccount } from "../src/utils/keycard-account.ts";

test("authentication failure requires explicit recovery", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kohaku-auth-recovery-"));

  try {
    const binary = join(dir, "bridge");
    const unavailable = join(dir, "unavailable");
    const calls = join(dir, "calls");
    const message = "explicit recovery test";
    const software = privateKeyToAccount(`0x${"11".repeat(32)}`);

    const signature = parseSignature(
      await software.signMessage({ message })
    );

    writeFileSync(unavailable, "1");

    writeFileSync(binary, `#!/bin/sh
case "$1" in
  get-address)
    printf 'get-address\\n' >> '${calls}'
    if [ -f '${unavailable}' ]; then
      echo 'simulated authentication interrupted' >&2
      exit 42
    fi
    printf '%s\\n' '${JSON.stringify({
      address: software.address,
      public_key: software.publicKey,
    })}'
    ;;
  sign-digest)
    printf 'sign-digest\\n' >> '${calls}'
    printf '%s\\n' '${JSON.stringify({
      signature_r: signature.r,
      signature_s: signature.s,
      signature_v: signature.yParity,
    })}'
    ;;
  *)
    exit 2
    ;;
esac
`);
    chmodSync(binary, 0o700);

    let reviews = 0;

    const reviewDigest = async ({ operation, digest }) => {
      assert.equal(operation, "EIP-191");
      assert.equal(digest, hashMessage(message));
      reviews++;
    };

    // Interrupted authentication must fail before signing.
    assert.throws(
      () => createKeycardAccount({
        binary,
        transport: "native",
        reviewDigest,
      }),
      (error) => {
        assert.equal(error.status, 42);
        assert.match(
          String(error.stderr),
          /simulated authentication interrupted/,
        );
        return true;
      },
    );

    assert.equal(readFileSync(calls, "utf8").trim(), "get-address");
    assert.equal(reviews, 0);

    // Simulate restoring the card. Recovery is explicitly initiated.
    rmSync(unavailable);

    const signer = createKeycardAccount({
      binary,
      transport: "native",
      reviewDigest,
    });

    const signed = await signer.signMessage({ message });

    assert.equal(
      await recoverMessageAddress({ message, signature: signed }),
      software.address,
    );
    assert.equal(reviews, 1);

    assert.deepEqual(
      readFileSync(calls, "utf8").trim().split("\n"),
      ["get-address", "get-address", "sign-digest"],
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
