import assert from "node:assert/strict";
import { test } from "node:test";
import {
  mkdtempSync, writeFileSync, readFileSync, rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { createKeycardAccount } from "../src/utils/keycard-account.ts";

test("native signer fails closed on simulated card removal", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kohaku-disconnect-"));

  try {
    const binary = join(dir, "bridge");
    const attempts = join(dir, "attempts");
    const account = privateKeyToAccount(`0x${"11".repeat(32)}`);

    writeFileSync(binary, `#!/bin/sh
case "$1" in
  get-address)
    printf '%s\\n' '${JSON.stringify({
      address: account.address,
      public_key: account.publicKey,
    })}'
    ;;
  sign-digest)
    printf 'attempt\\n' >> '${attempts}'
    echo 'simulated SCARD_W_REMOVED_CARD' >&2
    exit 31
    ;;
  *)
    exit 2
    ;;
esac
`, { mode: 0o700 });

    const signer = createKeycardAccount({
      binary,
      transport: "native",
    });

    assert.equal(signer.address, account.address);

    await assert.rejects(
      signer.signMessage({ message: "disconnect test" }),
      (error) => {
        assert.equal(error.status, 31);
        assert.match(
          String(error.stderr),
          /SCARD_W_REMOVED_CARD/,
        );
        return true;
      },
    );

    assert.equal(
      readFileSync(attempts, "utf8").trim(),
      "attempt",
      "Disconnected signing must not retry automatically",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
