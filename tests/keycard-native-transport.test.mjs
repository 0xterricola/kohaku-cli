import assert from "node:assert/strict";
import { test } from "node:test";
import {
  mkdtempSync,
  writeFileSync,
  chmodSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  isAddressEqual,
  parseSignature,
  recoverMessageAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { createKeycardAccount } from
  "../src/utils/keycard-account.ts";

test("native transport signs without forwarding credentials", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kohaku-native-test-"));
  const binary = join(dir, "fake-bridge");

  try {
    // Disposable test key; never fund this account.
    const software = privateKeyToAccount(
      `0x${"11".repeat(32)}`
    );
    const message = "Kohaku native bridge regression";
    const signature = await software.signMessage({ message });
    const parsed = parseSignature(signature);

    const exported = {
      address: software.address,
      public_key: software.publicKey,
    };

    const signed = {
      signature_r: parsed.r,
      signature_s: parsed.s,
      signature_v: parsed.yParity,
    };

    // Simulates the bridge contract, not physical hardware.
    // Fail if Node forwards a legacy credential.
    const script = `#!/bin/sh
[ -z "\${KEYCARD_PIN+x}" ] || exit 90
[ -z "\${KEYCARD_PUK+x}" ] || exit 91
[ -z "\${KEYCARD_PAIRING_PASSWORD+x}" ] || exit 92

case "$*" in
  *--json*|*--log-level*) exit 93 ;;
esac

case "$1" in
  get-address)
    printf '%s\\n' '${JSON.stringify(exported)}'
    ;;
  sign-digest)
    printf '%s\\n' '${JSON.stringify(signed)}'
    ;;
  *)
    exit 94
    ;;
esac
`;

    writeFileSync(binary, script, { mode: 0o700 });
    chmodSync(binary, 0o700);

    const account = createKeycardAccount({
      binary,
      transport: "native",
    });

    assert.ok(isAddressEqual(
      account.address,
      software.address
    ));

    const result = await account.signMessage({ message });

    const recovered = await recoverMessageAddress({
      message,
      signature: result,
    });

    assert.ok(isAddressEqual(
      recovered,
      software.address
    ));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
