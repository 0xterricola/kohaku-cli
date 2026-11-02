import assert from "node:assert/strict";
import { test } from "node:test";
import {
  mkdtempSync, writeFileSync, readFileSync,
  existsSync, chmodSync, rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  hashTypedData, parseSignature, recoverTypedDataAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createKeycardAccount } from "../src/utils/keycard-account.ts";

test("EIP-712 approval binds exact bridge digest", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kohaku-eip712-"));
  const binary = join(dir, "bridge");
  const marker = join(dir, "sign-called");

  try {
    const software = privateKeyToAccount(`0x${"11".repeat(32)}`);

    const typedData = {
      domain: {
        name: "Kohaku V2 Test",
        version: "1",
        chainId: 31337,
      },
      types: {
        Review: [
          { name: "recipient", type: "address" },
          { name: "value", type: "uint256" },
        ],
      },
      primaryType: "Review",
      message: {
        recipient: "0x000000000000000000000000000000000000dEaD",
        value: 0n,
      },
    };

    const digest = hashTypedData(typedData);
    const signature = parseSignature(
      await software.signTypedData(typedData)
    );

    const exported = JSON.stringify({
      address: software.address,
      public_key: software.publicKey,
    });

    const signed = JSON.stringify({
      signature_r: signature.r,
      signature_s: signature.s,
      signature_v: signature.yParity,
    });

    writeFileSync(binary, `#!/bin/sh
case "$1" in
  get-address)
    printf '%s\\n' '${exported}'
    ;;
  sign-digest)
    shift
    digest=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--hex" ]; then
        digest="$2"
        shift 2
      else
        shift
      fi
    done
    [ "$digest" = "${digest}" ] || exit 96
    printf 'signed\\n' >> '${marker}'
    printf '%s\\n' '${signed}'
    ;;
  *)
    exit 97
    ;;
esac
`);
    chmodSync(binary, 0o700);

    let approved = false;
    let reviews = 0;

    const account = createKeycardAccount({
      binary,
      transport: "native",
      reviewDigest: async (review) => {
        assert.equal(review.operation, "EIP-712");
        assert.equal(review.digest, digest);
        assert.deepEqual(review.payload, typedData);
        reviews++;

        if (!approved) throw new Error("Digest rejected");
      },
    });

    await assert.rejects(
      account.signTypedData(typedData),
      /Digest rejected/
    );

    assert.equal(existsSync(marker), false);

    approved = true;
    const result = await account.signTypedData(typedData);

    const recovered = await recoverTypedDataAddress({
      ...typedData,
      signature: result,
    });

    assert.equal(recovered, software.address);
    assert.equal(readFileSync(marker, "utf8").trim(), "signed");
    assert.equal(reviews, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
