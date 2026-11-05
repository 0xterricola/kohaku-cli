import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const source = readFileSync(
  "experiments/v3-r5e5b9k18-sepolia-preview.mjs",
  "utf8"
);

const root = label =>
  createHash("sha256")
    .update(`kohaku-key/k18/public-fixture/${label}`)
    .digest();

async function execute(payload) {
  const child = spawn(
    process.execPath,
    [
      "--import", "tsx",
      "--input-type=module",
      "--eval", source,
    ],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        NODE_OPTIONS: "",
      },
      stdio: [
        "ignore",
        "pipe",
        "pipe",
        "pipe",
      ],
    },
  );

  let stdout = "";
  let stderr = "";

  child.stdout.on("data", chunk => {
    stdout += chunk.toString();
  });

  child.stderr.on("data", chunk => {
    stderr += chunk.toString();
  });

  child.stdio[3].end(payload);

  const [code] = await once(child, "close");

  return { code, stdout, stderr };
}

test("K18 reproduces unsigned Sepolia calldata", async () => {
  const fixture = root("matching");

  const result = await execute(
    Buffer.concat([fixture, fixture])
  );

  assert.equal(result.code, 0, result.stderr);

  assert.match(
    result.stdout,
    /PASS: R5-E5B9K18/
  );

  assert.match(
    result.stdout,
    /"chainId": 11155111/
  );

  assert.match(
    result.stdout,
    /"calldataVerified": true/
  );

  assert.match(
    result.stdout,
    /"transactionConstructed": false/
  );

  assert.match(
    result.stdout,
    /"broadcast": false/
  );

  assert.ok(
    !result.stdout.includes(
      fixture.toString("hex")
    )
  );

  console.log(
    "PASS: Deterministic Sepolia preview"
  );
});

test("K18 rejects mismatched hardware roots", async () => {
  const result = await execute(
    Buffer.concat([
      root("first"),
      root("second"),
    ])
  );

  assert.notEqual(result.code, 0);

  assert.match(
    result.stderr,
    /Independent hardware roots differ/
  );

  console.log("PASS: Root mismatch rejected");
});

test("K18 rejects truncated credential IPC", async () => {
  const result = await execute(
    root("truncated")
  );

  assert.notEqual(result.code, 0);

  assert.match(
    result.stderr,
    /Incomplete hardware credential IPC/
  );

  console.log("PASS: Truncated IPC rejected");
});
