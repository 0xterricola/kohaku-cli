import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { once } from "node:events";
import { test } from "node:test";

const source = readFileSync(
  "experiments/v3-r5e5b9k16-hardware-r3-offline.mjs",
  "utf8",
);

const root = label =>
  createHash("sha256")
    .update(`kohaku-key/k16/public-fixture/${label}`)
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

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");

  child.stdout.on("data", data => {
    stdout += data;
  });

  child.stderr.on("data", data => {
    stderr += data;
  });

  child.stdio[3].end(payload);

  const [code] = await once(child, "close");

  return { code, stdout, stderr };
}

test("FD3 reconstructs matching public fixture credentials", async () => {
  const a = root("matching");
  const result = await execute(Buffer.concat([a, a]));

  assert.equal(result.code, 0, result.stderr);

  assert.match(
    result.stdout,
    /PASS: R5-E5B9K16/,
  );

  assert.match(
    result.stdout,
    /"hardwareCredentials": true/,
  );

  assert.match(
    result.stdout,
    /"broadcast": false/,
  );

  assert.ok(
    !result.stdout.includes(a.toString("hex"))
  );

  assert.ok(
    !result.stderr.includes(a.toString("hex"))
  );

  console.log(
    "PASS: Synthetic FD3 credential reconstruction"
  );
});

test("FD3 refuses mismatched hardware sessions", async () => {
  const result = await execute(
    Buffer.concat([
      root("first"),
      root("second"),
    ]),
  );

  assert.notEqual(result.code, 0);

  assert.match(
    result.stderr,
    /Independent hardware roots differ/,
  );

  assert.doesNotMatch(
    result.stdout,
    /PASS: R5-E5B9K16/,
  );

  console.log("PASS: Root mismatch rejected");
});

test("FD3 refuses truncated credential input", async () => {
  const result = await execute(root("truncated"));

  assert.notEqual(result.code, 0);

  assert.match(
    result.stderr,
    /Incomplete hardware credential IPC/,
  );

  assert.doesNotMatch(
    result.stdout,
    /PASS: R5-E5B9K16/,
  );

  console.log("PASS: Truncated IPC rejected");
});
