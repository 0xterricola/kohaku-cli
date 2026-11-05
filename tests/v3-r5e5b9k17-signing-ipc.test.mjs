import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const source = readFileSync(
  "experiments/v3-r5e5b9k17-native-offline.mjs",
  "utf8",
);

const root = label =>
  createHash("sha256")
    .update(`kohaku-key/k17/public-fixture/${label}`)
    .digest();

async function execute(first, second, response) {
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
        "pipe",
        "pipe",
      ],
    },
  );

  let stdout = "";
  let stderr = "";
  let digest = Buffer.alloc(0);
  let replied = false;

  child.stdout.on("data", chunk => {
    stdout += chunk.toString();
  });

  child.stderr.on("data", chunk => {
    stderr += chunk.toString();
  });

  child.stdio[5].on("error", () => {});

  child.stdio[4].on("data", chunk => {
    digest = Buffer.concat([digest, chunk]);

    if (digest.length >= 32 && !replied) {
      replied = true;

      assert.equal(digest.length, 32);
      child.stdio[5].end(response);
    }
  });

  child.stdio[4].on("end", () => {
    if (!replied) {
      replied = true;
      child.stdio[5].end();
    }
  });

  child.stdio[3].end(
    Buffer.concat([first, second])
  );

  const [code] = await once(child, "close");

  return { code, stdout, stderr, digest };
}

test("K17 rejects mismatched credential sessions", async () => {
  const result = await execute(
    root("first"),
    root("second"),
    Buffer.alloc(65),
  );

  assert.notEqual(result.code, 0);
  assert.equal(result.digest.length, 0);

  assert.match(
    result.stderr,
    /Independent hardware roots differ/,
  );

  console.log("PASS: Root mismatch refused");
});

test("K17 rejects missing hardware signature", async () => {
  const r = root("matching");

  const result = await execute(
    r,
    r,
    Buffer.alloc(0),
  );

  assert.notEqual(result.code, 0);
  assert.equal(result.digest.length, 32);

  assert.match(
    result.stderr,
    /Incomplete hardware signature IPC/,
  );

  console.log("PASS: Missing signature refused");
});

test("K17 rejects invalid hardware signature", async () => {
  const r = root("matching");

  const result = await execute(
    r,
    r,
    Buffer.alloc(65),
  );

  assert.notEqual(result.code, 0);
  assert.equal(result.digest.length, 32);

  assert.match(
    result.stderr,
    /Invalid signature R/,
  );

  assert.doesNotMatch(
    result.stdout,
    /PASS: R5-E5B9K17/,
  );

  console.log("PASS: Invalid signature refused");
});
