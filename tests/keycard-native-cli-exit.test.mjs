import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { test } from "node:test";

const repo = fileURLToPath(new URL("../", import.meta.url));

test("non-interactive native signing fails before bridge execution", () => {
  const missing = join(repo, "native/keycard-bridge/missing-test-binary");
  assert.equal(existsSync(missing), false);

  const env = { ...process.env };
  delete env.KEYCARD_PIN;
  delete env.KEYCARD_PUK;
  delete env.KEYCARD_PAIRING_PASSWORD;

  const result = spawnSync(process.execPath, [
    "--import", "tsx", "src/index.ts", "transact-raw",
    "--signer", "keycard",
    "--keycard-transport", "native",
    "--keycard-bridge", missing,
    "--non-interactive",
    "--from", "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa",
    "--targets", "0x000000000000000000000000000000000000dEaD",
    "--payloads", "0x",
    "--values", "0",
    "--chain-id", "31337",
    "--nonce", "0",
    "--gas", "21000",
    "--max-fee-per-gas", "1000000000",
    "--max-priority-fee-per-gas", "100000000",
  ], {
    cwd: repo,
    env,
    encoding: "utf8",
    timeout: 30000,
  });

  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.match(result.stdout + result.stderr, /Interactive Keycard approval required/);
});

test("native signing rejects missing --from", () => {
  const binary = join(repo, "nonexistent-keycard-bridge");

  const env = { ...process.env };
  delete env.KEYCARD_PIN;
  delete env.KEYCARD_PUK;
  delete env.KEYCARD_PAIRING_PASSWORD;

  const result = spawnSync(process.execPath, [
    "--import", "tsx", "src/index.ts", "transact-raw",
    "--signer", "keycard",
    "--keycard-transport", "native",
    "--keycard-bridge", binary,
    "--non-interactive",
    "--targets", "0x000000000000000000000000000000000000dEaD",
    "--payloads", "0x",
    "--values", "0",
    "--chain-id", "31337",
    "--nonce", "0",
    "--gas", "21000",
    "--max-fee-per-gas", "1000000000",
    "--max-priority-fee-per-gas", "100000000",
  ], {
    cwd: repo,
    env,
    encoding: "utf8",
    timeout: 30000,
  });

  const output = result.stdout + result.stderr;

  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.match(output, /requires an explicit --from address/);
  assert.doesNotMatch(output, /ENOENT|Keycard PIN:/);
});
