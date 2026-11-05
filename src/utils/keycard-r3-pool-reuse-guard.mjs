const SCHEMA =
  "kohaku-key/r5-e5b9k21r6/pools-v1";

function integer(value) {
  if (
    typeof value !== "string" ||
    !/^(0x[0-9a-f]+|[0-9]+)$/i.test(value)
  ) {
    throw new Error("Invalid public-history integer");
  }

  return BigInt(value);
}

function address(value) {
  if (
    typeof value !== "string" ||
    !/^0x[0-9a-f]{40}$/i.test(value)
  ) {
    throw new Error("Invalid public pool address");
  }

  return value.toLowerCase();
}

/**
 * Validates the public archive against the currently
 * checked-in bundled snapshot.
 *
 * Does not establish independent historical completeness.
 */
export function verifyR3PoolHistory(
  archive,
  source,
) {
  if (
    archive?.schema !== SCHEMA ||
    archive.chainId !== 11155111 ||
    address(archive.entrypoint) !==
      address(source.entrypoint) ||
    archive.snapshotSha !== source.sha256 ||
    !/^[a-f0-9]{64}$/i.test(
      archive.snapshotSha ?? ""
    )
  ) {
    throw new Error(
      "Public-history identity mismatch"
    );
  }

  if (
    integer(archive.snapshotHead) !==
      source.snapshotHead
  ) {
    throw new Error(
      "Public-history snapshot head mismatch"
    );
  }

  if (
    !Array.isArray(archive.snapshotKeys) ||
    archive.snapshotKeys.length !==
      source.snapshotKeys.length ||
    !archive.snapshotKeys.every(
      (value, index) =>
        value === source.snapshotKeys[index]
    )
  ) {
    throw new Error(
      "Public-history snapshot contents mismatch"
    );
  }

  if (
    !Array.isArray(archive.poolAddresses) ||
    archive.poolAddresses.length === 0 ||
    !Array.isArray(source.snapshotPools) ||
    source.snapshotPools.length === 0
  ) {
    throw new Error(
      "Public-history pool evidence missing"
    );
  }

  const pools = archive.poolAddresses.map(address);

  if (
    new Set(pools).size !== pools.length
  ) {
    throw new Error(
      "Duplicate public pool addresses"
    );
  }

  const poolSet = new Set(pools);

  for (const pool of source.snapshotPools) {
    if (!poolSet.has(address(pool))) {
      throw new Error(
        "Bundled pool missing from public history"
      );
    }
  }

  if (
    !Array.isArray(archive.recentKeys) ||
    !Array.isArray(archive.ranges) ||
    archive.ranges.length === 0
  ) {
    throw new Error(
      "Public-history coverage evidence missing"
    );
  }

  let next = source.snapshotHead + 1n;
  let count = 0;

  for (const range of archive.ranges) {
    const from = integer(range.from);
    const to = integer(range.to);

    if (
      from !== next ||
      to < from ||
      to - from + 1n > 500n ||
      !Number.isSafeInteger(range.count) ||
      range.count < 0
    ) {
      throw new Error(
        "Public-history coverage gap"
      );
    }

    count += range.count;
    next = to + 1n;
  }

  const checkedThrough =
    integer(archive.checkedThrough);

  const targetHead =
    integer(archive.targetHead);

  if (
    checkedThrough !== next - 1n ||
    checkedThrough !== targetHead ||
    checkedThrough <= source.snapshotHead ||
    count !== archive.recentKeys.length
  ) {
    throw new Error(
      "Public-history coverage incomplete"
    );
  }

  for (const value of [
    ...archive.snapshotKeys,
    ...archive.recentKeys,
  ]) {
    if (integer(value) <= 0n) {
      throw new Error(
        "Invalid public deposit precommitment"
      );
    }
  }

  return {
    snapshotCount: archive.snapshotKeys.length,
    recentCount: archive.recentKeys.length,
    poolCount: pools.length,
    checkedThrough: checkedThrough.toString(),
    archiveValidated: true,
  };
}

/**
 * All comparisons are local. Never send this candidate
 * to an RPC method, log it, or persist it.
 */
export function assertR3CredentialUnused(
  precommitment,
  archive,
) {
  if (
    typeof precommitment !== "bigint" ||
    precommitment <= 0n
  ) {
    throw new Error(
      "Invalid hardware precommitment"
    );
  }

  for (const value of archive.snapshotKeys) {
    if (integer(value) === precommitment) {
      throw new Error(
        "Hardware credential reuse detected in snapshot"
      );
    }
  }

  for (const value of archive.recentKeys) {
    if (integer(value) === precommitment) {
      throw new Error(
        "Hardware credential reuse detected after snapshot"
      );
    }
  }

  return true;
}
