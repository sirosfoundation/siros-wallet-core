// The storage migration — the design brief's deferred onboarding: a
// wallet that initialized and received credentials with NO passkey
// adopts one later, and the unencrypted backend swaps for the
// passkey-encrypted one (a PRF-derived key, @smncd's private-data
// library) WITHOUT losing anything.
//
// The contract is deliberately dumb: a migration copies every key's
// bytes to the target, verifies the copy, then deletes the source. The
// encryption is the TARGET backend's business — the migration never
// sees a plaintext it has to understand, so the future passkey backend
// (or any other) plugs in without this file changing.

import type { WalletStorage } from "./types.js";

export interface MigrationReport {
  /** The keys copied (source names). */
  keys: string[];
  /** A key that failed to copy — the migration aborts BEFORE deleting
   *  anything when one appears. */
  failed?: string;
}

/**
 * Copy every key from `source` to `target`, verifying each write, then
 * delete the source's copies. The wallet is offline for the duration;
 * on any failure the source stays intact (the delete pass runs only
 * after every key verified).
 */
export async function migrateWalletStorage(
  source: WalletStorage,
  target: WalletStorage,
): Promise<MigrationReport> {
  const keys = await source.list();
  const report: MigrationReport = { keys };
  for (const key of keys) {
    const value = await source.get(key);
    if (value === null) continue; // raced away; nothing to copy
    await target.put(key, value);
    // Verify before the delete pass: a target that lost the write is
    // a failure, never a silent data loss.
    const back = await target.get(key);
    if (back !== value) {
      report.failed = key;
      return report;
    }
  }
  // (A failure returned inside the loop above; nothing can be failed here.)
  for (const key of keys) await source.del(key);
  return report;
}
