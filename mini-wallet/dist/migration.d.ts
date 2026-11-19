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
export declare function migrateWalletStorage(source: WalletStorage, target: WalletStorage): Promise<MigrationReport>;
