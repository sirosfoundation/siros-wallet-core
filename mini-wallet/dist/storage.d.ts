import type { WalletStorage } from "./types.js";
/** The browser localStorage backend — the default, unencrypted for now.
 *  The namespace keeps unrelated page storage out of the wallet's (and
 *  the migration's) way. */
export declare class LocalStorageWalletStorage implements WalletStorage {
    #private;
    constructor(namespace?: string, store?: typeof localStorage);
    get(key: string): Promise<string | null>;
    put(key: string, value: string): Promise<void>;
    del(key: string): Promise<void>;
    list(prefix?: string): Promise<string[]>;
}
/** The in-memory backend — the no-storage fallback (the wallet works,
 *  nothing survives the reload) and the test bench. */
export declare class MemoryWalletStorage implements WalletStorage {
    #private;
    get(key: string): Promise<string | null>;
    put(key: string, value: string): Promise<void>;
    del(key: string): Promise<void>;
    list(prefix?: string): Promise<string[]>;
}
/** The in-memory localStorage stand-in (the LocalStorageWalletStorage
 *  constructor's fallback + the tests' injection). */
export declare function memoryStore(): typeof localStorage;
