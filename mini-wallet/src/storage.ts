// The storage backends. The design brief: pluggable, with a simple
// browser-localStorage implementation now and @smncd's private-data
// library (a passkey + a PRF-derived key) when it lands — the wallet
// initializes and receives credentials BEFORE any onboarding, and the
// passkey arrives later as a storage MIGRATION (see migration.ts).
//
// The wallet never parses a stored value; the keys are the wallet's own
// namespaced strings (`mw:<id>:credential:<uuid>`, `mw:<id>:stash:*`,
// `mw:<id>:key:*`), so a migration copies bytes and nothing else.

import type { WalletStorage } from "./types.js";

/** The browser localStorage backend — the default, unencrypted for now.
 *  The namespace keeps unrelated page storage out of the wallet's (and
 *  the migration's) way. */
export class LocalStorageWalletStorage implements WalletStorage {
  readonly #ns: string;
  readonly #store: { getItem(k: string): string | null; setItem(k: string, v: string): void; removeItem(k: string): void; length: number; key(i: number): string | null };

  constructor(namespace = "mini-wallet", store?: typeof localStorage) {
    this.#ns = namespace;
    // The injectable store: the browser's localStorage by default, a
    // test's in-memory map otherwise.
    this.#store = store ?? (typeof localStorage !== "undefined" ? localStorage : memoryStore());
  }

  #k(key: string): string {
    return `${this.#ns}:${key}`;
  }

  async get(key: string): Promise<string | null> {
    return this.#store.getItem(this.#k(key));
  }

  async put(key: string, value: string): Promise<void> {
    this.#store.setItem(this.#k(key), value);
  }

  async del(key: string): Promise<void> {
    this.#store.removeItem(this.#k(key));
  }

  async list(prefix?: string): Promise<string[]> {
    const at = this.#k(prefix ?? "");
    const out: string[] = [];
    for (let i = 0; i < this.#store.length; i += 1) {
      const full = this.#store.key(i);
      if (full !== null && full.startsWith(at)) out.push(full.slice(this.#ns.length + 1));
    }
    return out;
  }
}

/** The in-memory backend — the no-storage fallback (the wallet works,
 *  nothing survives the reload) and the test bench. */
export class MemoryWalletStorage implements WalletStorage {
  readonly #map = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.#map.get(key) ?? null;
  }

  async put(key: string, value: string): Promise<void> {
    this.#map.set(key, value);
  }

  async del(key: string): Promise<void> {
    this.#map.delete(key);
  }

  async list(prefix?: string): Promise<string[]> {
    const keys = [...this.#map.keys()];
    return prefix === undefined ? keys : keys.filter((k) => k.startsWith(prefix));
  }
}

/** The in-memory localStorage stand-in (the LocalStorageWalletStorage
 *  constructor's fallback + the tests' injection). */
export function memoryStore(): typeof localStorage {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    get length() {
      return map.size;
    },
    key: (i: number) => [...map.keys()][i] ?? null,
  } as unknown as typeof localStorage;
}
