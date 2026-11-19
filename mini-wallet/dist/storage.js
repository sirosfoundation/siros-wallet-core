// The storage backends. The design brief: pluggable, with a simple
// browser-localStorage implementation now and @smncd's private-data
// library (a passkey + a PRF-derived key) when it lands — the wallet
// initializes and receives credentials BEFORE any onboarding, and the
// passkey arrives later as a storage MIGRATION (see migration.ts).
//
// The wallet never parses a stored value; the keys are the wallet's own
// namespaced strings (`mw:<id>:credential:<uuid>`, `mw:<id>:stash:*`,
// `mw:<id>:key:*`), so a migration copies bytes and nothing else.
/** The browser localStorage backend — the default, unencrypted for now.
 *  The namespace keeps unrelated page storage out of the wallet's (and
 *  the migration's) way. */
export class LocalStorageWalletStorage {
    #ns;
    #store;
    constructor(namespace = "mini-wallet", store) {
        this.#ns = namespace;
        // The injectable store: the browser's localStorage by default, a
        // test's in-memory map otherwise.
        this.#store = store ?? (typeof localStorage !== "undefined" ? localStorage : memoryStore());
    }
    #k(key) {
        return `${this.#ns}:${key}`;
    }
    async get(key) {
        return this.#store.getItem(this.#k(key));
    }
    async put(key, value) {
        this.#store.setItem(this.#k(key), value);
    }
    async del(key) {
        this.#store.removeItem(this.#k(key));
    }
    async list(prefix) {
        const at = this.#k(prefix ?? "");
        const out = [];
        for (let i = 0; i < this.#store.length; i += 1) {
            const full = this.#store.key(i);
            if (full !== null && full.startsWith(at))
                out.push(full.slice(this.#ns.length + 1));
        }
        return out;
    }
}
/** The in-memory backend — the no-storage fallback (the wallet works,
 *  nothing survives the reload) and the test bench. */
export class MemoryWalletStorage {
    #map = new Map();
    async get(key) {
        return this.#map.get(key) ?? null;
    }
    async put(key, value) {
        this.#map.set(key, value);
    }
    async del(key) {
        this.#map.delete(key);
    }
    async list(prefix) {
        const keys = [...this.#map.keys()];
        return prefix === undefined ? keys : keys.filter((k) => k.startsWith(prefix));
    }
}
/** The in-memory localStorage stand-in (the LocalStorageWalletStorage
 *  constructor's fallback + the tests' injection). */
export function memoryStore() {
    const map = new Map();
    return {
        getItem: (k) => (map.has(k) ? map.get(k) : null),
        setItem: (k, v) => void map.set(k, v),
        removeItem: (k) => void map.delete(k),
        get length() {
            return map.size;
        },
        key: (i) => [...map.keys()][i] ?? null,
    };
}
