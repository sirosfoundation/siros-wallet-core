// @sirosfoundation/mini-wallet — the whole wallet a page hosts.
// See the README for the design: the engine is the published wasm, the
// storage is pluggable (localStorage now, the passkey-encrypted
// private-data library later — with NO onboarding required first and a
// migration between backends), and every UI decision is the page's.
export { MiniWallet } from "./wallet.js";
export { LocalStorageWalletStorage, MemoryWalletStorage, memoryStore, } from "./storage.js";
export { migrateWalletStorage } from "./migration.js";
export { AlwaysTrustedPlugin, AuthzenTrustPlugin, asPdp, DemoAlwaysTrustedPlugin } from "./trust.js";
export { GoWalletBackendTarget, NullCipher } from "./adopt.js";
export { isOfferUri, normalizeOffer, unwrapOffer, unwrapAuthorizationRequest, } from "./offer.js";
export { ZkpPresenterPort, fromEngineJson, asRecord, openId4VpHandover, secretSeedOf } from "./presenter.js";
