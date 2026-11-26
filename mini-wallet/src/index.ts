// @sirosfoundation/mini-wallet — the whole wallet a page hosts.
// See the README for the design: the engine is the published wasm, the
// storage is pluggable (localStorage now, the passkey-encrypted
// private-data library later — with NO onboarding required first and a
// migration between backends), and every UI decision is the page's.

export { MiniWallet } from "./wallet.js";
export type { MiniWalletOptions } from "./wallet.js";
export {
  LocalStorageWalletStorage,
  MemoryWalletStorage,
  memoryStore,
} from "./storage.js";
export { migrateWalletStorage } from "./migration.js";
export { AlwaysTrustedPlugin, AuthzenTrustPlugin, asPdp, DemoAlwaysTrustedPlugin } from "./trust.js";
export type { TrustPlugin, TrustAsk, TrustAnswer } from "./trust.js";
export { GoWalletBackendTarget, NullCipher } from "./adopt.js";
export type { AdoptAsk, AdoptReport, AdoptTarget, AdoptUi, PrivateDataCipher } from "./adopt.js";
// The modal CONTRACT only (types.ts): the library ships no renderer —
// every UX string, style and layout is the hosting page's (the design
// brief: "the library renders nothing"). The example carries a
// reference implementation (examples/realeyes/adopt-modal.mjs).
export type { AdoptModal } from "./types.js";
export type { MigrationReport } from "./migration.js";
export {
  isOfferUri,
  normalizeOffer,
  unwrapOffer,
  unwrapAuthorizationRequest,
} from "./offer.js";
export type { NormalizedOffer, OfferSource } from "./offer.js";
export { ZkpPresenterPort, fromEngineJson, asRecord, openId4VpHandover, secretSeedOf } from "./presenter.js";
export type { PresenterOptions, PresenterRefusal, VpAskParams, MatchAskParams } from "./presenter.js";
export type {
  MiniWalletEvent,
  MiniWalletFetch,
  MiniWalletPdp,
  MiniWalletPdpOption,
  MiniWalletUi,
  StoredCredential,
  WalletStorage,
} from "./types.js";
