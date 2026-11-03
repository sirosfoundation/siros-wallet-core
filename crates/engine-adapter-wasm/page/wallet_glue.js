// The glue: loads the wasm module and exposes the engine constructor
// to wallet.js. Built by `make wasm-page`, which runs wasm-pack and
// copies this plus wallet.js and index.html into the page bundle.

import init, { WasmEngine } from '../pkg/engine_adapter_wasm.js';

let ready = null;

async function boot() {
  await init();
  window.Engine = { new: (config) => Promise.resolve(new WasmEngine(config)) };
  document.dispatchEvent(new Event('mini-wallet-ready'));
}

ready = boot();
export { ready };
