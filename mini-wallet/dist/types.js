// The mini-wallet's contracts. Everything here is wire-shaped: the types
// mirror the engine's documented callback surfaces exactly, so a page
// implementing them needs no adapter layer.
//
// The library delegates ALL UI to the calling page (the design brief):
// consent, credential matching, transaction codes and the presentation
// approval arrive as callbacks; the library renders nothing.
export {};
