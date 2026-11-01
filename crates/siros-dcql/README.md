# siros-dcql

An implementation of the Digital Credentials Query Language (DCQL), as defined
by [OpenID for Verifiable Presentations 1.0][oid4vp] §6.

DCQL is how a verifier says which credentials it wants: a set of credential
queries, each constrained by format, type and claims, optionally grouped into
credential sets that express "one of these combinations will do".

This crate is the query engine on its own — parsing, evaluation against an
abstract credential source, and enumeration of the credential combinations that
satisfy a query. It performs no I/O, knows nothing about any particular wallet,
and is independent of how credentials are stored or presented.

It was extracted from [siros-dc-matcher][matcher], a credential matcher for the
W3C Digital Credentials API, where the same engine has to run identically inside
a WebAssembly sandbox, in Kotlin, and in Swift.

## Status

Published as [`siros-dcql`](https://crates.io/crates/siros-dcql). Query model,
claims path pointers and selection are implemented and tested against the
specification's own examples. The API will move before 1.0.

## Licence

BSD-2-Clause.

[oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
[matcher]: https://github.com/sirosfoundation/siros-dc-matcher
