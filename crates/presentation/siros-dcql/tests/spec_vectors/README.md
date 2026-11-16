# Spec vectors

Verbatim copies of the DCQL examples published in the OpenID4VP 1.0
repository, `1.0/examples/query_lang`.

**Do not reformat these files.** Not the indentation, not the trailing
whitespace, not the key order. Their value is that they are byte-for-byte what
the specification publishes rather than something shaped by this
implementation's assumptions — a tidied copy is just another fixture we wrote
ourselves.

`simple.json` in particular carries trailing whitespace upstream. It is
supposed to.

Verify a copy against upstream with:

```sh
curl -sSL https://raw.githubusercontent.com/openid/OpenID4VP/main/1.0/examples/query_lang/simple.json \
  | diff - simple.json
```

Refresh them only deliberately, and say so in the commit: a changed vector
means the specification's example changed, which is worth reading before
accepting.
