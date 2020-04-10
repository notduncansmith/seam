[![GoDoc](https://godoc.org/github.com/notduncansmith/seam?status.svg)](https://godoc.org/github.com/notduncansmith/seam) [![Build Status](https://travis-ci.com/notduncansmith/seam.svg?branch=master)](https://travis-ci.com/notduncansmith/seam) [![codecov](https://codecov.io/gh/notduncansmith/seam/branch/master/graph/badge.svg)](https://codecov.io/gh/notduncansmith/seam)

# SEAM - Simple Encrypted Authenticated Messaging

**⚠️ WARNING: THIS IS ALPHA SOFTWARE AND HAS NOT BEEN AUDITED. USE AT YOUR OWN RISK. ⚠️**

The SEAM library implements a small encoding standard for exchanging messages signed and encrypted with TweetNaCl (and compatible) constructions: `sign`, `box`, and `secretbox`.

SEAM is designed to enable two messaging modes.

1. In **direct message** (or "DM") mode, messages are encrypted with the `box` construction (*x25519-xsalsa20-poly1305*) using the recipient's public key and an ephemeral private key (the "transit" key).

```json
{
  "mode": "direct",
  "body": "(base64-encoded encrypted bytes)",
  "destination": "(opaque string)",
  "nonce": "(base64-encoded nonce bytes)",
  "timestamp": 2234567890,
  "transitIdentity": "(base64-encoded X25519 public key)"
}
```

2. In **shared message** (or "thread") mode, messages are encrypted with the `secretbox` construction (*xsalsa20-poly1305*) using a shared key.

```json
{
  "mode": "shared",
  "body": "(base64-encoded encrypted bytes)",
  "destination": "(opaque string)",
  "nonce": "(base64-encoded nonce bytes)",
  "timestamp": 2234567890
}
```

All messages are encoded as JSON, digested with SHA512, signed (*ed25519*), and wrapped in an **envelope** with the signing user's public key.

```json
{
  "author": "(base64-encoded ed25519 public key)",
  "message": "(SHA-512 hash of message JSON)",
  "signature": "(base64-encoded ed25519 signature)"
}
```

See GoDoc for full usage.

## License

Released under [The MIT License](https://opensource.org/licenses/MIT) (see `LICENSE.txt`).

Copyright 2020 Duncan Smith