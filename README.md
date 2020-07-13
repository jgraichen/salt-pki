# Salt PKI

This repository contains a collection of execution modules and states to manage a X.509 keys, certificate signing requests and certificates. It does support modern EC suites. The actual signing can be delegated to other execution modules or runners, such as [`acme.sign`](https://github.com/jgraichen/salt-acme).

The current version focuses on the needs for TLS certificates and external signing (e.g. ACME, Vault, custom modules).

## Modules

See [_modules/pki.py](_modules/pki.py).

## States

See [_states/pki.py](_states/pki.py).
