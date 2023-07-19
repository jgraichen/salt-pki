# Salt PKI

This repository contains a collection of execution modules and states to manage X.509 keys, certificate signing requests and certificates. It does support modern EC suites. The actual signing can be delegated to other execution modules or runners, such as [`acme.sign`](https://github.com/jgraichen/salt-acme).

The current version focuses on the needs for TLS certificates and external signing (e.g. ACME, Vault, custom modules).

## Modules

See [`_modules/pki.py`](_modules/pki.py).

## States

See [`_states/pki.py`](_states/pki.py).

## Installation

The recommended way of installation is using [salt `gitfs`](https://docs.saltproject.io/en/latest/topics/tutorials/gitfs.html) on the salt master.

```yaml
# /etc/salt/master
gitfs_remotes:
  - "https://github.com/jgraichen/salt-pki.git":
      - base: v1.0.1
```

If you want to use execution modules on the salt master, e.g. in runners, remember to synchronize modules on the master:

```console
salt-run saltutil.sync_modules
```
