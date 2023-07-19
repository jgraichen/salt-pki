# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pylint: disable=redefined-outer-name

import os
import shutil
import stat
import sys
from unittest.mock import patch

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from matchlib import Partial


def test_private_key(states, tmpdir):
    """
    Creates an elliptic curve private key using secp256r1 curve by default.
    """

    path = os.path.join(tmpdir, "example.key")

    assert states["pki.private_key"](path) == {
        "changes": {
            "new": {"curve": "secp256r1", "type": "ec"},
            "old": "The private key does not exist",
        },
        "comment": "New private key generated",
        "name": path,
        "result": True,
    }

    assert os.path.exists(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"


def test_private_key_test(states, tmpdir):
    path = os.path.join(tmpdir, "example.key")

    with patch.dict(sys.modules["salt.loaded.ext.states.pki"].__opts__, {"test": True}):
        ret = states["pki.private_key"](path)

    assert ret == {
        "changes": {
            "new": {"curve": "secp256r1", "type": "ec"},
            "old": "The private key does not exist",
        },
        "comment": "A new private key would be generated",
        "name": path,
        "result": None,
    }

    assert not os.path.exists(path)


def test_private_key_exists(states, tmpdir):
    path = os.path.join(tmpdir, "example.key")
    shutil.copyfile("test/fixtures/example-ec.key", path)

    assert states["pki.private_key"](path, curve="secp192r1") == {
        "changes": {},
        "comment": "The private key is already in the correct state",
        "name": path,
        "result": True,
    }


def test_private_key_changed(states, tmpdir):
    path = os.path.join(tmpdir, "example.key")
    shutil.copyfile("test/fixtures/example-rsa.key", path)

    assert states["pki.private_key"](path, curve="secp192r1") == {
        "changes": {
            "new": {"curve": "secp192r1", "type": "ec"},
            "old": {"size": 1024, "type": "rsa"},
        },
        "comment": "New private key generated",
        "name": path,
        "result": True,
    }


def test_certificate(states, mods, tmpdir):
    path = os.path.join(tmpdir, "example.crt")
    ret = states["pki.certificate"](path, csr="test/fixtures/example.csr")

    assert ret == Partial(
        {
            "changes": {
                "new": {
                    "extensions": {
                        "subjectAltName": [
                            "DNS:example.com",
                            "DNS:example.org",
                            "DNS:www.example.com",
                            "DNS:www.example.org",
                        ]
                    },
                    "issuer": {
                        "countryName": "DE",
                        "localityName": "Potsdam",
                        "organizationName": "Example CA",
                        "stateOrProvinceName": "Brandenburg",
                    },
                    "not_valid_after": ...,
                    "not_valid_before": ...,
                    "public_key": ...,
                    "serial": ...,
                    "subject": {
                        "commonName": "example.org",
                        "countryName": "DE",
                        "localityName": "Potsdam",
                        "stateOrProvinceName": "Brandenburg",
                    },
                },
                "old": "Certificate does not exist",
            },
            "comment": "The certificate has been updated",
            "name": path,
            "result": True,
        }
    )

    assert os.path.exists(path)
    assert mods["pki.read_certificate"](path) == Partial(
        {
            "subject": {"commonName": "example.org", ...: ...},
            ...: ...,
        }
    )


def test_certificate_test(states, tmpdir):
    path = os.path.join(tmpdir, "example.crt")

    with patch.dict(sys.modules["salt.loaded.ext.states.pki"].__opts__, {"test": True}):
        ret = states["pki.certificate"](path, csr="test/fixtures/example.csr")

    assert ret == Partial(
        {
            "changes": {
                "new": {
                    "extensions": {
                        "subjectAltName": [
                            "DNS:example.com",
                            "DNS:example.org",
                            "DNS:www.example.com",
                            "DNS:www.example.org",
                        ]
                    },
                    "public_key": ...,
                    "subject": {
                        "commonName": "example.org",
                        "countryName": "DE",
                        "localityName": "Potsdam",
                        "stateOrProvinceName": "Brandenburg",
                    },
                },
                "old": "Certificate does not exist",
            },
            "comment": "The certificate has changed and will be updated",
            "name": path,
            "result": None,
        }
    )

    assert not os.path.exists(path)


def test_certificate_domain(states, mods, tmpdir):
    """
    Testing a dynamic certificate (without CSR) and a single string as domain.
    """

    path = os.path.join(tmpdir, "example.crt")
    ret = states["pki.certificate"](
        path,
        key="test/fixtures/example-ec.key",
        domains="example.com",
    )

    assert ret == Partial(
        {
            "changes": {
                "new": {
                    "extensions": {"subjectAltName": ["DNS:example.com"]},
                    "subject": {"commonName": "example.com"},
                    ...: ...,
                },
                ...: ...,
            },
            "comment": "The certificate has been updated",
            "name": path,
            "result": True,
        }
    )

    assert os.path.exists(path)
    assert mods["pki.read_certificate"](path) == Partial(
        {
            "extensions": {"subjectAltName": ["DNS:example.com"]},
            "subject": {"commonName": "example.com"},
            ...: ...,
        }
    )


def test_certificate_update(states, mods, tmpdir):
    path = os.path.join(tmpdir, "example.crt")

    # Ensure certificate exists first
    assert states["pki.certificate"](
        path, key="test/fixtures/example-ec.key", domains="example.com"
    )
    assert os.path.exists(path)

    ret = states["pki.certificate"](
        path, key="test/fixtures/example-ec.key", domains="example.org"
    )

    assert ret == Partial(
        {
            "changes": {
                "new": {
                    "extensions": {"subjectAltName": ["DNS:example.org"]},
                    "issuer": ...,
                    "not_valid_after": ...,
                    "not_valid_before": ...,
                    "public_key": ...,
                    "serial": ...,
                    "subject": {"commonName": "example.org"},
                },
                ...: ...,
            },
            "comment": "The certificate has been updated",
            "name": path,
            "result": True,
        }
    )

    assert mods["pki.read_certificate"](path) == Partial(
        {
            "extensions": {"subjectAltName": ["DNS:example.org"]},
            "subject": {"commonName": "example.org"},
            ...: ...,
        }
    )


def test_certificate_domain_update_test(states, mods, tmpdir):
    path = os.path.join(tmpdir, "example.crt")

    # Ensure certificate exists first
    assert states["pki.certificate"](
        path, key="test/fixtures/example-ec.key", domains="example.com"
    )

    assert os.path.exists(path)

    # Check test mode on updates
    with patch.dict(sys.modules["salt.loaded.ext.states.pki"].__opts__, {"test": True}):
        ret = states["pki.certificate"](
            path, key="test/fixtures/example-ec.key", domains="example.org"
        )

    assert ret == Partial(
        {
            "changes": {
                "new": {
                    "extensions": {"subjectAltName": ["DNS:example.org"]},
                    "public_key": ...,
                    "subject": {"commonName": "example.org"},
                },
                ...: ...,
            },
            "comment": "The certificate has changed and will be updated",
            "name": path,
            "result": None,
        }
    )

    # Asset certificate file has not been updated
    assert mods["pki.read_certificate"](path) == Partial(
        {
            "extensions": {"subjectAltName": ["DNS:example.com"]},
            "subject": {"commonName": "example.com"},
            ...: ...,
        }
    )


def test_certificate_domains(states, mods, tmpdir):
    """
    Testing a dynamic certificate with a list of domain names.
    """

    path = os.path.join(tmpdir, "example.crt")
    ret = states["pki.certificate"](
        path,
        key="test/fixtures/example-ec.key",
        domains=["example.com", "example.org"],
    )

    assert ret == Partial(
        {
            "changes": {
                "new": {
                    "extensions": {
                        "subjectAltName": ["DNS:example.com", "DNS:example.org"]
                    },
                    "subject": {"commonName": "example.com"},
                    ...: ...,
                },
                ...: ...,
            },
            "comment": "The certificate has been updated",
            "name": path,
            "result": True,
        }
    )

    assert os.path.exists(path)
    assert mods["pki.read_certificate"](path) == Partial(
        {
            "extensions": {"subjectAltName": ["DNS:example.com", "DNS:example.org"]},
            "subject": {"commonName": "example.com"},
            ...: ...,
        }
    )


def test_certificate_renewal(states, mods, tmpdir):
    """
    Testing a dynamic certificate with a list of domain names.
    """
    path = os.path.join(tmpdir, "example.crt")
    kwargs = {"key": "test/fixtures/example-ec.key", "domains": "example.org"}

    # Make sure certificate exists before
    assert states["pki.certificate"](path, **kwargs)
    old_serial = mods["pki.read_certificate"](path)["serial"]

    def renewal_needed(crt_path, **kwargs):
        assert crt_path == path
        assert kwargs == {"days_remaining": 28}
        return True

    with patch.dict(
        mods._dict,  # pylint: disable=protected-access
        {"pki.renewal_needed": renewal_needed},
    ):
        ret = states["pki.certificate"](path, **kwargs)

    assert ret == Partial(
        {
            "changes": {
                "new": {
                    "extensions": {"subjectAltName": ["DNS:example.org"]},
                    "issuer": ...,
                    "not_valid_after": ...,
                    "not_valid_before": ...,
                    "public_key": ...,
                    "serial": ...,
                    "subject": {"commonName": "example.org"},
                },
                "old": {...: ...},
            },
            "comment": "The certificate has been updated",
            "name": path,
            "result": True,
        }
    )

    # Assert certficiate file has been updated
    crt = mods["pki.read_certificate"](path)
    assert old_serial != crt["serial"]


def test_certificate_renewal_test(states, mods, tmpdir):
    """
    Testing a dynamic certificate with a list of domain names.
    """
    path = os.path.join(tmpdir, "example.crt")
    kwargs = {"key": "test/fixtures/example-ec.key", "domains": "example.org"}

    # Make sure certificate exists before
    assert states["pki.certificate"](path, **kwargs)
    old_serial = mods["pki.read_certificate"](path)["serial"]

    def renewal_needed(crt_path, **kwargs):
        assert crt_path == path
        assert kwargs == {"days_remaining": 28}
        return True

    with patch.dict(
        mods._dict,  # pylint: disable=protected-access
        {"pki.renewal_needed": renewal_needed},
    ):
        # Check test mode renewal
        with patch.dict(
            sys.modules["salt.loaded.ext.states.pki"].__opts__, {"test": True}
        ):
            ret = states["pki.certificate"](path, **kwargs)

    assert ret == Partial(
        {
            "changes": {
                # In test mode only the CSR output can be returned as "new"
                "new": {
                    "extensions": {"subjectAltName": ["DNS:example.org"]},
                    "public_key": ...,
                    "subject": {"commonName": "example.org"},
                },
                "old": {...: ...},
            },
            "comment": "The certificate expires soon and will be updated",
            "name": path,
            "result": None,
        }
    )

    # Assert certificate has not been updated
    crt = mods["pki.read_certificate"](path)
    assert old_serial == crt["serial"]
