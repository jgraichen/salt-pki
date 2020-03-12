# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pylint: disable=redefined-outer-name

import os
import stat
import shutil

from unittest.mock import patch

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


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

    with patch.dict(states.opts, {"test": True}):
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
