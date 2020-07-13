# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
# pylint: disable=redefined-outer-name

import datetime
import ipaddress
import os
import stat

from unittest.mock import patch

import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from salt.exceptions import SaltInvocationError


_EXAMPLE_PUBKEY = {
    "type": "ec",
    "curve": "secp192r1",
    "text": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEzHytpRZH/0nCuMoT8K8Nijw2tcpi\n"
        "otufkOQPX+k4azNhQL/WwqZWW83A16dlhCSz\n"
        "-----END PUBLIC KEY-----\n"
    ),
}


_EXAMPLE_CSR = {
    "extensions": {
        "subjectAltName": [
            "DNS:example.com",
            "DNS:example.org",
            "DNS:www.example.com",
            "DNS:www.example.org",
        ]
    },
    "public_key": _EXAMPLE_PUBKEY,
    "subject": {
        "commonName": "example.org",
        "countryName": "DE",
        "localityName": "Potsdam",
        "stateOrProvinceName": "Brandenburg",
    },
}


_EXAMPLE_CERT = {
    "extensions": {
        "subjectAltName": [
            "DNS:example.com",
            "DNS:example.org",
            "DNS:www.example.com",
            "DNS:www.example.org",
        ]
    },
    "issuer": {
        "commonName": "example.org",
        "countryName": "DE",
        "localityName": "Potsdam",
        "stateOrProvinceName": "Brandenburg",
    },
    "not_valid_after": "2020-01-31 14:47:42",
    "not_valid_before": "2020-01-30 14:47:42",
    "public_key": _EXAMPLE_PUBKEY,
    "serial": 454319881906309886160729579224994843050700058032,
    "subject": {
        "commonName": "example.org",
        "countryName": "DE",
        "localityName": "Potsdam",
        "stateOrProvinceName": "Brandenburg",
    },
}


@pytest.fixture
def keyfile(tmpdir):
    return os.path.join(tmpdir, "example.key")


def _gen_pkey(path, mod, **kwargs):
    key = mod.generate_private_key(**kwargs, backend=default_backend())

    if path:
        with open(path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    return key


def _gen_crt(path, key, days=30):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])

    crt = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256(), default_backend())
    )

    if path:
        with open(path, "wb") as f:
            f.write(crt.public_bytes(serialization.Encoding.PEM))

    return crt


def test_create_private_key(mods, keyfile):
    """
    Creates an elliptic curve private key using secp256r1 curve by default.
    """

    assert mods["pki.create_private_key"](keyfile) == {
        "type": "ec",
        "curve": "secp256r1",
    }

    assert os.path.exists(keyfile)
    assert stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600

    with open(keyfile, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"


def test_create_private_key_ec_curve(mods, keyfile):
    assert mods["pki.create_private_key"](keyfile, curve="secp384r1") == {
        "type": "ec",
        "curve": "secp384r1",
    }

    assert os.path.exists(keyfile)

    with open(keyfile, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp384r1"


def test_create_private_key_rsa(mods, keyfile):
    assert mods["pki.create_private_key"](keyfile, type="rsa") == {
        "type": "rsa",
        "size": 4096,
    }

    assert os.path.exists(keyfile)

    with open(keyfile, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096


def test_create_private_key_rsa_size(mods, keyfile):
    assert mods["pki.create_private_key"](keyfile, type="rsa", size=1024) == {
        "type": "rsa",
        "size": 1024,
    }

    assert os.path.exists(keyfile)

    with open(keyfile, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 1024


def test_create_private_key_invalid_type(mods, keyfile):
    with pytest.raises(SaltInvocationError):
        mods["pki.create_private_key"](keyfile, type="dsa")


def test_read_private_key(mods):
    path = "test/fixtures/example-ec.key"

    assert mods["pki.read_private_key"](path) == {"type": "ec", "curve": "secp192r1"}


def test_read_private_key_rsa(mods):
    path = "test/fixtures/example-rsa.key"

    assert mods["pki.read_private_key"](path) == {"type": "rsa", "size": 1024}


def test_create_csr(mods, tmpdir):
    path = os.path.join(tmpdir, "example.csr")

    ret = mods["pki.create_csr"](
        path,
        key="test/fixtures/example-ec.key",
        subject={"commonName": "localhost"},
        extensions={"subjectAltName": "DNS:localhost,IP:127.0.0.1"},
    )

    assert os.path.exists(path)
    assert ret == {
        "extensions": {"subjectAltName": ["DNS:localhost", "IP:127.0.0.1"]},
        "public_key": _EXAMPLE_PUBKEY,
        "subject": {"commonName": "localhost"},
    }

    with open(path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read(), default_backend())

    assert isinstance(csr, x509.CertificateSigningRequest)
    assert csr.subject == x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")]
    )

    assert repr(csr.extensions) == repr(
        x509.Extensions(
            [
                x509.Extension(
                    x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                    False,
                    x509.SubjectAlternativeName(
                        [
                            x509.DNSName("localhost"),
                            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                        ]
                    ),
                )
            ]
        )
    )


def test_create_csr_domains(mods):
    ret = mods["pki.create_csr"](
        text=True,
        key="test/fixtures/example-ec.key",
        domains=["example.org", "example.com"],
    )

    csr = x509.load_pem_x509_csr(ret.encode(), default_backend())

    assert isinstance(csr, x509.CertificateSigningRequest)
    assert csr.subject == x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.org")]
    )

    assert repr(csr.extensions) == repr(
        x509.Extensions(
            [
                x509.Extension(
                    x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                    False,
                    x509.SubjectAlternativeName(
                        [x509.DNSName("example.org"), x509.DNSName("example.com")]
                    ),
                )
            ]
        )
    )


def test_create_csr_text(mods):
    ret = mods["pki.create_csr"](
        text=True,
        key="test/fixtures/example-ec.key",
        subject={"commonName": "localhost"},
    )

    csr = x509.load_pem_x509_csr(ret.encode(), default_backend())
    assert isinstance(csr, x509.CertificateSigningRequest)


def test_read_csr(mods):
    assert mods["pki.read_csr"]("test/fixtures/example.csr") == _EXAMPLE_CSR


def test_create_certificate(mods, tmpdir):
    path = os.path.join(tmpdir, "test.crt")
    fn = mods["pki.create_certificate"]

    with open("test/fixtures/example.crt", "r") as f:
        test_crt = f.read()

    def publish_runner_mock(name, arg, timeout):
        assert name == "test.sign"
        assert timeout == 120

        with open("test/fixtures/example.csr", "r") as f:
            assert arg == f.read()

        with open("test/fixtures/example.crt", "r") as f:
            return {"text": f.read()}

    with patch.dict(
        fn.__globals__["__salt__"], {"publish.runner": publish_runner_mock}
    ):
        ret = fn(path, csr="test/fixtures/example.csr")

    assert ret == _EXAMPLE_CERT
    assert os.path.exists(path)

    with open(path, "r") as f:
        assert f.read() == test_crt


def test_create_certificate_module(mods, tmpdir):
    path = os.path.join(tmpdir, "test.crt")
    fn = mods["pki.create_certificate"]

    def mock(csr):
        with open("test/fixtures/example.csr", "r") as f:
            assert csr == f.read()

        with open("test/fixtures/example.crt", "r") as f:
            return {"text": f.read()}

    with patch.dict(fn.__globals__["__salt__"], {"test.sign": mock}):
        ret = fn(path, csr="test/fixtures/example.csr", module="test.sign")

    assert ret == _EXAMPLE_CERT
    assert os.path.exists(path)

    with open("test/fixtures/example.crt", "r") as example:
        with open(path, "r") as crt:
            assert crt.read() == example.read()


def test_create_certificate_module_and_runner(mods, tmpdir):
    path = os.path.join(tmpdir, "test.crt")

    with pytest.raises(SaltInvocationError):
        mods["pki.create_certificate"](
            path,
            csr="test/fixtures/example.csr",
            module="test.sign",
            runner="test.sign",
        )


def test_read_certificate(mods):
    path = "test/fixtures/example.crt"

    assert mods["pki.read_certificate"](path) == _EXAMPLE_CERT


def test_renewal_needed(mods):
    path = "test/fixtures/example.crt"

    assert mods["pki.renewal_needed"](path)


def test_renewal_needed_valid(mods, tmpdir):
    path = os.path.join(tmpdir, "example.crt")
    _gen_crt(path, _gen_pkey(None, ec, curve=ec.SECP192R1()), days=29)

    assert not mods["pki.renewal_needed"](path)


def test_renewal_needed_days_remaining(mods, tmpdir):
    path = os.path.join(tmpdir, "example.crt")
    _gen_crt(path, _gen_pkey(None, ec, curve=ec.SECP192R1()), days=10)

    assert mods["pki.renewal_needed"](path, days_remaining=10)
    assert not mods["pki.renewal_needed"](path, days_remaining=9)
