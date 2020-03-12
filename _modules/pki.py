# -*- coding: utf-8 -*-
"""
Manage PKI (X509) infrastructure

:depends: cryptography
"""

import binascii
import datetime
import os
import re

from salt.exceptions import (
    CommandExecutionError,
    SaltInvocationError,
    SaltReqTimeoutError,
)

try:
    from salt.utils.files import fopen as _fopen, fpopen as _fpopen
except ImportError:
    from salt.utils import fopen as _fopen, fpopen as _fpopen

try:
    from cryptography import x509

    from cryptography.hazmat.backends import default_backend as _default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


def __virtual__():
    if not _HAS_CRYPTOGRAPHY:
        return False, "cryptography not available"

    return True


def create_private_key(path, type="ec", size=4096, curve="secp256r1"):
    """
    Create an RSA or elliptic curve private key in PEM format.

    path:
        The file path to write the private key to. File are written with ``600``
        as file mode.

    type:
        Key type to generate, either ``ec`` (default) or ``rsa``.

    size:
        Key length of an RSA key in bits. Defaults to ``4096``.

    curve:
        Curve to use for an EC key. Defaults to ``secp256r1``.

    CLI example:

    .. code-block:: bash

        salt '*' pki.create_private_key /etc/ssl/private/example.key
        salt '*' pki.create_private_key /etc/ssl/private/rsa.key type=rsa
    """
    # pylint: disable=redefined-builtin

    ret = {"type": type}

    if type == "rsa":
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=size, backend=_default_backend()
        )

        ret["size"] = size

    elif type == "ec":
        key = ec.generate_private_key(
            # pylint: disable=protected-access
            curve=ec._CURVE_TYPES[curve.lower()],
            backend=_default_backend(),
        )

        ret["curve"] = curve

    else:
        raise SaltInvocationError("Unsupported key type: {}".format(type))

    out = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with _fpopen(path, "wb", mode=0o600) as f:
        f.write(out)

    return ret


def read_private_key(path):
    """
    Read details about a private key.

    path:
        Path to a private key in PEM format.

    CLI Example:

    .. code-block:: bash

        salt '*' pki.read_private_key /etc/ssl/private/example.key
    """

    ret = {}

    with _fopen(path, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=_default_backend()
        )

    if isinstance(key, ec.EllipticCurvePrivateKey):
        ret["type"] = "ec"
        ret["curve"] = key.curve.name

    elif isinstance(key, rsa.RSAPrivateKey):
        ret["type"] = "rsa"
        ret["size"] = key.key_size

    else:
        raise SaltInvocationError(
            "Unsupported private key object: {0}".format(type(key))
        )

    return ret


def create_csr(path=None, text=False, algorithm="sha384", **kwargs):
    """
    Create a certificate signing request (CSR).

    path:
        Path to write the CSR to.

    text:

    key:
        Path to the private key used to sign the CSR.

    subject:
        Dictionary with subject name pairs.

        .. code-block::
            {"commonName": "localhost"}

    domains:
        Alias method to quickly create a CSR with DNS names. All given domains
        will be added as DNS names to the subject alternative name extension and
        the first domain will additionally used for the subjects common name.

    extensions:
        Dictionary with x509v3 extensions.

        Supported extensions are:

        subjectAltName:
            x509v3 Subject Alternative Name

            .. code-block::

                {"subjectAltName": "DNS:www.example.org,IP:192.0.2.1"}
    """

    key = kwargs.get("key", None)
    subject = kwargs.get("subject", {})
    extensions = kwargs.get("extensions", {})

    if not path and not text:
        raise SaltInvocationError("Either path or text must be specified")

    if not key:
        raise SaltInvocationError("Key required")

    if "domains" in kwargs:
        domains = kwargs["domains"]
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split(",")]
        if isinstance(domains, list):
            if not subject:
                subject = {"commonName": domains[0]}
            if "subjectAltName" not in extensions:
                extensions["subjectAltName"] = [f"DNS:{n}" for n in domains]

    if not subject:
        raise SaltInvocationError("Subject required")

    if algorithm not in _HASHES:
        raise SaltInvocationError(f"Algorithm not supported: {algorithm}")

    subject = _create_name(subject)
    extensions = _create_extensions(extensions)

    with _fopen(key, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=_default_backend()
        )

    csr = x509.CertificateSigningRequestBuilder(subject, extensions).sign(
        key, _HASHES[algorithm], backend=_default_backend()
    )

    out = csr.public_bytes(serialization.Encoding.PEM)

    if path:
        with _fopen(path, "wb") as f:
            f.write(out)

    if text:
        return out.decode()

    return read_csr(csr)


def read_csr(csr):
    """
    Read details about a certificate signing request.

    csr:
        Path to a certificate signing request file or a PEM-encoded string.
    """

    if not isinstance(csr, x509.CertificateSigningRequest):
        if os.path.isfile(csr):
            with _fopen(csr, "rb") as f:
                csr = x509.load_pem_x509_csr(f.read(), _default_backend())
        else:
            csr = x509.load_pem_x509_csr(csr.encode(), _default_backend())

    return {
        "extensions": _read_extensions(csr.extensions),
        "public_key": _read_public_key(csr.public_key(), text=True),
        "subject": _read_name(csr.subject),
    }


def create_certificate(path=None, text=False, csr=None, timeout=120, **kwargs):
    """
    Create a certificate by asking the master to sign a certificate signing
    request (CSR) or create a CSR on-the-fly.

    path:
        Path to write certificate to. Either ``path`` or ``text`` must be
        specified.

    text:
        Return certificate as PEM-encoded string. Either ``path`` or ``text``
        must be specified.

    csr:
        Path to certificate signing request file.

    runner:
        Runner to call on the master. The CSR is passed as a PEM-encoded string
        as the first argument to the runner. It is expected to return a
        dictionary with the following field(s):

        text:
            The resulting certificate as a PEM-encoded string. It may contain
            additional intermediate certificates.

        A default runner is fetched with ``config.get`` from ``pki:default:runner``.

    timeout:
        Maximum time to wait on a response from the runner.
    """

    if not path and not text:
        raise SaltInvocationError("Either path or text must be specified")

    if not csr:
        raise SaltInvocationError("CSR is required")

    runner = __salt__["config.get"]("pki:default:runner", None)
    runner = kwargs.get("runner", runner)

    if not runner:
        raise SaltInvocationError("Runner is required")

    if os.path.exists(csr):
        with _fopen(csr, "r") as f:
            csr = f.read()

    resp = __salt__["publish.runner"](runner, arg=csr, timeout=timeout)

    if not resp:
        raise SaltInvocationError(
            f"Nothing returned from runner, do you have permissions run {runner}?"
        )

    if isinstance(resp, str) and "timed out" in resp:
        raise SaltReqTimeoutError(resp)

    if isinstance(resp, str):
        raise CommandExecutionError(resp)

    if not isinstance(resp, dict):
        raise CommandExecutionError(
            f"Expected response to be a dict, but got {type(resp)}"
        )

    try:
        ret = read_certificate(resp["text"])
    except ValueError as e:
        raise CommandExecutionError(
            f"Runner did not return a valid PEM-encoded certificate: {e}"
        )

    if path:
        with _fopen(path, "w") as f:
            f.write(resp["text"])

    if text:
        return resp["text"]

    return ret


def read_certificate(crt):
    """
    Read details about a certificate.

    crt:
        Path to PEM-encoded certificate file or PEM-encoded string.


    CLI Example:

    .. code-block:: bash

        salt '*' pki.read_certificate /etc/ssl/certs/example.crt
    """

    if os.path.exists(crt):
        with _fopen(crt, "rb") as f:
            crt = x509.load_pem_x509_certificate(f.read(), _default_backend())
    else:
        crt = x509.load_pem_x509_certificate(crt.encode(), _default_backend())

    ret = {
        "extensions": _read_extensions(crt.extensions),
        "issuer": _read_name(crt.issuer),
        "not_valid_after": str(crt.not_valid_after),
        "not_valid_before": str(crt.not_valid_before),
        "public_key": _read_public_key(crt.public_key(), text=True),
        "serial": crt.serial_number,
        "subject": _read_name(crt.subject),
    }

    return ret


def renewal_needed(path, days_remaining=28):
    """
    Check if a certificate expires within the specified days.

    path:
        Path to PEM encoded certificate file.

    days_remaining:
        The minimum number of days remaining when the certificate should be
        renewed. Defaults to 28 days.
    """

    with _fopen(path, "rb") as f:
        crt = x509.load_pem_x509_certificate(f.read(), backend=_default_backend())

    remaining_days = (crt.not_valid_after - datetime.datetime.now()).days

    return remaining_days < days_remaining


def _get_oid(name, cls=None):
    if re.search(r"^\d+(\.\d+)*$", name):
        return x509.oid.ObjectIdentifier(name)

    for oid, name in x509.oid._OID_NAMES.items():
        if name == name and (not cls or oid in cls.__dict__.values()):
            return oid

    raise KeyError(f"Unknown OID: {name}")


def _read_name(name):
    return {n.oid._name: n.value for n in name}


def _create_name(name):
    if isinstance(name, x509.Name):
        return name

    if isinstance(name, str):
        name = dict([s.strip().split("=", 1) for s in name.split(",")])

    if isinstance(name, dict):
        return x509.Name(
            [
                x509.NameAttribute(_get_oid(k, x509.oid.NameOID), str(v))
                for k, v in name.items()
            ]
        )

    raise ValueError(f"The x509 name must be a string or dictionary, but was: {name!r}")


def _read_public_key(pubkey, text=False):
    ret = {}

    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        ret["type"] = "ec"
        ret["curve"] = pubkey.curve.name

    if isinstance(pubkey, rsa.RSAPublicKey):
        ret["type"] = "rsa"
        ret["size"] = pubkey.key_size

    if text:
        ret["text"] = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    return ret


def _read_extensions(extensions):
    ret = {}

    for ext in extensions:
        name = ext.oid._name

        if name in _EXTENSIONS:
            ret[name] = _EXTENSIONS[name].read(ext)

    return ret


def _create_extensions(extensions):
    if extensions is None:
        return x509.Extensions([])

    if not isinstance(extensions, dict):
        raise ValueError(f"Extensions must be a dictionary, but is: {extensions!r}")

    result = []

    for name, value in extensions.items():
        if not name in _EXTENSIONS:
            raise KeyError(f"Unsupported extension: {name}")

        result.append(_EXTENSIONS[name].build(value))

    return x509.Extensions(result)


class _SubjectAltName:
    @staticmethod
    def read(ext):
        names = []

        for name in ext.value:
            if isinstance(name, x509.RFC822Name):
                names.append("email:{}".format(name.value))
            if isinstance(name, x509.DNSName):
                names.append("DNS:{}".format(name.value))
            if isinstance(name, x509.DirectoryName):
                names.append("dirName:{}".format(name.value))
            if isinstance(name, x509.UniformResourceIdentifier):
                names.append("URI:{}".format(name.value))
            if isinstance(name, x509.IPAddress):
                names.append("IP:{}".format(name.value))
            if isinstance(name, x509.OtherName):
                names.append(
                    "otherName:{};{}".format(
                        name.type_id.dotted_string,
                        "HEX:{}".format(binascii.hexlify(name.value)),
                    )
                )

        return sorted(names)

    @staticmethod
    def build(value):
        if not isinstance(value, list):
            value = [s.strip() for s in value.split(",")]

        names = [s.split(":", 1) for s in value]

        return x509.Extension(
            critical=False,
            oid=x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            value=x509.SubjectAlternativeName(
                [_SubjectAltName.build_name(k, v) for k, v in names]
            ),
        )

    @staticmethod
    def build_name(key, value):
        key = key.lower()

        if key == "dns":
            return x509.DNSName(str(value))

        if key == "email":
            return x509.RFC822Name(str(value))

        if key == "uri":
            return x509.UniformResourceIdentifier(str(value))

        if key == "dirname":
            return x509.DirectoryName(str(value))

        if key == "ip" or key == "ip address":
            import ipaddress

            try:
                value = ipaddress.ip_address(str(value))
            except ValueError:
                value = ipaddress.ip_network(str(value))

            return x509.IPAddress(value)

        raise ValueError(f"Unsupported alternative name: {key}")


_EXTENSIONS = {"subjectAltName": _SubjectAltName}

_HASHES = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}
