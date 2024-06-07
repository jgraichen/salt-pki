# vim: ft=python

import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend as _default_backend
from cryptography.hazmat.primitives import hashes, serialization


def sign(csr):
    """
    Minimal execution module to test signing with a CA.
    """

    with open("test/fixtures/ca.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), backend=_default_backend())
    with open("test/fixtures/ca.key", "rb") as f:
        ca_pkey = serialization.load_pem_private_key(
            f.read(), password=None, backend=_default_backend()
        )

    obj = x509.load_pem_x509_csr(csr.encode(), backend=_default_backend())

    crt = x509.CertificateBuilder(
        issuer_name=ca_cert.subject,
        subject_name=obj.subject,
        public_key=obj.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=90),
        not_valid_before=datetime.datetime.utcnow(),
        extensions=obj.extensions,
    ).sign(ca_pkey, algorithm=hashes.SHA384(), backend=_default_backend())

    return {"text": crt.public_bytes(serialization.Encoding.PEM).decode()}
