# -*- coding: utf-8 -*-
# pylint: disable=missing-module-docstring

import logging
import os

try:
    from salt.utils.files import backup_minion as _backup_minion
except ImportError:
    from salt.utils import backup_minion as _backup_minion

from salt.exceptions import SaltInvocationError


def __virtual__():
    """
    Depend on corresponding execution module
    """
    if "pki.create_private_key" not in __salt__:
        return False, "Execution module unavailable"
    return True


def private_key(name, new=False, type="ec", size=4096, curve="secp256r1", backup=True):  # pylint: disable=R0913
    """
    Manage a private key.

    name:
        Path to private key

    new:
        Always create a new key. Default to ``False``.
        Combining new with :mod:`prereq <salt.states.requsities.preqreq>` can
        allow key rotation whenever a new certificate is generated.

    type:
        Key type to generate. Can be 'ec' (default) or 'rsa'.

    size:
        Length of private RSA key in bits. Defaults to ``4096``.

    curve:
        Curve name to use for EC keys. Defaults to ``secp256r1``.

    backup:
        When replacing an existing file, backup the old file on the minion.
        Default is ``True``.
    """
    # pylint: disable=redefined-builtin

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}

    if type == "ec":
        target = {"type": "ec", "curve": curve}
    elif type == "rsa":
        target = {"type": "rsa", "size": size}
    else:
        raise SaltInvocationError(f"Invalid key type: {type}")

    if os.path.isfile(name):
        try:
            current = __salt__["pki.read_private_key"](name)
        except SaltInvocationError as e:
            current = f"The private key is not valid: {e}"
    else:
        current = "The private key does not exist"

    if not new and current == target:
        ret["result"] = True
        ret["comment"] = "The private key is already in the correct state"
        return ret

    ret["changes"] = {"old": current, "new": target}

    if __opts__["test"] is True:
        ret["result"] = None
        ret["comment"] = "A new private key would be generated"
        return ret

    if os.path.isfile(name) and backup:
        bkroot = os.path.join(__opts__["cachedir"], "file_backup")
        _backup_minion(name, bkroot)

    __salt__["pki.create_private_key"](path=name, type=type, size=size, curve=curve)

    ret["result"] = True
    ret["comment"] = "New private key generated"

    return ret


def certificate(name, csr=None, days_remaining=28, backup=True, **kwargs):  # pylint: disable=R0912
    """
    Manage a x509 certificate.

    name:
        Path to store the certificate.

    path:
        Path to store the certificate is ``name`` is not a file path.

    csr:
        Path to CSR. If no CSR is given all additional arguments will be passed
        to ``pki.create_csr`` to create a CSR on demand.

        See ``pki.create_csr`` for available arguments.

    days_remaining:
        The minimum number of days remaining when the certificate should be
        renewed. Defaults to 28 days.

    backup:
        When replacing an existing certificate, backup the old file on the
        minion. Default is ``True``.
    """

    ret = {"name": name, "changes": {}, "result": False, "comment": ""}
    renewal_needed = False
    cert_changed = False

    if "path" in kwargs:
        name = kwargs.pop("path")

    if os.path.isfile(name):
        try:
            current = __salt__["pki.read_certificate"](name)
        except SaltInvocationError as e:
            current = f"Certificate is not valid: {e}"
    else:
        current = "Certificate does not exist"

    if not csr:
        if "key" not in kwargs:
            raise SaltInvocationError("CSR or private key required")

        if not os.path.exists(kwargs["key"]) and __opts__["test"]:
            new = "Private key does not yet exist, cannot preview changes"
        else:
            csr = __salt__["pki.create_csr"](text=True, **kwargs)
            new = __salt__["pki.read_csr"](csr)
    else:
        new = __salt__["pki.read_csr"](csr)

    if os.path.exists(name):
        renewal_needed = __salt__["pki.renewal_needed"](
            name, days_remaining=days_remaining
        )

    if isinstance(current, dict) and isinstance(new, dict):
        for key in ("subject", "extensions", "public_key"):
            if current[key] != new[key]:
                logging.debug("[%s] Certificate %s has changed", name, key)
                cert_changed = True
    else:
        cert_changed = True

    if not renewal_needed and not cert_changed:
        ret["result"] = True
        ret["comment"] = "Certificate is already in correct state"
        return ret

    ret["changes"] = {"old": current, "new": new}

    if __opts__["test"]:
        ret["result"] = None
        if cert_changed:
            ret["comment"] = "The certificate has changed and will be updated"
        if renewal_needed:
            ret["comment"] = "The certificate expires soon and will be updated"
        return ret

    if os.path.isfile(name) and backup:
        bkroot = os.path.join(__opts__["cachedir"], "file_backup")
        _backup_minion(name, bkroot)

    result = __salt__["pki.create_certificate"](path=name, csr=csr, **kwargs)

    ret["changes"] = {"old": current, "new": result}
    ret["comment"] = "The certificate has been updated"
    ret["result"] = True

    return ret
