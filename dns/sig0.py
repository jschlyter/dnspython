# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""DNS SIG(0) support."""


import time
from datetime import datetime
from typing import cast

import dns._features
import dns.message
import dns.name
import dns.node
import dns.rdataset
import dns.rdatatype
from dns.dnssec import (
    GenericPrivateKey,
    PrivateKey,
    UnsupportedAlgorithm,
    ValidationFailure,
    _find_candidate_keys,
    _need_pyca,
    get_algorithm_cls_from_dnskey,
    key_id,
    to_timestamp,
)
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.KEY import KEY
from dns.rdtypes.ANY.RRSIG import RRSIG
from dns.rdtypes.ANY.SIG import SIG

if dns._features.have("dnssec"):
    from cryptography.exceptions import InvalidSignature


def _make_sig_signature_data(
    request: dns.message.Message | bytes,
    response: dns.message.Message | bytes | None,
    signer: dns.name.Name,
    algorithm: int,
    key_tag: int,
    inception: datetime | str | int | float,
    expiration: datetime | str | int | float,
) -> tuple[bytes, SIG]:
    """Create SIG RDATA for request/response."""

    sig_template = SIG(
        rdclass=dns.rdataclass.ANY,
        rdtype=dns.rdatatype.SIG,
        type_covered=dns.rdatatype.NONE,
        algorithm=algorithm,
        labels=0,
        original_ttl=0,
        expiration=expiration,
        inception=inception,
        key_tag=key_tag,
        signer=signer,
        signature=b"",
    )

    data: bytes = sig_template.to_wire(origin=signer)  # type: ignore

    if isinstance(request, bytes):
        data += request
    elif isinstance(request, dns.message.Message):
        data += request.to_wire(want_shuffle=False)

    if response:
        if isinstance(response, bytes):
            data += response
        elif isinstance(response, dns.message.Message):
            data += response.to_wire(want_shuffle=False)
        else:
            raise TypeError("Unsupported request type")

    return data, sig_template


def _strip_sig0_additional(message: dns.message.Message) -> bytes:
    """Strip all SIG RRs from request additional section and return bytes"""

    res = dns.message.from_wire(
        message.to_wire(want_shuffle=False),
        one_rr_per_rrset=True,
    )
    res.additional = [
        rrset for rrset in message.additional if rrset.rdtype != dns.rdatatype.SIG
    ]

    return res.to_wire(want_shuffle=False)


def _create_sig_rdata(
    request: dns.message.Message | bytes,
    response: dns.message.Message | bytes | None,
    private_key: PrivateKey,
    key: KEY,
    signer: dns.name.Name,
    inception: datetime | str | int | float | None = None,
    expiration: datetime | str | int | float | None = None,
    lifetime: int | None = None,
    verify: bool = False,
    deterministic: bool = True,
) -> SIG:
    """Create SIG RDATA for request/response using private key."""

    if inception is not None:
        sig_inception = to_timestamp(inception)
    else:
        sig_inception = int(time.time())

    if expiration is not None:
        sig_expiration = to_timestamp(expiration)
    elif lifetime is not None:
        sig_expiration = sig_inception + lifetime
    else:
        raise ValueError("expiration or lifetime must be specified")

    data, sig_template = _make_sig_signature_data(
        request=request,
        response=response,
        signer=signer,
        key_tag=key_id(key),
        algorithm=key.algorithm,
        inception=sig_inception,
        expiration=sig_expiration,
    )

    # pylint: disable=possibly-used-before-assignment
    if isinstance(private_key, GenericPrivateKey):
        signing_key = private_key
    else:
        try:
            private_cls = get_algorithm_cls_from_dnskey(cast(DNSKEY, key))
            signing_key = private_cls(key=private_key)
        except UnsupportedAlgorithm:
            raise TypeError("Unsupported key algorithm")

    signature = signing_key.sign(data, verify, deterministic)

    return cast(SIG, sig_template.replace(signature=signature))


def _sign_request(
    request: dns.message.Message,
    private_key: PrivateKey,
    signer: dns.name.Name,
    key: KEY,
    inception: datetime | str | int | float | None = None,
    expiration: datetime | str | int | float | None = None,
    lifetime: int | None = None,
    verify: bool = False,
    deterministic: bool = True,
) -> dns.message.Message:
    """Sign request using private key.

    **request**, a `dns.message.Message` of the request, excluding SIG(0) for queries.

    *private_key*, the private key to use for signing, a ``GenericPrivateKey`` private
    key class applicable for DNSSEC.

    *signer*, a ``dns.name.Name``, the Signer's name.

    *key*, a ``KEY`` matching ``private_key``.

    *inception*, a ``datetime``, ``str``, ``int``, ``float`` or ``None``, the
    signature inception time.  If ``None``, the current time is used.  If a ``str``, the
    format is "YYYYMMDDHHMMSS" or alternatively the number of seconds since the UNIX
    epoch in text form; this is the same the RRSIG rdata's text form.
    Values of type `int` or `float` are interpreted as seconds since the UNIX epoch.

    *expiration*, a ``datetime``, ``str``, ``int``, ``float`` or ``None``, the signature
    expiration time.  If ``None``, the expiration time will be the inception time plus
    the value of the *lifetime* parameter.  See the description of *inception* above
    for how the various parameter types are interpreted.

    *lifetime*, an ``int`` or ``None``, the signature lifetime in seconds.  This
    parameter is only meaningful if *expiration* is ``None``.

    *verify*, a ``bool``.  If set to ``True``, the signer will verify signatures
    after they are created; the default is ``False``.

    *deterministic*, a ``bool``. If ``True``, the default, use deterministic
    (reproducible) signatures when supported by the algorithm used for signing.
    Currently, this only affects ECDSA.
    """

    sig_rr = _create_sig_rdata(
        request=request,
        response=None,
        private_key=private_key,
        key=key,
        signer=signer,
        inception=inception,
        expiration=expiration,
        lifetime=lifetime,
        verify=verify,
        deterministic=deterministic,
    )
    request = dns.message.from_wire(
        request.to_wire(want_shuffle=False), one_rr_per_rrset=True
    )
    request.additional.extend([dns.rrset.from_rdata_list(signer, 0, [sig_rr])])
    return request


def _sign_response(
    request: dns.message.Message,
    response: dns.message.Message,
    private_key: PrivateKey,
    signer: dns.name.Name,
    key: KEY,
    inception: datetime | str | int | float | None = None,
    expiration: datetime | str | int | float | None = None,
    lifetime: int | None = None,
    verify: bool = False,
    deterministic: bool = True,
) -> dns.message.Message:
    """Sign request using private key.

    **request**, a `dns.message.Message` of the request.

    **response**, a `dns.message.Message` of the response, excluding SIG(0).

    *private_key*, the private key to use for signing, a ``GenericPrivateKey`` private
    key class applicable for DNSSEC.

    *signer*, a ``dns.name.Name``, the Signer's name.

    *key*, a ``KEY`` matching ``private_key``.

    *inception*, a ``datetime``, ``str``, ``int``, ``float`` or ``None``, the
    signature inception time.  If ``None``, the current time is used.  If a ``str``, the
    format is "YYYYMMDDHHMMSS" or alternatively the number of seconds since the UNIX
    epoch in text form; this is the same the RRSIG rdata's text form.
    Values of type `int` or `float` are interpreted as seconds since the UNIX epoch.

    *expiration*, a ``datetime``, ``str``, ``int``, ``float`` or ``None``, the signature
    expiration time.  If ``None``, the expiration time will be the inception time plus
    the value of the *lifetime* parameter.  See the description of *inception* above
    for how the various parameter types are interpreted.

    *lifetime*, an ``int`` or ``None``, the signature lifetime in seconds.  This
    parameter is only meaningful if *expiration* is ``None``.

    *verify*, a ``bool``.  If set to ``True``, the signer will verify signatures
    after they are created; the default is ``False``.

    *deterministic*, a ``bool``. If ``True``, the default, use deterministic
    (reproducible) signatures when supported by the algorithm used for signing.
    Currently, this only affects ECDSA.
    """

    sig_rr = _create_sig_rdata(
        request=request,
        response=response,
        private_key=private_key,
        key=key,
        signer=signer,
        inception=inception,
        expiration=expiration,
        lifetime=lifetime,
        verify=verify,
        deterministic=deterministic,
    )

    response = dns.message.from_wire(
        response.to_wire(want_shuffle=False), one_rr_per_rrset=True
    )
    response.additional.extend([dns.rrset.from_rdata_list(signer, 0, [sig_rr])])
    return response


def _validate_signature(sig: bytes, data: bytes, key: KEY) -> None:
    # pylint: disable=possibly-used-before-assignment
    dnskey = cast(DNSKEY, key)
    public_cls = get_algorithm_cls_from_dnskey(dnskey).public_cls
    try:
        public_key = public_cls.from_dnskey(dnskey)
    except ValueError:
        raise ValidationFailure("invalid public key")
    public_key.verify(sig, data)


def _validate(
    request: dns.message.Message,
    sig: SIG,
    keys: dict[dns.name.Name, dns.node.Node | dns.rdataset.Rdataset],
    response: dns.message.Message | None = None,
    now: float | None = None,
) -> None:
    """Validate an RRset against a single signature rdata, throwing an
    exception if validation is not successful.

    **request**, a `dns.message.Message` of the request, excluding SIG(0) for queries.

    **response**, an optional `dns.message.Message` of the response excluding SIG(0).

    *sig*, a ``dns.rdata.Rdata``, the signature to validate.

    *keys*, the key dictionary, used to find the DNSKEY associated
    with a given name.  The dictionary is keyed by a
    ``dns.name.Name``, and has ``dns.node.Node`` or
    ``dns.rdataset.Rdataset`` values.

    *now*, a ``float`` or ``None``, the time, in seconds since the epoch, to
    use as the current time when validating.  If ``None``, the actual current
    time is used.

    Raises ``ValidationFailure`` if the signature is expired, not yet valid,
    the public key is invalid, the algorithm is unknown, the verification
    fails, etc.

    Raises ``UnsupportedAlgorithm`` if the algorithm is recognized by
    dnspython but not implemented.
    """

    dnssig = cast(RRSIG, sig)
    candidate_keys = _find_candidate_keys(keys, dnssig)
    if candidate_keys is None:
        raise ValidationFailure("unknown key")

    if now is None:
        now = time.time()
    if sig.expiration < now:
        raise ValidationFailure("expired")
    if sig.inception > now:
        raise ValidationFailure("not yet valid")

    request_sans_sig0 = _strip_sig0_additional(request)
    response_sans_sig0 = _strip_sig0_additional(response) if response else None

    data, _ = _make_sig_signature_data(
        request=request_sans_sig0,
        response=response_sans_sig0,
        signer=sig.signer,
        key_tag=sig.key_tag,
        algorithm=sig.algorithm,
        inception=sig.inception,
        expiration=sig.expiration,
    )

    for candidate_key in candidate_keys:
        try:
            _validate_signature(sig.signature, data, candidate_key)
            return
        except (InvalidSignature, ValidationFailure):
            # this happens on an individual validation failure
            continue

    raise ValidationFailure("verify failure")


if dns._features.have("dnssec"):
    from cryptography.exceptions import InvalidSignature

    validate = _validate  # type: ignore
    sign_request = _sign_request
    sign_response = _sign_response
    _have_pyca = True
else:  # pragma: no cover
    validate = _need_pyca
    sign_request = _need_pyca
    sign_response = _need_pyca
    _have_pyca = False
