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

import time
import unittest

import dns.dnssec
import dns.name
import dns.rrset
import dns.message
import dns.sig0
import dns.rdtypes
import dns.rdatatype
import dns.rdataclass
import dns.zone
from typing import cast

query_text = """id 1234
opcode QUERY
rcode NOERROR
flags RD
edns 0
eflags DO
payload 4096
;QUESTION
wwww.dnspython.org. IN A
;ANSWER
;AUTHORITY
;ADDITIONAL"""

answer_text = """id 1234
opcode QUERY
rcode NOERROR
flags QR AA RD
;QUESTION
dnspython.org. IN SOA
;ANSWER
dnspython.org. 3600 IN SOA woof.dnspython.org. hostmaster.dnspython.org. 2003052700 3600 1800 604800 3600
;AUTHORITY
dnspython.org. 3600 IN NS ns1.staff.nominum.org.
dnspython.org. 3600 IN NS ns2.staff.nominum.org.
dnspython.org. 3600 IN NS woof.play-bow.org.
;ADDITIONAL
woof.play-bow.org. 3600 IN A 204.152.186.150
"""


try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    pass  # Cryptography ImportError already handled in dns.dnssec

    def default_backend():
        raise NotImplementedError


SIGNATURE_OFFSET = 300
SIGNATURE_LIFETIME = 300
SIGNATURE_TIMESTAMP = int(time.time())


@unittest.skipUnless(dns.dnssec._have_pyca, "Python Cryptography cannot be imported")
class Sig0(unittest.TestCase):

    def test_sign_request(self):
        request = dns.message.from_text(query_text)
        signer = dns.name.from_text("signer.example.com.")
        private_key = ed25519.Ed25519PrivateKey.generate()
        key = cast(
            dns.rdtypes.ANY.KEY,
            dns.dnssec.make_dnskey(
                public_key=private_key.public_key(),
                algorithm=dns.dnssec.Algorithm.ED25519,
            ),
        )

        signed_request = dns.sig0.sign_request(
            request=request,
            private_key=private_key,
            signer=signer,
            key=key,
            inception=SIGNATURE_TIMESTAMP - SIGNATURE_OFFSET,
            expiration=SIGNATURE_TIMESTAMP + SIGNATURE_LIFETIME,
            verify=True,
            deterministic=True,
        )

        keys = {signer: dns.rrset.from_rdata_list(signer, 0, [key])}

        signed_request = dns.message.from_wire(
            signed_request.to_wire(want_shuffle=False), one_rr_per_rrset=True
        )

        for sig in signed_request.find_rrset(
            section=signed_request.additional,
            name=signer,
            rdclass=dns.rdataclass.ANY,
            rdtype=dns.rdatatype.SIG,
        ):

            dns.sig0.validate(
                request=signed_request,
                keys=keys,
                sig=sig,
                now=SIGNATURE_TIMESTAMP,
            )

    def test_sign_response(self):
        request = dns.message.from_text(query_text)
        response = dns.message.from_text(answer_text)

        signer = dns.name.from_text("signer.example.com.")
        private_key = ed25519.Ed25519PrivateKey.generate()
        key = cast(
            dns.rdtypes.ANY.KEY,
            dns.dnssec.make_dnskey(
                public_key=private_key.public_key(),
                algorithm=dns.dnssec.Algorithm.ED25519,
            ),
        )

        signed_response = dns.sig0.sign_response(
            request=request,
            response=response,
            private_key=private_key,
            signer=signer,
            key=key,
            inception=SIGNATURE_TIMESTAMP - SIGNATURE_OFFSET,
            expiration=SIGNATURE_TIMESTAMP + SIGNATURE_LIFETIME,
            verify=True,
            deterministic=True,
        )

        keys = {signer: dns.rrset.from_rdata_list(signer, 0, [key])}

        signed_response = dns.message.from_wire(
            signed_response.to_wire(want_shuffle=False), one_rr_per_rrset=True
        )

        for sig in signed_response.find_rrset(
            section=signed_response.additional,
            name=signer,
            rdclass=dns.rdataclass.ANY,
            rdtype=dns.rdatatype.SIG,
        ):

            dns.sig0.validate(
                request=request,
                response=signed_response,
                keys=keys,
                sig=sig,
                now=SIGNATURE_TIMESTAMP,
            )


if __name__ == "__main__":
    unittest.main()
