import hashlib
import itertools
import unittest

import dns.merkle3


def H(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


class Merkle3TestCase(unittest.TestCase):

    def test_empty(self):
        m = dns.merkle3.Merkle3(hashlib.sha384)
        self.assertEqual(m.digest(), hashlib.sha384(b"").digest())
        self.assertEqual(len(m), 0)

    def test_non_empty(self):
        m = dns.merkle3.Merkle3(hashlib.sha384)
        m.update(b"some data")
        # root = H(level1), level1 = H(level2), level2 = H(leaf)
        self.assertEqual(m.digest(), H(H(H(H(b"some data")))))
        self.assertEqual(len(m), 1)

    def test_multiple(self):
        m = dns.merkle3.Merkle3(hashlib.sha384)

        i1, i2 = m.update(b"foo")
        self.assertEqual(i1, 152)
        self.assertEqual(i2, 193)

        i1, i2 = m.update(b"bar")
        self.assertEqual(i1, 20)
        self.assertEqual(i2, 145)

        d = m.digest()
        self.assertEqual(
            d.hex(),
            "8f0164886d2d1aec750fe056a165e991155a754bddf219128671dc24c6fed246cb9ac5ab32c62e4c06c5b2d3fd7b982e",
        )

        i1, i2 = m.update(b"bar")
        self.assertEqual(i1, 20)
        self.assertEqual(i2, 145)

        d = m.digest()
        self.assertEqual(
            d.hex(),
            "e3da6290f8d6da9e06099adccc4e0cd54d1b765095be0599cd73ef09921f61f1f696d7a0876a001391fbe06f47eff8df",
        )

        self.assertEqual(len(m), 3)

    def test_remove(self):
        m = dns.merkle3.Merkle3(hashlib.sha384)
        m.update(b"foo")
        m.update(b"bar")
        self.assertEqual(len(m), 2)
        self.assertTrue(m.remove(b"foo"))
        self.assertEqual(len(m), 1)
        self.assertFalse(m.remove(b"foo"))
        self.assertEqual(len(m), 1)
        self.assertTrue(m.remove(b"bar"))
        self.assertEqual(len(m), 0)
        self.assertEqual(m.digest(), dns.merkle3.Merkle3(hashlib.sha384).digest())

    def test_remove_duplicate(self):
        m = dns.merkle3.Merkle3(hashlib.sha384)
        m.update(b"foo")
        m.update(b"bar")
        m.update(b"bar")
        self.assertTrue(m.remove(b"bar"))
        self.assertEqual(len(m), 2)
        expected = dns.merkle3.Merkle3(hashlib.sha384)
        expected.update(b"foo")
        expected.update(b"bar")
        self.assertEqual(m.digest(), expected.digest())

    def test_remove_digest(self):
        # After removing data, the digest must equal that of a trie that
        # never contained it.
        data = [b"foo", b"bar", b"data352", b"data391", b"data17", b"data19"]
        for removed in data:
            m = dns.merkle3.Merkle3(hashlib.sha384)
            expected = dns.merkle3.Merkle3(hashlib.sha384)
            for d in data:
                m.update(d)
                if d != removed:
                    expected.update(d)
            self.assertTrue(m.remove(removed))
            self.assertEqual(m.digest(), expected.digest())

    def test_same_level2_bucket(self):
        # b"data352" and b"data391" both land in bucket (152, 192)
        m = dns.merkle3.Merkle3(hashlib.sha384)
        self.assertEqual(m.update(b"data352"), (152, 192))
        self.assertEqual(m.update(b"data391"), (152, 192))
        leaves = sorted([H(b"data352"), H(b"data391")])
        self.assertEqual(m.digest(), H(H(H(b"".join(leaves)))))
        self.assertEqual(len(m), 2)

    def test_same_level1_bucket(self):
        # b"data17" and b"data19" share index1 54, with index2 105 and 80
        m = dns.merkle3.Merkle3(hashlib.sha384)
        self.assertEqual(m.update(b"data17"), (54, 105))
        self.assertEqual(m.update(b"data19"), (54, 80))
        # level-2 nodes are ordered by index2, so 80 comes before 105
        level1 = H(H(H(b"data19")) + H(H(b"data17")))
        self.assertEqual(m.digest(), H(level1))

    def test_different_level1_buckets(self):
        m = dns.merkle3.Merkle3(hashlib.sha384)
        self.assertEqual(m.update(b"foo"), (152, 193))
        self.assertEqual(m.update(b"bar"), (20, 145))
        # level-1 nodes are ordered by index1, so 20 comes before 152
        expected = H(H(H(H(b"bar"))) + H(H(H(b"foo"))))
        self.assertEqual(m.digest(), expected)

    def test_insertion_order_independent(self):
        data = [b"foo", b"bar", b"data352", b"data391", b"data17", b"data19"]
        digests = set()
        for permutation in itertools.permutations(data):
            m = dns.merkle3.Merkle3(hashlib.sha384)
            for d in permutation:
                m.update(d)
            digests.add(m.digest())
        self.assertEqual(len(digests), 1)

    def test_sha512(self):
        m = dns.merkle3.Merkle3(hashlib.sha512)
        m.update(b"some data")
        expected = b"some data"
        for _ in range(4):
            expected = hashlib.sha512(expected).digest()
        self.assertEqual(m.digest(), expected)
        self.assertEqual(len(m.digest()), 64)

    def test_draft_example(self):
        # Example from Section 2.2 of draft-aklpdw-dnsop-zonemd-incremental:
        #
        # example.com.  300  IN  SOA   mname.example.com. rname.example.com. (
        #                              1 3600 7200 43200 300 )
        # example.com.   60  IN  NS    ns1.foo.example.
        # example.com.  300  IN  AAAA  2606:4700:10::ac42:93f3
        # example.com.  300  IN  AAAA  2606:4700:10::6814:179a
        #
        # Each entry is the canonical wire form of one RRset, the leaf hash
        # given in the draft, and the expected (index1, index2).
        rrsets = [
            (
                # NS
                "076578616d706c6503636f6d00000200010000003c0011036e733103666f6f"
                "076578616d706c6500",
                "089AAD19F7AE6D16D4BBA103E784AA8F0E2818E56921C4395F59EC80A3C4C856"
                "10D50D7D5B3A1DD78C51C0ED5A9F45CC",
                (0x08, 0x9A),
            ),
            (
                # SOA
                "076578616d706c6503636f6d00000600010000012c003a056d6e616d65076578"
                "616d706c6503636f6d0005726e616d65076578616d706c6503636f6d00000000"
                "0100000e1000001c200000a8c00000012c",
                "B5EE62F73B9094B4B0E1FCF899FADBD55972359A355C82C924CEA28A1B73959E"
                "CA9D6D00670FF32A873B8AD03721A181",
                (0xB5, 0xEE),
            ),
            (
                # AAAA (both records, in canonical order)
                "076578616d706c6503636f6d00001c00010000012c00102606470000100000"
                "000000006814179a076578616d706c6503636f6d00001c00010000012c0010"
                "260647000010000000000000ac4293f3",
                "9CDD7D2DB2C820F54DF2F64690A68665D3459BEACC09F21657D01848B2D195A9"
                "5C0E24C3E7458B95B03EFBDC8B252DEF",
                (0x9C, 0xDD),
            ),
        ]
        m = dns.merkle3.Merkle3(hashlib.sha384)
        for data_hex, leaf_hex, indices in rrsets:
            data = bytes.fromhex(data_hex)
            self.assertEqual(H(data), bytes.fromhex(leaf_hex))
            self.assertEqual(m.update(data), indices)
        self.assertEqual(len(m), 3)
        self.assertEqual(
            m.digest(),
            bytes.fromhex(
                "5F0AD47C76A59B6E287E221C296EA5C899AE5D473E4AE0E3FF0FCEDF3E2345BE"
                "7FC9F27CA13077754C98BB53B6288B64"
            ),
        )

    def test_digest_cache(self):
        # Interleave changes with digest() calls, so that the cached node
        # hashes are reused, and compare with a freshly built trie each time.
        data = [b"foo", b"bar", b"data352", b"data391", b"data17", b"data19"]
        ops = [(True, d) for d in data] + [(False, d) for d in data]
        m = dns.merkle3.Merkle3(hashlib.sha384)
        present: list[bytes] = []
        for add, d in ops:
            if add:
                m.update(d)
                present.append(d)
            else:
                self.assertTrue(m.remove(d))
                present.remove(d)
            expected = dns.merkle3.Merkle3(hashlib.sha384)
            for p in present:
                expected.update(p)
            self.assertEqual(m.digest(), expected.digest())
            # A second call must return the same cached root.
            self.assertEqual(m.digest(), expected.digest())
        self.assertEqual(m.digest(), H(b""))

    def test_digest_recompute(self):
        # digest(recompute=True) must agree with the cached digest() after every
        # change, and must not depend on digest() having been called.
        data = [b"foo", b"bar", b"data352", b"data391", b"data17", b"data19"]
        m = dns.merkle3.Merkle3(hashlib.sha384)
        self.assertEqual(m.digest(recompute=True), H(b""))
        for d in data:
            m.update(d)
            full = m.digest(recompute=True)
            self.assertEqual(full, m.digest())
            self.assertEqual(full, m.digest(recompute=True))
        for d in data:
            m.remove(d)
            self.assertEqual(m.digest(recompute=True), m.digest())
        self.assertEqual(m.digest(recompute=True), H(b""))
