# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import hashlib
from collections import defaultdict
from typing import Callable

HashFactory = Callable[[bytes], "hashlib._Hash"]


class Merkle3:
    """Merkle3 trie implementation for computing Merkle root hashes.

    https://datatracker.ietf.org/doc/draft-aklpdw-dnsop-zonemd-incremental/
    """

    def __init__(self, hashinfo: HashFactory):
        self.hashinfo = hashinfo
        self.trie: defaultdict[int, defaultdict[int, list[bytes]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def update(self, data: bytes) -> tuple[int, int]:
        """Update the Merkle trie with the given data.

        :param data: The data to add to the trie.
        :type data: bytes
        :return: The indices in the trie where the data was added.
        :rtype: tuple[int, int]
        """

        leaf = self.hashinfo(data).digest()
        index1, index2 = leaf[0], leaf[1]
        self.trie[index1][index2].append(leaf)
        return index1, index2

    def digest(self) -> bytes:
        """Compute the Merkle root of the trie.

        :return: The Merkle root hash.
        :rtype: bytes
        """

        level1_leaves = []
        for index1 in sorted(self.trie):
            level1 = self.trie[index1]
            level2_leaves = [
                self.hashinfo(b"".join(sorted(level1[index2]))).digest()
                for index2 in sorted(level1)
            ]
            level1_leaves.append(self.hashinfo(b"".join(level2_leaves)).digest())
        return self.hashinfo(b"".join(level1_leaves)).digest()
