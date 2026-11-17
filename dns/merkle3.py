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
        # Cached interior node hashes, so that digest() only needs to
        # recompute the nodes on the paths changed since the last call.
        self._level1_hashes: dict[int, bytes] = {}
        self._level2_hashes: dict[int, dict[int, bytes]] = {}
        self._dirty: dict[int, set[int]] = {}
        self._root: bytes | None = None

    def _mark_dirty(self, index1: int, index2: int) -> None:
        self._dirty.setdefault(index1, set()).add(index2)
        self._root = None

    def __len__(self) -> int:
        """Return the total number of leaves in the trie."""
        return sum(
            len(level2) for level1 in self.trie.values() for level2 in level1.values()
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
        self._mark_dirty(index1, index2)
        return index1, index2

    def remove(self, data: bytes) -> bool:
        """Remove one leaf for the given data from the trie.

        Duplicate leaves are kept as separate entries, so if the same data
        was added more than once, only one of the leaves is removed.

        :param data: The data to remove from the trie.
        :type data: bytes
        :return: ``True`` if a leaf was removed, ``False`` if the data was
          not in the trie.
        :rtype: bool
        """

        leaf = self.hashinfo(data).digest()
        index1, index2 = leaf[0], leaf[1]
        # Use get() so that a lookup does not create empty buckets.
        level2 = self.trie.get(index1, {}).get(index2, [])
        if leaf not in level2:
            return False
        level2.remove(leaf)
        self._mark_dirty(index1, index2)
        if not level2:
            del self.trie[index1][index2]
            if not self.trie[index1]:
                del self.trie[index1]
        return True

    def digest(self, recompute: bool = False) -> bytes:
        """Compute the Merkle root of the trie.

        :param recompute: If ``True``, recompute the Merkle root from scratch instead of using cached hashes.
        :type recompute: bool
        :return: The Merkle root hash.
        :rtype: bytes
        """

        if recompute:
            return self._digest_full()

        if self._root is not None:
            return self._root

        hashinfo = self.hashinfo

        for index1, indices2 in self._dirty.items():
            level1 = self.trie.get(index1)
            if level1 is None:
                # The whole level-1 node was emptied by remove().
                self._level1_hashes.pop(index1, None)
                self._level2_hashes.pop(index1, None)
                continue
            level2_hashes = self._level2_hashes.setdefault(index1, {})
            for index2 in indices2:
                leaves = level1.get(index2)
                if leaves is None:
                    level2_hashes.pop(index2, None)
                else:
                    level2_hashes[index2] = hashinfo(b"".join(sorted(leaves))).digest()
            self._level1_hashes[index1] = hashinfo(
                b"".join(level2_hashes[index2] for index2 in sorted(level2_hashes))
            ).digest()

        self._dirty.clear()
        self._root = hashinfo(
            b"".join(
                self._level1_hashes[index1] for index1 in sorted(self._level1_hashes)
            )
        ).digest()

        return self._root

    def _digest_full(self) -> bytes:
        """Compute the Merkle root of the trie from scratch.

        Unlike :py:meth:`digest`, this does not use or update the cached
        node hashes. It is slower, but useful for verifying the cache.

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
