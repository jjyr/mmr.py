"""
Merkle Mountain Range
"""

import hashlib
import logging, sys
logging.basicConfig(stream=sys.stderr, level=logging.INFO)


class MMR(object):
    def __init__(self):
        self.inner = []
        self.pos_hash = {}

    def _hasher(self) -> bin:
        return hashlib.sha256()

    def _int_to_bytes(self, pos):
        return pos.to_bytes(4, 'little')

    def add(self, v: bin):
        pos = len(self.inner)
        hasher = self._hasher()
        hasher.update(v)
        # store hash
        self.pos_hash[pos] = hasher.digest()
        self.inner.append(0)
        # try merge same sub trees
        height = 0
        while True:
            # calculate pffset of current node and previous sibling
            sibling_offset = self.sibling_offset(height)
            # check height, merge subtrees if the height is same
            if len(self.inner) <= sibling_offset:
                break
            elif self.inner[-1] != self.inner[-1 - sibling_offset]:
                break
            pos = len(self.inner)
            left_pos = pos - 2 ** (height + 1)
            right_pos = left_pos + sibling_offset
            # print('node pos', pos, 'left' , left_pos, 'right', right_pos)
            hasher = self._hasher()
            # parent hash
            hasher.update(self.pos_hash[left_pos])
            hasher.update(self.pos_hash[right_pos])
            self.pos_hash[pos] = hasher.digest()
            height += 1
            self.inner.append(height)

    def sibling_offset(self, height) -> int:
        return 2 ** (height + 1) - 1

    def get_peaks(self) -> [bin]:
        """
        return peaks from left to right
        """
        poss = []
        height, pos = self._get_left_peak()
        poss.append(self.pos_hash[pos])
        while height > 0:
            height, pos = self._get_right_peak(height, pos)
            poss.append(self.pos_hash[pos])
        return poss

    # TODO optimize this
    def _get_left_peak(self) -> (int, int):
        height = 0
        prev_pos = 0
        # try to get left peak
        while True:
            pos = self.sibling_offset(height) - 1
            # once pos is out of length we consider previous pos is left peak
            if pos > len(self.inner) - 1:
                assert(self.inner[prev_pos] is not None)
                return (height - 1, prev_pos)
            else:
                height += 1
                prev_pos = pos

    def _get_right_peak(self, height, pos):
        """
        find next right peak
        """
        assert(self.inner[pos] is not None)
        # jump to right sibling
        pos += self.sibling_offset(height)
        # jump to left child
        while pos > len(self.inner) - 1:
            pos -= 2 ** height
            height -= 1
        return (height, pos)

    def get_root(self) -> bin:
        height, pos = self._get_left_peak()
        if pos == len(self.inner) - 1:
            return self.get_hash(pos, height)
        else:
            pos += 2 ** (height + 1)
            return self.get_hash(pos, height + 1)

    # convert leaf pos to inner pos
    # TODO optimize this
    def _leaf_to_inner(self, leaf_pos: int) -> int:
        count = 0
        for i, elem in enumerate(self.inner):
            if elem == 0:
                count += 1
            if count == leaf_pos:
                return i
        raise ValueError("leaf_pos do not exists")

    def gen_proof(self, leaf_pos: int) -> [bin]:
        """
        generate a merkle proof
        1. find and push sibling hash
           1. calculate virtual sibling if reach a peak
        2. increase height
        3. return proof if reach MMR height(height + 1)
        """
        # convert leaf index to inner index
        pos = self._leaf_to_inner(leaf_pos + 1)
        assert(self.inner[pos] is not None)
        height, _pos = self._get_left_peak()
        proof = []
        proof_size = height + 1
        height = 0
        while len(proof) < proof_size:
            sibling_offset = self.sibling_offset(height)
            if leaf_pos % 2 == 0:
                # leaf is left child
                pos2 = pos + sibling_offset
                proof.append((pos2, self.get_hash(pos2, height)))
                # goto parent node
                pos += 2 ** (height + 1)
            else:
                # leaf is right child
                pos2 = pos - sibling_offset
                proof.append((pos2, self.get_hash(pos2, height)))
                # goto parent node
                pos = pos + 1
            height += 1
            leaf_pos //= 2
        return proof

    def get_hash(self, pos: int, height: int) -> bin:
        """
        get hash from pos,
        pos must less than 2 ** (height + 1)
        """
        self_height, _pos = self._get_left_peak()
        assert(pos < 2 ** (self_height + 2) - 1)
        if self.pos_hash.get(pos) is not None:
            return self.pos_hash[pos]
        elif height == 0:
            return None
        # we hit a virtual node(not recorded in inner)
        # find left child
        left_pos = pos - 2 ** height
        right_pos = left_pos + self.sibling_offset(height - 1)
        left = self.get_hash(left_pos, height - 1)
        if left is None:
            return None
        right = self.get_hash(right_pos, height - 1)
        hasher = self._hasher()
        hasher.update(left)
        if right is not None:
            hasher.update(right)
        hash = hasher.digest()
        logging.debug('get_hash', pos, height, hash)
        return hash

    def verify_proof(self, root: bin, leaves: int, leaf_pos: int,
                     elem: bin,
                     merkle_proof: [bin]) -> bool:
        height, _pos = self._get_left_peak()
        # proof is log(n), exactly is our height + 1
        if len(merkle_proof) != height + 1:
            raise ValueError("invalid proof size")
        hasher = self._hasher()
        hasher.update(elem)
        elem_hash = hasher.digest()
        for (proof_pos, proof) in merkle_proof:
            hasher = self._hasher()
            if leaf_pos % 2 == 0:
                logging.debug('left', leaf_pos)
                # we are in left child
                hasher.update(elem_hash)
                hasher.update(proof)
                logging.debug('left child is', elem_hash)
                logging.debug('right child is', proof)
            else:
                logging.debug('right', leaf_pos)
                logging.debug('proof', proof)
                logging.debug('9 is ', self.pos_hash[9])
                logging.debug('13 is ', self.pos_hash[13])
                logging.debug('14 is ', self.pos_hash[14])
                logging.debug('30 is ', self.get_hash(30,4))
                # we are in right child
                hasher.update(proof)
                hasher.update(elem_hash)
                logging.debug('left child is', proof)
                logging.debug('right child is', elem_hash)
            elem_hash = hasher.digest()
            logging.debug('----parent is', proof_pos, elem_hash, leaf_pos, leaves)
            # reduce pos and leaves to our subtree
            leaf_pos = leaf_pos // 2
            leaves = leaves // 2
        return elem_hash == root


def test_mmr():
    mmr = MMR()
    for i in range(0, 11):
        mmr.add(i.to_bytes(4, 'little'))
    assert(mmr.inner ==
           [0, 0, 1, 0, 0, 1, 2, 0, 0, 1, 0, 0, 1, 2, 3, 0, 0, 1, 0])
    merkle_root = mmr.get_root()
    proof = mmr.gen_proof(5)
    logging.debug('proof', proof)
    elem = 5
    result = mmr.verify_proof(root=merkle_root, leaves=11, leaf_pos=5,
                              elem=elem.to_bytes(4, 'little'),
                              merkle_proof=proof)
    assert(result)


if __name__ == "__main__":
    test_mmr()
    print("tests passed")
