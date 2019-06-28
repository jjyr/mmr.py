"""
Merkle Mountain Range
"""

import hashlib
import logging, sys
logging.basicConfig(stream=sys.stderr, level=logging.INFO)


# https://github.com/mimblewimble/grin/blob/0ff6763ee64e5a14e70ddd4642b99789a1648a32/core/src/core/pmmr.rs#L606
# use binary expression to find tree height(all one position number)
def tree_height(pos: int) -> int:
    # convert from 0-based to 1-based position, see document
    pos += 1
    def all_ones(num: int) -> bool:
        return (1 << num.bit_length()) - 1 == num
    def jump_left(pos: int) -> int:
        most_significant_bits =  1 << pos.bit_length() - 1
        return pos - (most_significant_bits - 1)

    # loop until we jump to all ones position, which is tree height
    while not all_ones(pos):
        pos = jump_left(pos)
    # count all 1 bits
    return pos.bit_length() - 1

def sibling_offset(height) -> int:
    return 2 ** (height + 1) - 1

# TODO optimize this
def left_peak_height_pos(mmr_size: int) -> (int, int):
    height = 0
    prev_pos = 0
    # try to get left peak
    while True:
        pos = sibling_offset(height) - 1
        # once pos is out of length we consider previous pos is left peak
        if pos > mmr_size - 1:
            return (height - 1, prev_pos)
        else:
            height += 1
            prev_pos = pos

class MMR(object):
    def __init__(self):
        self.last_pos = -1
        self.pos_hash = {}

    def _hasher(self) -> bin:
        return hashlib.sha256()

    def _int_to_bytes(self, pos):
        return pos.to_bytes(4, 'little')

    def add(self, v: bin):
        self.last_pos += 1
        hasher = self._hasher()
        hasher.update(v)
        # store hash
        self.pos_hash[self.last_pos] = hasher.digest()
        height = 0
        # try merge same sub trees
        while tree_height(self.last_pos + 1) > height:
            # calculate pffset of current node and previous sibling
            self.last_pos += 1
            left_pos = self.last_pos - 2 ** (height + 1)
            right_pos = left_pos + sibling_offset(height)
            # print('node pos', pos, 'left' , left_pos, 'right', right_pos)
            hasher = self._hasher()
            # parent hash
            hasher.update(self.pos_hash[left_pos])
            hasher.update(self.pos_hash[right_pos])
            self.pos_hash[self.last_pos] = hasher.digest()
            height += 1

    def get_peaks(self) -> [int]:
        """
        return peaks from left to right
        """
        poss = []
        height, pos = left_peak_height_pos(self.last_pos + 1)
        poss.append(pos)
        while height > 0:
            height, pos = self._get_right_peak(height, pos)
            poss.append(pos)
        return poss

    def _get_right_peak(self, height, pos):
        """
        find next right peak
        """
        # jump to right sibling
        pos += sibling_offset(height)
        # jump to left child
        while pos > self.last_pos:
            pos -= 2 ** height
            height -= 1
        return (height, pos)

    def get_root(self) -> bin:
        height, pos = left_peak_height_pos(self.last_pos + 1)
        if pos == self.last_pos:
            return self.get_hash(pos, height)
        else:
            pos += 2 ** (height + 1)
            return self.get_hash(pos, height + 1)

    # convert leaf pos to inner pos
    # TODO optimize this
    def gen_proof(self, pos: int) -> [bin]:
        """
        generate a merkle proof
        1. find and push sibling hash
           1. calculate virtual sibling if reach a peak
        2. increase height
        3. return proof if reach MMR height(height + 1)
        """
        height, _pos = left_peak_height_pos(self.last_pos + 1)
        proof = []
        proof_size = height + 1
        height = 0
        while len(proof) < proof_size:
            pos_height = tree_height(pos)
            next_height = tree_height(pos + 1)
            if next_height > pos_height:
                # get left child sib
                sib = pos - sibling_offset(height)
                proof.append((sib, self.get_hash(sib, height)))
                # goto parent node
                pos += 1
            else:
                # get right child
                sib = pos + sibling_offset(height)
                proof.append((sib, self.get_hash(sib, height)))
                # goto parent node
                pos += 2 ** (height + 1)
            height += 1
        return proof

    def get_hash(self, pos: int, height: int) -> bin:
        """
        get hash from pos,
        pos must less than 2 ** (height + 1)
        """
        self_height, _pos = left_peak_height_pos(self.last_pos + 1)
        assert(pos < 2 ** (self_height + 2) - 1)
        if self.pos_hash.get(pos) is not None:
            return self.pos_hash[pos]
        elif height == 0:
            return None
        # we hit a virtual node(not recorded in inner)
        # find left child
        left_pos = pos - 2 ** height
        right_pos = left_pos + sibling_offset(height - 1)
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
        height, _pos = left_peak_height_pos(self.last_pos + 1)
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
    merkle_root = mmr.get_root()
    proof = mmr.gen_proof(8)
    logging.debug('proof', proof)
    elem = 5
    result = mmr.verify_proof(root=merkle_root, leaves=11, leaf_pos=5,
                              elem=elem.to_bytes(4, 'little'),
                              merkle_proof=proof)
    assert(result)


if __name__ == "__main__":
    test_mmr()
    print("tests passed")
