"""
Merkle Mountain Range
"""

import hashlib
import logging
import sys
logging.basicConfig(stream=sys.stderr, level=logging.INFO)


def tree_height(pos: int) -> int:
    """
    Explains:
    https://github.com/mimblewimble/grin/blob/0ff6763ee64e5a14e70ddd4642b99789a1648a32/core/src/core/pmmr.rs#L606
    use binary expression to find tree height(all one position number)
    return pos height
    """
    # convert from 0-based to 1-based position, see document
    pos += 1

    def all_ones(num: int) -> bool:
        return (1 << num.bit_length()) - 1 == num

    def jump_left(pos: int) -> int:
        most_significant_bits = 1 << pos.bit_length() - 1
        return pos - (most_significant_bits - 1)

    # loop until we jump to all ones position, which is tree height
    while not all_ones(pos):
        pos = jump_left(pos)
    # count all 1 bits
    return pos.bit_length() - 1


# get left or right sibling offset by height
def sibling_offset(height) -> int:
    return 2 ** (height + 1) - 1


def get_peaks(mmr_size) -> [int]:
    """
    return peaks positions from left to right
    """
    poss = []
    height, pos = left_peak_height_pos(mmr_size)
    poss.append(pos)
    while height > 0:
        height, pos = get_right_peak(height, pos, mmr_size)
        poss.append(pos)
    return poss


def get_right_peak(height, pos, mmr_size):
    """
    find next right peak
    """
    # jump to right sibling
    pos += sibling_offset(height)
    # jump to left child
    while pos > mmr_size - 1:
        pos -= 2 ** height
        height -= 1
    return (height, pos)


def left_peak_height_pos(mmr_size: int) -> (int, int):
    """
    find left peak
    return (left peak height, pos)
    """
    def get_left_pos(height):
        """
        convert height to binary express, then minus 1 to get 0 based pos
        explain:
        https://github.com/mimblewimble/grin/blob/master/doc/mmr.md#structure
        https://github.com/mimblewimble/grin/blob/0ff6763ee64e5a14e70ddd4642b99789a1648a32/core/src/core/pmmr.rs#L606
        For example:
        height = 2
        # use one-based encoding, mean that left node is all one-bits
        # 0b1 is 0 pos, 0b11 is 2 pos 0b111 is 6 pos
        one_based_binary_encoding = 0b111
        pos = 0b111 - 1 = 6
        """
        return (1 << height + 1) - 2
    height = 0
    prev_pos = 0
    pos = get_left_pos(height)
    # increase height and get most left pos of tree
    # once pos is out of mmr_size we consider previous pos is left peak
    while pos < mmr_size:
        height += 1
        prev_pos = pos
        pos = get_left_pos(height)
    return (height - 1, prev_pos)


class MMR(object):
    """
    MMR
    """
    def __init__(self):
        self.last_pos = -1
        self.pos_hash = {}

    def _hasher(self) -> bin:
        return hashlib.sha256()

    def _int_to_bytes(self, pos):
        return pos.to_bytes(4, 'little')

    def add(self, elem: bin) -> int:
        """
        Insert a new leaf, v is a binary value
        """
        self.last_pos += 1
        hasher = self._hasher()
        hasher.update(elem)
        # store hash
        self.pos_hash[self.last_pos] = hasher.digest()
        height = 0
        pos = self.last_pos
        # merge same sub trees
        # if next pos height is higher implies we are in right children
        # and sub trees can be merge
        while tree_height(self.last_pos + 1) > height:
            # increase pos cursor
            self.last_pos += 1
            # calculate pos of left child and right child
            left_pos = self.last_pos - 2 ** (height + 1)
            right_pos = left_pos + sibling_offset(height)
            hasher = self._hasher()
            # calculate parent hash
            hasher.update(self.pos_hash[left_pos])
            hasher.update(self.pos_hash[right_pos])
            self.pos_hash[self.last_pos] = hasher.digest()
            height += 1
        return pos

    def get_root(self) -> bin:
        """
        MMR root
        """
        peaks = get_peaks(self.last_pos + 1)
        # bag all rhs peaks, which is exact root
        root = self._bag_rhs_peaks(0, peaks)
        if root is not None:
            return root[1]
        else:
            return None

    def gen_proof(self, pos: int) -> [bin]:
        """
        generate a merkle proof
        1. generate merkle tree proof for pos
        2. find peaks positions
        3. find rhs peaks packs into one single hash, then push to proof
        4. find lhs peaks reverse then push to proof

        For peaks: P1, P2, P3, P4, P5, we proof a P4 leaf
        [P4 merkle proof.., P5, P3, P2, P1]
        """
        height, _pos = left_peak_height_pos(self.last_pos + 1)
        proof = []
        height = 0
        # construct merkle proof of one peak
        while pos <= self.last_pos:
            pos_height = tree_height(pos)
            next_height = tree_height(pos + 1)
            if next_height > pos_height:
                # get left child sib
                sib = pos - sibling_offset(height)
                # break if sib is out of mmr
                if sib > self.last_pos:
                    break
                proof.append((sib, self.get_hash(sib, height)))
                # goto parent node
                pos += 1
            else:
                # get right child
                sib = pos + sibling_offset(height)
                # break if sib is out of mmr
                if sib > self.last_pos:
                    break
                proof.append((sib, self.get_hash(sib, height)))
                # goto parent node
                pos += 2 ** (height + 1)
            height += 1
        # now pos is peak of the mountain(because pos can't find a sibling)
        peak_pos = pos
        peaks = get_peaks(self.last_pos + 1)
        # bagging rhs peaks into one hash
        rhs_peak_hash = self._bag_rhs_peaks(peak_pos, peaks)
        if rhs_peak_hash is not None:
            proof.append(rhs_peak_hash)
        # insert lhs peaks
        proof.extend(reversed(self._lhs_peaks(peak_pos, peaks)))
        return MerkleProof(mmr_size=self.last_pos + 1, proof=proof)

    def _bag_rhs_peaks(self, peak_pos: int, peaks: [int]):
        rhs_peak_hashes = [(p, self.pos_hash[p]) for p in peaks
                           if p > peak_pos]
        while len(rhs_peak_hashes) > 1:
            peak_r = rhs_peak_hashes.pop()
            peak_l = rhs_peak_hashes.pop()
            hasher = self._hasher()
            hasher.update(peak_r[1])
            hasher.update(peak_l[1])
            rhs_peak_hashes.append((peak_r[0] + peak_l[0], hasher.digest()))
        if len(rhs_peak_hashes) > 0:
            return rhs_peak_hashes[0]
        else:
            return None

    def _lhs_peaks(self, peak_pos: int, peaks: [int]):
        return [(p, self.pos_hash[p]) for p in peaks if p < peak_pos]

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
        logging.debug('get_hash %s %s %s', pos, height, hash)
        return hash


class MerkleProof(object):
    """
    MerkleProof, used for verify a proof
    """
    def __init__(self, mmr_size: int, proof: [bin]):
        self.mmr_size = mmr_size
        self.proof = proof

    def _hasher(self) -> bin:
        return hashlib.sha256()

    def verify(self, root: bin, pos: int, elem: bin) -> bool:
        """
        verify proof
        root - MMR root that generate this proof
        pos - elem insertion pos
        elem - elem
        """
        peaks = get_peaks(self.mmr_size)
        hasher = self._hasher()
        hasher.update(elem)
        elem_hash = hasher.digest()
        height = 0
        logging.debug('proof is %s', self.proof)
        for (proof_pos, proof) in self.proof:
            hasher = self._hasher()
            # verify bagging peaks
            if pos in peaks:
                if pos == peaks[-1]:
                    hasher.update(elem_hash)
                    hasher.update(proof)
                else:
                    hasher.update(proof)
                    hasher.update(elem_hash)
                    pos = peaks[-1]
                elem_hash = hasher.digest()
                continue

            # verify merkle path
            pos_height = tree_height(pos)
            next_height = tree_height(pos + 1)
            if next_height > pos_height:
                logging.debug('right %s', pos)
                logging.debug('proof %s', proof)
                # we are in right child
                hasher.update(proof)
                hasher.update(elem_hash)
                pos += 1
                logging.debug('left child is %s', proof)
                logging.debug('right child is %s', elem_hash)
            else:
                logging.debug('left %s', pos)
                # we are in left child
                hasher.update(elem_hash)
                hasher.update(proof)
                logging.debug('left child is %s', elem_hash)
                logging.debug('right child is %s', proof)
                pos += 2 ** (height + 1)
            elem_hash = hasher.digest()
            height += 1
            logging.debug('----parent is %s %s %s', proof_pos, elem_hash, pos)
        logging.debug('----parent is %s %s %s', proof_pos, elem_hash, pos)
        logging.debug(elem_hash)
        logging.debug(root)
        return elem_hash == root


def test_mmr():
    def serialize(i):
        return i.to_bytes(4, 'little')

    mmr = MMR()
    # push 0..11 into MMR, and record MMR positions
    positions = [mmr.add(serialize(i)) for i in range(0, 11)]
    merkle_root = mmr.get_root()
    # proof
    elem = 5
    pos = positions[elem]
    # generate proof for 5
    proof = mmr.gen_proof(pos)
    # verify proof
    result = proof.verify(root=merkle_root, pos=pos,
                          elem=serialize(elem))
    assert(result)


if __name__ == "__main__":
    test_mmr()
    print("tests passed")
