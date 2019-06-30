import unittest
from mmr import MMR


class MMRTest(unittest.TestCase):
    def run_mmr(self, count, proof_elem, hasher=None):
        def serialize(i):
            return i.to_bytes(4, 'little')

        if hasher is None:
            mmr = MMR()
        else:
            mmr = MMR(hasher=hasher)
        # push 0..count into MMR, and record MMR positions
        positions = [mmr.add(serialize(i)) for i in range(0, count)]
        merkle_root = mmr.get_root()
        # proof
        pos = positions[proof_elem]
        # generate proof for proof_elem
        proof = mmr.gen_proof(pos)
        # verify proof
        result = proof.verify(root=merkle_root, pos=pos,
                              elem=serialize(proof_elem))
        self.assertTrue(result)

    def test_mmr_tree_peaks(self):
        # tree peaks
        self.run_mmr(11, 5)

    def test_mmr_two_peaks(self):
        # two peaks
        self.run_mmr(10, 5)

    def test_mmr_one_peak(self):
        # one peak
        self.run_mmr(8, 5)

    def test_mmr_first_elem(self):
        # first elem
        self.run_mmr(11, 0)

    def test_mmr_last_elem(self):
        # last elem
        self.run_mmr(11, 10)

    def test_mmr_one_elem(self):
        self.run_mmr(1, 0)

    def test_mmr_two_elems(self):
        self.run_mmr(2, 0)
        self.run_mmr(2, 1)

    def test_customize_hasher(self):
        import hashlib
        self.run_mmr(11, 5, hasher=hashlib.sha3_256)


if __name__ == '__main__':
    unittest.main()
