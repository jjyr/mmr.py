import unittest
from mmr import MMR


class MMRTest(unittest.TestCase):
    def test_mmr(self):
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
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
