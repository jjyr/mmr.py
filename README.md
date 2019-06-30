# MMR.py

Merkle Mountain Range

## Install

`pip3 install -U git+https://github.com/jjyr/mmr.py.git`

## Example

``` python 
from mmr import MMR

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
    print("Ok")

test_mmr()
```

See [tests](tests) to learn more.

## License

MIT

