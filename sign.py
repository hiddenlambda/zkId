from zokrates_pycrypto.eddsa import PrivateKey
from zokrates_pycrypto.field import FQ
from zokrates_pycrypto.utils import to_bytes

if __name__ == "__main__":
    # sk = PrivateKey.from_rand()
    # Seeded for debug purpose
    key = FQ(1997011358982923168928344992199991480689546837621580239342656433234255379025)
    sk = PrivateKey(key)
    print("sk: ", sk)
    print(sk.sign(
        to_bytes(1711356323507237180552937552317790917782970328860998733130523775749559859825) +
        to_bytes(14095131731246428772852652665573772750096871572312120894325648105939092536841)
    ))
