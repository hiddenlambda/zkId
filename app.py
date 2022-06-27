from dataclasses import dataclass
from typing import Any, Dict, Tuple, List
from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from zokrates_pycrypto.babyjubjub import Point


@dataclass
class Attestation:
    providerPublicKey: Any
    credential: Any


@dataclass
class SimplePassport:
    publicKey: PublicKey


@dataclass
class FederatedPassport(SimplePassport):
    attestation: Attestation


def verifyProof(proof: Any, request: Any, hashSig: Any, attestation: Attestation) -> bool:
    # todo add implementation
    pass


def createProof(
    userPublicKey: Any,
    userPrivateKey: Any,
    providerSignedUserPublicKey: Tuple[Point, Any],
    request: Any,
    hashSig: Any,
    attestation: Attestation
) -> Any:
    # todo add implementation
    pass


def makeHash(message: List[Any]) -> Any:
    # todo add implementation
    pass


def createCredential(
    userPublicKey: Any,
    userPrivateKey: Any,
    providerSignedUserPublicKey: Any
) -> Any:
    makeHash([userPrivateKey, userPublicKey, providerSignedUserPublicKey])


class SimpleIdProvider:
    _privateKey: PrivateKey
    publicKey: PublicKey

    _accounts: Dict[int, Dict[int, SimplePassport]] = {}

    def __init__(self, _privateKey: PrivateKey, publicKey: PublicKey) -> None:
        self._privateKey = _privateKey
        self.publicKey = publicKey

    def _put(self, key: PublicKey, passport: SimplePassport):
        if key.p.x.n not in self._accounts:
            self._accounts[key.p.x.n] = {}
        self._accounts[key.p.x.n][key.p.y.n] = passport

    def _index(self, passport: SimplePassport):
        self._put(passport.publicKey, passport)

    def has(self, key: PublicKey) -> bool:
        return key.p.x.n in self._accounts and key.p.y.n in self._accounts[key.p.x.n]

    def register(self, passport: SimplePassport) -> bool:
        if self.has(passport.publicKey):
            return False

        self._index(passport)
        return True

    def sign(self, key: PublicKey) -> Tuple[bool, Tuple[Point, Any]]:
        if not self.has(key):
            return False, None
        return True, self._privateKey.sign([key.p.x.n, key.p.y.n])

    def authorize(self, userPublicKey: PublicKey, msg: Any, sig: Tuple[Point, Any]) -> bool:
        return self.has(userPublicKey) and userPublicKey.verify(sig, msg)


class FedIdProvider(SimpleIdProvider):
    def authAdmin(self, upk: PublicKey, msg: Any, hashSig: Tuple[Point, Any], proof: Any) -> bool:
        return upk.p.x.n in self._accounts and upk.p.y.n in self._accounts[upk.p.x.n] and \
            verifyProof(proof, msg, hashSig, self._accounts[upk].attestation)


if __name__ == '__main__':
    sk = PrivateKey.from_rand()
    pk = PublicKey.from_private(sk)

    usk = PrivateKey.from_rand()
    uupk = PublicKey.from_private(usk)

    pro = SimpleIdProvider(sk, pk)
    ok = pro.register(SimplePassport(uupk))
    assert ok

    mmsg = PrivateKey.from_rand().fe.n
    assert pro.authorize(uupk, mmsg, usk.sign(mmsg))
