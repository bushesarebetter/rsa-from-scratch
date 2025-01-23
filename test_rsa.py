import pytest

import rsa


@pytest.fixture(scope="module")
def keys():
    return rsa.keygen(1024)


def test_int_and_bytes_roundtrip(keys):
    pub, priv = keys
    for m in (0, 1, 123456789, pub[0] - 1):
        assert rsa.decrypt_int(rsa.encrypt_int(m, pub), priv) == m
    for msg in (b"", b"hello", bytes(range(100))):
        assert rsa.decrypt(rsa.encrypt(msg, pub), priv) == msg


def test_signature_rejects_tampering(keys):
    pub, priv = keys
    sig = rsa.sign(b"pay bob 10", priv)
    assert rsa.verify(b"pay bob 10", sig, pub)
    assert not rsa.verify(b"pay bob 99", sig, pub)
    assert not rsa.verify(b"pay bob 10", bytes([sig[0] ^ 1]) + sig[1:], pub)


def test_miller_rabin_matches_sieve():
    N = 100_000
    sieve = bytearray([1]) * N
    sieve[0] = sieve[1] = 0
    for i in range(2, int(N**0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(range(i * i, N, i)))
    assert all(rsa.is_probable_prime(n) == bool(sieve[n]) for n in range(N))


def test_modinv():
    assert rsa.modinv(3, 11) == 4
    with pytest.raises(ValueError):
        rsa.modinv(6, 9)


def test_wiener_recovers_weak_key(keys):
    pub, priv = rsa.weak_keygen(1024)
    assert rsa.wiener(pub) == priv[1]
    assert rsa.wiener(keys[0]) is None
