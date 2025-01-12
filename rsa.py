import hashlib
import math
import secrets

SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # the first 12 primes as bases are a proven-deterministic test for n < 3.3e24
    if n < 3_317_044_064_679_887_385_961_981:
        bases = SMALL_PRIMES
    else:
        bases = [2 + secrets.randbelow(n - 3) for _ in range(rounds)]
    for a in bases:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits):
    while True:
        # top two bits set so p*q has exactly 2*bits bits; low bit set so it's odd
        n = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if is_probable_prime(n):
            return n


def egcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("not invertible")
    return x % m


def keygen(bits=1024, e=65537):
    while True:
        p, q = random_prime(bits // 2), random_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and math.gcd(e, phi) == 1:
            return (p * q, e), (p * q, modinv(e, phi))


def encrypt_int(m, pub):
    n, e = pub
    assert 0 <= m < n
    return pow(m, e, n)


def decrypt_int(c, priv):
    n, d = priv
    return pow(c, d, n)


def byte_len(n):
    return (n.bit_length() + 7) // 8


# PKCS#1 v1.5-style padding: 00 02 <random nonzero bytes> 00 <message>
def encrypt(msg, pub):
    k = byte_len(pub[0])
    if len(msg) > k - 11:
        raise ValueError("message too long")
    pad = bytes(secrets.choice(range(1, 256)) for _ in range(k - 3 - len(msg)))
    block = b"\x00\x02" + pad + b"\x00" + msg
    return encrypt_int(int.from_bytes(block, "big"), pub).to_bytes(k, "big")


def decrypt(ct, priv):
    k = byte_len(priv[0])
    block = decrypt_int(int.from_bytes(ct, "big"), priv).to_bytes(k, "big")
    if block[:2] != b"\x00\x02":
        raise ValueError("bad padding")
    return block[block.index(b"\x00", 2) + 1:]


# signature block: 00 01 FF..FF 00 sha256(msg)














