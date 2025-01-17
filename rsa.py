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
def _sig_block(msg, k):
    h = hashlib.sha256(msg).digest()
    return b"\x00\x01" + b"\xff" * (k - 3 - len(h)) + b"\x00" + h


def sign(msg, priv):
    n, d = priv
    k = byte_len(n)
    return pow(int.from_bytes(_sig_block(msg, k), "big"), d, n).to_bytes(k, "big")


def verify(msg, sig, pub):
    n, e = pub
    k = byte_len(n)
    return pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big") == _sig_block(msg, k)


def weak_keygen(bits=1024):
    # private exponent well below n^(1/4)/3, which is what Wiener's attack needs
    p, q = random_prime(bits // 2), random_prime(bits // 2)
    n, phi = p * q, (p - 1) * (q - 1)
    while True:
        d = secrets.randbits(bits // 4 - 4) | 1
        if math.gcd(d, phi) == 1:
            return (n, modinv(d, phi)), (n, d)


def convergents(num, den):
    h0, h1, k0, k1 = 0, 1, 1, 0
    while den:
        a = num // den
        num, den = den, num - a * den
        h0, h1 = h1, a * h1 + h0
        k0, k1 = k1, a * k1 + k0
        yield h1, k1


def wiener(pub):
    # some convergent k/d of e/n equals k/d from e*d = 1 + k*phi; test each by
    # checking that the implied phi gives integer roots p, q of x^2 - (n - phi + 1)x + n
    n, e = pub
    for k, d in convergents(e, n):
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc >= 0 and math.isqrt(disc) ** 2 == disc and (b + math.isqrt(disc)) % 2 == 0:
            return d
    return None


def main():
    pub, priv = keygen(1024)
    print(f"n = {pub[0]:#x}"[:60] + "...")
    m = 42424242
    c = encrypt_int(m, pub)
    print(f"integer roundtrip: {m} -> {decrypt_int(c, priv)}")

    msg = b"attack at dawn"
    ct = encrypt(msg, pub)
    print(f"bytes roundtrip:   {msg!r} -> {decrypt(ct, priv)!r}")

    sig = sign(msg, priv)
    print(f"verify original:   {verify(msg, sig, pub)}")
    print(f"verify tampered:   {verify(b'attack at dusk', sig, pub)}")

    wpub, wpriv = weak_keygen(1024)
    d = wiener(wpub)
    print(f"Wiener: weak d has {wpriv[1].bit_length()} bits, recovered = {d == wpriv[1]}")
    print(f"Wiener on the normal key: {wiener(pub)}")


if __name__ == "__main__":
    main()
