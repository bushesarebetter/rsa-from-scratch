# rsa-from-scratch

Textbook RSA in plain Python: Miller-Rabin, prime generation, extended Euclid, keygen, encrypt/decrypt and sign/verify on integers and bytes, plus Wiener's attack recovering a private key when d is too small.

**This is for learning, not real security.** The padding is a simplified PKCS#1 v1.5 style scheme with no OAEP or PSS, and none of the math is constant-time. Use a real crypto library for anything that matters.

## Setup

Standard library only. The tests need pytest (`pip install pytest`).

## Run

```
python rsa.py
```

It makes a 1024-bit key, round-trips an integer and a byte string, signs a message and checks that a tampered copy fails, then builds a key with a ~250-bit d and recovers d using the continued fraction expansion of e/n. The same attack returns `None` on the normal key.

## Test

```
python -m pytest -q
```

Covers the integer and byte roundtrips, tampered signatures being rejected, Miller-Rabin agreeing with a sieve for every n below 10^5, and Wiener's attack recovering a weak key.
