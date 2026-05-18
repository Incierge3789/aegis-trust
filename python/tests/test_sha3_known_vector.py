"""SHA-3-512 known vector test — NIST FIPS 202 compliance."""

import hashlib


def test_sha3_512_abc():
    """NIST SHA-3-512("abc") known answer test.

    Prevents accidental use of SHA-512/256 (SHA-2 family) which produces
    a completely different digest.
    """
    digest = hashlib.sha3_512(b"abc").hexdigest()
    expected = (
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    )
    assert digest == expected, f"SHA-3-512 mismatch: got {digest}"


def test_sha3_512_not_sha2():
    """Ensure our hash is NOT SHA-512/256 (a common confusion)."""
    sha2_digest = hashlib.sha512(b"abc").hexdigest()
    sha3_digest = hashlib.sha3_512(b"abc").hexdigest()
    assert sha2_digest != sha3_digest, (
        "SHA-2 and SHA-3 should produce different digests"
    )
