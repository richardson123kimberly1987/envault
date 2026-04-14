"""Tests for envault.crypto encryption/decryption utilities."""

import pytest
from envault.crypto import encrypt, decrypt


PASSPHRASE = "super-secret-passphrase-123"
PLAINTEXT = "DATABASE_URL=postgres://user:pass@localhost/db"


def test_encrypt_returns_string():
    result = encrypt(PLAINTEXT, PASSPHRASE)
    assert isinstance(result, str)
    assert len(result) > 0


def test_encrypt_produces_unique_ciphertexts():
    """Each encryption call should produce a different ciphertext (random salt/nonce)."""
    result1 = encrypt(PLAINTEXT, PASSPHRASE)
    result2 = encrypt(PLAINTEXT, PASSPHRASE)
    assert result1 != result2


def test_decrypt_round_trip():
    encoded = encrypt(PLAINTEXT, PASSPHRASE)
    recovered = decrypt(encoded, PASSPHRASE)
    assert recovered == PLAINTEXT


def test_decrypt_wrong_passphrase_raises():
    encoded = encrypt(PLAINTEXT, PASSPHRASE)
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt(encoded, "wrong-passphrase")


def test_decrypt_corrupted_payload_raises():
    encoded = encrypt(PLAINTEXT, PASSPHRASE)
    corrupted = encoded[:-4] + "AAAA"
    with pytest.raises(ValueError):
        decrypt(corrupted, PASSPHRASE)


def test_decrypt_invalid_base64_raises():
    with pytest.raises(ValueError, match="Invalid encoded payload"):
        decrypt("!!!not-base64!!!", PASSPHRASE)


def test_decrypt_too_short_payload_raises():
    import base64
    short = base64.b64encode(b"tooshort").decode()
    with pytest.raises(ValueError, match="too short"):
        decrypt(short, PASSPHRASE)


def test_encrypt_empty_string():
    encoded = encrypt("", PASSPHRASE)
    recovered = decrypt(encoded, PASSPHRASE)
    assert recovered == ""


def test_encrypt_unicode_content():
    unicode_text = "SECRET=caf\u00e9-\u4e2d\u6587-\u0440\u0443\u0441"
    encoded = encrypt(unicode_text, PASSPHRASE)
    recovered = decrypt(encoded, PASSPHRASE)
    assert recovered == unicode_text
