"""Encoding utilities for secret values (base64, hex, url-safe)."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from envault.vault import Vault

ENCODE_FORMATS = ("base64", "hex", "urlsafe")


class EncodeError(Exception):
    """Raised when encoding or decoding fails."""


@dataclass
class EncodeResult:
    secret: str
    environment: str
    format: str
    original: str
    encoded: str

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "format": self.format,
            "original": self.original,
            "encoded": self.encoded,
        }


def _get_entry_or_raise(vault: "Vault", environment: str, secret: str):
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise EncodeError(f"Secret '{secret}' not found in environment '{environment}'")
    return entry


def encode_secret(
    vault: "Vault",
    environment: str,
    secret: str,
    fmt: str,
    passphrase: str,
) -> EncodeResult:
    """Encode a secret value using the specified format."""
    if fmt not in ENCODE_FORMATS:
        raise EncodeError(f"Unsupported format '{fmt}'. Choose from: {ENCODE_FORMATS}")
    entry = _get_entry_or_raise(vault, environment, secret)
    plaintext = entry.decrypt(passphrase)
    raw = plaintext.encode()
    if fmt == "base64":
        encoded = base64.b64encode(raw).decode()
    elif fmt == "hex":
        encoded = raw.hex()
    else:  # urlsafe
        encoded = base64.urlsafe_b64encode(raw).decode()
    return EncodeResult(
        secret=secret,
        environment=environment,
        format=fmt,
        original=plaintext,
        encoded=encoded,
    )


def decode_secret(
    vault: "Vault",
    environment: str,
    secret: str,
    fmt: str,
    passphrase: str,
) -> EncodeResult:
    """Decode a secret value that was previously encoded with the specified format."""
    if fmt not in ENCODE_FORMATS:
        raise EncodeError(f"Unsupported format '{fmt}'. Choose from: {ENCODE_FORMATS}")
    entry = _get_entry_or_raise(vault, environment, secret)
    plaintext = entry.decrypt(passphrase)
    try:
        raw = plaintext.encode()
        if fmt == "base64":
            decoded = base64.b64decode(raw).decode()
        elif fmt == "hex":
            decoded = bytes.fromhex(plaintext).decode()
        else:  # urlsafe
            decoded = base64.urlsafe_b64decode(raw).decode()
    except (binascii.Error, ValueError) as exc:
        raise EncodeError(f"Failed to decode secret '{secret}': {exc}") from exc
    return EncodeResult(
        secret=secret,
        environment=environment,
        format=fmt,
        original=plaintext,
        encoded=decoded,
    )
