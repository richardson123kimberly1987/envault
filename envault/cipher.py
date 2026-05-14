"""Cipher module: list, describe, and benchmark available cipher suites."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

CIPHER_SUITES: Dict[str, Dict[str, object]] = {
    "AES-256-GCM": {
        "key_bits": 256,
        "mode": "GCM",
        "authenticated": True,
        "description": "AES 256-bit in Galois/Counter Mode (default)",
    },
    "AES-128-GCM": {
        "key_bits": 128,
        "mode": "GCM",
        "authenticated": True,
        "description": "AES 128-bit in Galois/Counter Mode",
    },
    "CHACHA20-POLY1305": {
        "key_bits": 256,
        "mode": "POLY1305",
        "authenticated": True,
        "description": "ChaCha20 stream cipher with Poly1305 MAC",
    },
}

DEFAULT_CIPHER = "AES-256-GCM"


class CipherError(Exception):
    """Raised when an unsupported or invalid cipher suite is requested."""


@dataclass
class CipherInfo:
    name: str
    key_bits: int
    mode: str
    authenticated: bool
    description: str
    is_default: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "key_bits": self.key_bits,
            "mode": self.mode,
            "authenticated": self.authenticated,
            "description": self.description,
            "is_default": self.is_default,
        }


def get_cipher_info(name: str) -> CipherInfo:
    """Return CipherInfo for *name*, raising CipherError if unknown."""
    key = name.upper()
    if key not in CIPHER_SUITES:
        raise CipherError(
            f"Unknown cipher suite '{name}'. "
            f"Supported: {', '.join(CIPHER_SUITES)}"
        )
    data = CIPHER_SUITES[key]
    return CipherInfo(
        name=key,
        key_bits=int(data["key_bits"]),
        mode=str(data["mode"]),
        authenticated=bool(data["authenticated"]),
        description=str(data["description"]),
        is_default=(key == DEFAULT_CIPHER),
    )


def list_ciphers() -> List[CipherInfo]:
    """Return CipherInfo for every supported cipher suite."""
    return [get_cipher_info(name) for name in CIPHER_SUITES]
