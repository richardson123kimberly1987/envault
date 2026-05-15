"""Track rotation streaks for secrets — consecutive on-time rotations."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

STREAK_FILE = ".envault_streaks.json"


class StreakError(Exception):
    """Raised when a streak operation fails."""


@dataclass
class StreakResult:
    secret: str
    environment: str
    current_streak: int
    longest_streak: int
    last_rotated: Optional[str]

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "environment": self.environment,
            "current_streak": self.current_streak,
            "longest_streak": self.longest_streak,
            "last_rotated": self.last_rotated,
        }


def _load_streaks(vault_path: str) -> Dict[str, dict]:
    streak_path = os.path.join(os.path.dirname(vault_path), STREAK_FILE)
    if not os.path.exists(streak_path):
        return {}
    with open(streak_path, "r") as fh:
        return json.load(fh)


def _save_streaks(vault_path: str, data: Dict[str, dict]) -> None:
    streak_path = os.path.join(os.path.dirname(vault_path), STREAK_FILE)
    with open(streak_path, "w") as fh:
        json.dump(data, fh, indent=2)


def _key(environment: str, secret: str) -> str:
    return f"{environment}::{secret}"


def record_rotation(vault, environment: str, secret: str) -> StreakResult:
    """Record a successful rotation and update the streak counter."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise StreakError(f"Secret '{secret}' not found in environment '{environment}'")

    streaks = _load_streaks(vault.path)
    k = _key(environment, secret)
    record = streaks.get(k, {"current": 0, "longest": 0, "last_rotated": None})

    record["current"] += 1
    if record["current"] > record["longest"]:
        record["longest"] = record["current"]
    record["last_rotated"] = datetime.now(timezone.utc).isoformat()

    streaks[k] = record
    _save_streaks(vault.path, streaks)

    return StreakResult(
        secret=secret,
        environment=environment,
        current_streak=record["current"],
        longest_streak=record["longest"],
        last_rotated=record["last_rotated"],
    )


def get_streak(vault, environment: str, secret: str) -> StreakResult:
    """Return the current streak info for a secret."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise StreakError(f"Secret '{secret}' not found in environment '{environment}'")

    streaks = _load_streaks(vault.path)
    k = _key(environment, secret)
    record = streaks.get(k, {"current": 0, "longest": 0, "last_rotated": None})

    return StreakResult(
        secret=secret,
        environment=environment,
        current_streak=record["current"],
        longest_streak=record["longest"],
        last_rotated=record["last_rotated"],
    )


def reset_streak(vault, environment: str, secret: str) -> StreakResult:
    """Reset the current streak for a secret (e.g. after a missed rotation)."""
    entry = vault.get_secret(environment, secret)
    if entry is None:
        raise StreakError(f"Secret '{secret}' not found in environment '{environment}'")

    streaks = _load_streaks(vault.path)
    k = _key(environment, secret)
    record = streaks.get(k, {"current": 0, "longest": 0, "last_rotated": None})
    record["current"] = 0
    streaks[k] = record
    _save_streaks(vault.path, streaks)

    return StreakResult(
        secret=secret,
        environment=environment,
        current_streak=0,
        longest_streak=record["longest"],
        last_rotated=record["last_rotated"],
    )
