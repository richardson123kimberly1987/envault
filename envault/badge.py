"""Badge generation for secret health and status reporting."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

BADGE_STYLES = ["flat", "flat-square", "plastic", "for-the-badge"]

BADGE_COLORS = {
    "success": "brightgreen",
    "warning": "yellow",
    "error": "red",
    "info": "blue",
    "unknown": "lightgrey",
}


class BadgeError(Exception):
    """Raised when badge generation fails."""


@dataclass
class BadgeResult:
    label: str
    message: str
    color: str
    style: str
    url: str

    def to_dict(self) -> Dict:
        return {
            "label": self.label,
            "message": self.message,
            "color": self.color,
            "style": self.style,
            "url": self.url,
        }


def _shield_url(label: str, message: str, color: str, style: str) -> str:
    import urllib.parse

    encoded_label = urllib.parse.quote(label, safe="")
    encoded_message = urllib.parse.quote(message, safe="")
    return (
        f"https://img.shields.io/badge/{encoded_label}-{encoded_message}-{color}"
        f"?style={style}"
    )


def generate_badge(
    vault,
    environment: str,
    style: str = "flat",
    label: Optional[str] = None,
) -> BadgeResult:
    """Generate a shields.io-compatible badge summarising secret health."""
    if style not in BADGE_STYLES:
        raise BadgeError(
            f"Unknown style '{style}'. Choose from: {', '.join(BADGE_STYLES)}"
        )

    secrets = vault.list_secrets(environment)
    total = len(secrets)

    if total == 0:
        message = "no secrets"
        color = BADGE_COLORS["unknown"]
    else:
        expired: List[str] = []
        for name in secrets:
            entry = vault.get_secret(environment, name)
            if entry is None:
                continue
            d = entry.to_dict()
            expiry = d.get("expires_at")
            if expiry:
                from datetime import datetime, timezone

                try:
                    exp_dt = datetime.fromisoformat(expiry)
                    if exp_dt < datetime.now(timezone.utc):
                        expired.append(name)
                except ValueError:
                    pass

        if expired:
            message = f"{len(expired)}/{total} expired"
            color = BADGE_COLORS["error"]
        else:
            message = f"{total} healthy"
            color = BADGE_COLORS["success"]

    badge_label = label or environment
    url = _shield_url(badge_label, message, color, style)
    return BadgeResult(
        label=badge_label,
        message=message,
        color=color,
        style=style,
        url=url,
    )


def generate_all_badges(
    vault,
    style: str = "flat",
) -> Dict[str, BadgeResult]:
    """Generate badges for every environment in the vault."""
    results: Dict[str, BadgeResult] = {}
    for env in vault.list_environments():
        results[env] = generate_badge(vault, env, style=style)
    return results
