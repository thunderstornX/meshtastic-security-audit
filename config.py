"""Module-level constants used by the parser and detectors.

The values here are sourced from the Meshtastic project's public
protobuf definitions and firmware presets. See ``audit/pcap_parser.py``
for how they are applied at parse time.
"""
from __future__ import annotations

# ─── Documented Meshtastic modem presets ───────────────────────────
# Names ship with every device. The primary channel on a freshly
# flashed Meshtastic node uses one of these names plus a one-byte
# PSK index of 0x01 (the documented default).
DEFAULT_PRESET_NAMES: tuple[str, ...] = (
    "LongFast",
    "LongSlow",
    "VeryLongSlow",
    "MediumSlow",
    "MediumFast",
    "ShortSlow",
    "ShortFast",
)

# The PSK *index* the firmware writes to a fresh primary channel.
# Not the 256-bit AES key — the firmware derives the AES key from
# this index. Detection treats any frame whose channel hash matches
# (preset name XOR index) as "default channel".
DEFAULT_PSK_INDEX: int = 0x01


def channel_hash(name: str, psk: bytes | int) -> int:
    """Compute the 8-bit Meshtastic channel hash.

    The hash is XOR of every byte of the channel name with every byte
    of the PSK. Used to populate the single-byte ``channel`` field in
    the Meshtastic packet header.
    """
    h = 0
    for c in name.encode("utf-8"):
        h ^= c
    if isinstance(psk, int):
        h ^= (psk & 0xFF)
    else:
        for b in psk:
            h ^= b
    return h & 0xFF


def default_preset_hashes() -> dict[str, int]:
    """Map each preset name to its hash under the default PSK index."""
    return {name: channel_hash(name, DEFAULT_PSK_INDEX) for name in DEFAULT_PRESET_NAMES}


# ─── PortNum (Meshtastic application layer ports) ──────────────────
# A subset of the 256-port namespace from the upstream protobuf,
# sufficient for the audit surface this toolkit cares about.
PORTNUM_UNKNOWN_APP   = 0
PORTNUM_TEXT_MESSAGE  = 1
PORTNUM_POSITION_APP  = 3
PORTNUM_NODEINFO_APP  = 4
PORTNUM_ROUTING_APP   = 5
PORTNUM_ADMIN_APP     = 6
PORTNUM_TELEMETRY_APP = 67

PORTNUM_NAMES: dict[int, str] = {
    0:  "UNKNOWN_APP",
    1:  "TEXT_MESSAGE",
    3:  "POSITION_APP",
    4:  "NODEINFO_APP",
    5:  "ROUTING_APP",
    6:  "ADMIN_APP",
    67: "TELEMETRY_APP",
}


# ─── Finding severity bands ────────────────────────────────────────
SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
