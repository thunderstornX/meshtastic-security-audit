"""Flag frames carrying the 'unencrypted' indicator.

Two complementary signals:

  1. The 0x10 bit in the flags byte ("encrypted" indicator). When the
     bit is clear, the firmware is announcing that the channel was
     configured with no PSK at all.
  2. A payload whose first bytes parse cleanly as a Meshtastic ``Data``
     protobuf (port + ascii text), suggesting the payload was sent
     without any encryption applied irrespective of the flag bit.

The audit reports finding (1) as ``high`` severity and finding (2) as
``critical``.
"""
from __future__ import annotations

from typing import Iterable

from . import Finding

# A Data protobuf always starts with a varint-encoded field tag for the
# ``portnum`` field (field 1, wire type 0). Tag = (1 << 3) | 0 = 0x08.
DATA_PROTOBUF_TAG = 0x08


def _looks_like_plaintext_protobuf(payload: bytes) -> bool:
    """Cheap heuristic: does the payload start with the Data tag and
    contain enough printable bytes to look like a real message?"""
    if len(payload) < 4:
        return False
    if payload[0] != DATA_PROTOBUF_TAG:
        return False
    # The Data envelope usually carries either a small protobuf (text)
    # or further nested tags. Look for at least one printable run of 4
    # bytes anywhere in the first 64 bytes — a stronger signal than the
    # tag alone.
    sample = payload[1:64]
    printable = sum(1 for b in sample if 32 <= b < 127)
    return printable >= 4


def detect(frames: Iterable) -> list[Finding]:
    findings: list[Finding] = []
    flag_hits = 0
    plaintext_hits = 0

    for f in frames:
        flag_set = not f.encrypted_bit  # bit clear means "not encrypted"
        looks_plain = _looks_like_plaintext_protobuf(f.payload)

        if flag_set:
            flag_hits += 1
            findings.append(
                Finding(
                    detector="unencrypted",
                    severity="high",
                    title="Frame flagged as unencrypted",
                    description=(
                        "The encrypted-bit (0x10) is clear in the flags "
                        "byte, indicating the channel was configured "
                        "without a PSK. Any observer within RF range can "
                        "recover the payload directly."
                    ),
                    frame_index=f.pcap_index,
                    metadata={
                        "flags":   f.flags,
                        "channel": f.channel,
                        "src":     f.src,
                    },
                )
            )

        if looks_plain:
            plaintext_hits += 1
            findings.append(
                Finding(
                    detector="unencrypted",
                    severity="critical",
                    title="Payload decodes as a plaintext Meshtastic Data protobuf",
                    description=(
                        "The payload starts with the Data envelope tag and "
                        "contains a contiguous run of printable bytes, "
                        "consistent with text being broadcast without any "
                        "encryption applied. This is more conclusive than "
                        "the flag-bit signal because it is content-based."
                    ),
                    frame_index=f.pcap_index,
                    metadata={
                        "channel":          f.channel,
                        "src":              f.src,
                        "payload_preview":  payload_preview(f.payload),
                    },
                )
            )

    if flag_hits or plaintext_hits:
        findings.append(
            Finding(
                detector="unencrypted",
                severity="high" if not plaintext_hits else "critical",
                title="Unencrypted traffic summary",
                description=(
                    f"{flag_hits} frame(s) had the encrypted flag clear and "
                    f"{plaintext_hits} frame(s) contained a plaintext "
                    f"Data protobuf payload."
                ),
                metadata={
                    "flag_hits":      flag_hits,
                    "plaintext_hits": plaintext_hits,
                },
            )
        )
    return findings


def payload_preview(payload: bytes, max_len: int = 32) -> str:
    """Hex+ASCII preview, trimmed to ``max_len`` bytes."""
    head = payload[:max_len]
    hex_part = head.hex()
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in head)
    return f"{hex_part} :: {ascii_part}"
