"""Flag frames whose channel hash matches a Meshtastic preset under
the documented default PSK index.

The Meshtastic firmware ships every device with a primary channel
named after one of the seven modem presets and a one-byte PSK index
of 0x01. Anyone running that same preset and index can decrypt the
traffic. The audit reports such frames as ``high`` severity.
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable

import sys
from pathlib import Path

# Allow this file to import the top-level ``config`` module whether
# run as ``python -m audit.detectors.default_key`` or imported
# transitively via the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import DEFAULT_PSK_INDEX, default_preset_hashes   # noqa: E402

from . import Finding  # noqa: E402


def detect(frames: Iterable) -> list[Finding]:
    preset_hashes = default_preset_hashes()
    # hash -> preset name
    inverse = {h: n for n, h in preset_hashes.items()}

    findings: list[Finding] = []
    hits_by_preset: Counter[str] = Counter()

    for f in frames:
        preset_name = inverse.get(f.channel)
        if preset_name is None:
            continue
        hits_by_preset[preset_name] += 1
        findings.append(
            Finding(
                detector="default_key",
                severity="high",
                title=f"Frame on default channel '{preset_name}'",
                description=(
                    f"Channel hash 0x{f.channel:02X} matches the Meshtastic "
                    f"preset '{preset_name}' with default PSK index "
                    f"0x{DEFAULT_PSK_INDEX:02X}. Traffic on this channel can "
                    f"be decrypted by any Meshtastic node using the same "
                    f"preset out of the box."
                ),
                frame_index=f.pcap_index,
                metadata={
                    "channel_hash": f.channel,
                    "preset_name":  preset_name,
                    "src":          f.src,
                    "to":           f.to,
                },
            )
        )

    if hits_by_preset:
        total = sum(hits_by_preset.values())
        per_preset = ", ".join(f"{n}={c}" for n, c in hits_by_preset.most_common())
        findings.append(
            Finding(
                detector="default_key",
                severity="high",
                title="Default-channel traffic observed across the capture",
                description=(
                    f"{total} frame(s) carried a channel hash matching a "
                    f"documented Meshtastic preset under the default PSK. "
                    f"Counts: {per_preset}."
                ),
                metadata={
                    "total_default_channel_frames": total,
                    "per_preset": dict(hits_by_preset),
                },
            )
        )
    return findings
