"""Scapy-crafted Meshtastic frames + PCAPs for the test suite.

The frames here are *byte-level* synthetic — they reproduce the wire
format we parse, not the protobuf payload structure produced by a
real firmware. That is intentional: we want the parser and detectors
exercised against inputs whose ground truth we control, and we want
the test suite to be reproducible without RF hardware.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable

from scapy.all import Raw, Ether, wrpcap
from scapy.packet import Packet

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config import default_preset_hashes   # noqa: E402

_PRESET_HASH = default_preset_hashes()["LongFast"]   # documented preset
_NON_PRESET_HASH = 0xA7                              # arbitrary non-preset


def _build_header(*, to: int, src: int, packet_id: int, flags: int,
                  channel: int, next_hop: int = 0,
                  relay_node: int = 0) -> bytes:
    """Pack the current 16-byte Meshtastic frame header."""
    return struct.pack(
        "<IIIBBBB",
        to, src, packet_id, flags & 0xFF, channel & 0xFF,
        next_hop & 0xFF, relay_node & 0xFF,
    )


def frame_default_channel_encrypted() -> bytes:
    """Encrypted-looking frame on the default LongFast channel."""
    header = _build_header(
        to=0xFFFFFFFF, src=0x12345678, packet_id=1001,
        flags=0x10, channel=_PRESET_HASH,  # 0x10 = encrypted bit set
    )
    # Random-looking opaque payload (encrypted Data envelope).
    payload = bytes.fromhex("9af30aa1b2c3d4e5") + bytes(8)
    return header + payload


def frame_unencrypted_text() -> bytes:
    """Unencrypted text frame: flag clear AND Data tag at the head."""
    header = _build_header(
        to=0xFFFFFFFF, src=0x12345679, packet_id=1002,
        flags=0x00, channel=_NON_PRESET_HASH,  # encrypted bit clear
    )
    # Field 1 (portnum) = TEXT_MESSAGE (1); field 2 (payload) = "hello mesh".
    payload = b"\x08\x01\x12\x0bhello mesh"
    return header + payload


def frame_unencrypted_position() -> bytes:
    """Position payload with recoverable GPS in plaintext."""
    header = _build_header(
        to=0xFFFFFFFF, src=0x1234567A, packet_id=1003,
        flags=0x00, channel=_NON_PRESET_HASH,
    )
    # Build the inner Position protobuf: latitude_i (field 1, sfixed32),
    # longitude_i (field 2, sfixed32). 47.6062, -122.3321 (Seattle-ish).
    lat_i = int(47.6062 * 1e7)
    lon_i = int(-122.3321 * 1e7)
    inner = (b"\x0d" + struct.pack("<i", lat_i)
             + b"\x15" + struct.pack("<i", lon_i))
    # Wrap in a Data envelope: portnum=3 (POSITION_APP), payload=inner.
    envelope = b"\x08\x03\x12" + bytes([len(inner)]) + inner
    return header + envelope


def frame_unicast_to_specific_node() -> bytes:
    """Encrypted unicast frame to a specific node id (node enum signal)."""
    header = _build_header(
        to=0xABCDEF01, src=0x1234567B, packet_id=1004,
        flags=0x10, channel=_NON_PRESET_HASH,
    )
    return header + bytes.fromhex("deadbeef" + "00" * 8)


def frame_second_unicast_to_another_node() -> bytes:
    """Second unicast to a distinct node (enumeration spread)."""
    header = _build_header(
        to=0x44556677, src=0x1234567C, packet_id=1005,
        flags=0x10, channel=_NON_PRESET_HASH,
    )
    return header + bytes.fromhex("cafebabe" + "00" * 8)


def all_synthetic_frames() -> list[bytes]:
    """The full corpus the tests sweep over."""
    return [
        frame_default_channel_encrypted(),
        frame_unencrypted_text(),
        frame_unencrypted_position(),
        frame_unicast_to_specific_node(),
        frame_second_unicast_to_another_node(),
    ]


def write_sample_pcap(path: str | Path) -> Path:
    """Write all synthetic frames into a single PCAP at *path*.

    Each frame is wrapped in a minimal Ether placeholder so Scapy's
    ``wrpcap`` is happy; the parser unwraps the Raw payload at read
    time.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pkts: list[Packet] = []
    for blob in all_synthetic_frames():
        pkts.append(Ether() / Raw(load=blob))
    wrpcap(str(path), pkts)
    return path


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ns = ap.parse_args()
    written = write_sample_pcap(ns.out)
    print(f"wrote {written}")
