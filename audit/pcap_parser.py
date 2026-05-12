"""Parse Meshtastic frames out of a PCAP capture.

A Meshtastic radio frame as it travels over LoRa carries a small
header followed by an encrypted payload. The exact wire format is
defined in the upstream protobuf project; the fields the audit cares
about are:

  * ``to``         (uint32, little-endian)  — destination node id
  * ``from``       (uint32, little-endian)  — source node id
  * ``packet_id``  (uint32, little-endian)  — per-source counter
  * ``flags``      (uint8)                  — hop limit + want_ack
  * ``channel``    (uint8)                  — 8-bit channel hash
  * ``next_hop``   (uint8)                  — relay id (firmware ≥ 2.3)
  * ``relay_node`` (uint8)                  — previous relay id
  * ``payload``    (variable, encrypted)    — protobuf ``Data`` if
                                              decrypted

The on-the-wire frame can be encapsulated inside several different
PCAP link-layer types depending on how the capture was produced
(USERDLT, LoRaTap, raw bytes). This module reads PCAP files via
Scapy and tries each known encapsulation in order; frames that do
not decode are skipped without raising.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from scapy.all import PcapReader, Raw
from scapy.packet import Packet

# ─── Wire-format constants ─────────────────────────────────────────
HEADER_LEN_LEGACY = 14   # before next_hop / relay_node bytes
HEADER_LEN_CURRENT = 16  # current firmware


@dataclass
class MeshFrame:
    """One decoded Meshtastic frame.

    The encrypted payload is preserved verbatim; decryption (if the
    operator supplies a key) is left to the detector that needs it.
    """

    to:           int
    src:          int
    packet_id:    int
    flags:        int
    channel:      int
    payload:      bytes
    next_hop:     int | None = None
    relay_node:   int | None = None
    # Caller-provided source attribution, e.g. PCAP frame index.
    pcap_index:   int = -1
    raw_header:   bytes = b""
    decoded_port: int | None = None
    decoded_text: str | None = None
    decoded_position: dict[str, float] | None = None

    @property
    def hop_limit(self) -> int:
        return self.flags & 0x07

    @property
    def want_ack(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def encrypted_bit(self) -> bool:
        """The 'is encrypted' flag bit.

        Position 4 (0x10) in the flags byte. Real-world firmware
        toggles this when a channel is configured with no key.
        """
        return bool(self.flags & 0x10)


def _try_decode(data: bytes, index: int) -> MeshFrame | None:
    """Attempt to interpret ``data`` as a Meshtastic frame."""
    if len(data) < HEADER_LEN_LEGACY:
        return None

    # Try current firmware header first.
    if len(data) >= HEADER_LEN_CURRENT:
        try:
            to, src, pid, flags, channel, next_hop, relay = struct.unpack(
                "<IIIBBBB", data[:HEADER_LEN_CURRENT]
            )
            payload = data[HEADER_LEN_CURRENT:]
            if _plausible(to, src, pid, payload):
                return MeshFrame(
                    to=to, src=src, packet_id=pid, flags=flags, channel=channel,
                    payload=payload, next_hop=next_hop, relay_node=relay,
                    pcap_index=index, raw_header=data[:HEADER_LEN_CURRENT],
                )
        except struct.error:
            pass

    # Fall through to legacy 14-byte header.
    try:
        to, src, pid, flags, channel = struct.unpack(
            "<IIIBB", data[:HEADER_LEN_LEGACY]
        )
        payload = data[HEADER_LEN_LEGACY:]
        if _plausible(to, src, pid, payload):
            return MeshFrame(
                to=to, src=src, packet_id=pid, flags=flags, channel=channel,
                payload=payload, pcap_index=index, raw_header=data[:HEADER_LEN_LEGACY],
            )
    except struct.error:
        pass
    return None


def _plausible(to: int, src: int, pid: int, payload: bytes) -> bool:
    """Cheap sanity checks to weed out non-Meshtastic frames."""
    # The Meshtastic broadcast id is 0xFFFFFFFF; src is normally not.
    if src == 0 or src == 0xFFFFFFFF:
        return False
    # Packet ids are monotonic per source; they fit comfortably below 2^31.
    if pid == 0:
        return False
    # An empty payload is unusual; the protocol always carries at least
    # the encrypted Data envelope (one byte minimum).
    if len(payload) < 1:
        return False
    # ``to`` is either 0xFFFFFFFF (broadcast) or a valid 32-bit node id.
    if to != 0xFFFFFFFF and to == 0:
        return False
    return True


def _bytes_from_packet(pkt: Packet) -> bytes:
    """Extract the raw payload from a Scapy packet candidate."""
    layer = pkt.getlayer(Raw)
    if layer is not None and layer.load:
        return bytes(layer.load)
    return bytes(pkt)


def iter_frames(pcap_path: str | Path) -> Iterator[MeshFrame]:
    """Yield ``MeshFrame`` objects for every recognisable record in *pcap_path*."""
    pcap_path = Path(pcap_path)
    with PcapReader(str(pcap_path)) as reader:
        for index, pkt in enumerate(reader):
            blob = _bytes_from_packet(pkt)
            frame = _try_decode(blob, index)
            if frame is not None:
                yield frame


def parse_pcap(pcap_path: str | Path) -> list[MeshFrame]:
    """Eager wrapper around :func:`iter_frames`."""
    return list(iter_frames(pcap_path))


def parse_bytes(stream: Iterable[bytes]) -> list[MeshFrame]:
    """Decode an iterable of byte buffers (one buffer per frame).

    Useful for testing without a real PCAP on disk.
    """
    out: list[MeshFrame] = []
    for i, blob in enumerate(stream):
        frame = _try_decode(blob, i)
        if frame is not None:
            out.append(frame)
    return out
