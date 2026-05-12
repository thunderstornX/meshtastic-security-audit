"""Tests for the Scapy-backed PCAP parser."""
from __future__ import annotations

from pathlib import Path

from audit.pcap_parser import MeshFrame, parse_bytes, parse_pcap
from tests.fixtures.test_packets import (
    all_synthetic_frames,
    frame_default_channel_encrypted,
    frame_unencrypted_text,
    frame_unencrypted_position,
    write_sample_pcap,
)


def test_parse_default_channel_frame():
    blob = frame_default_channel_encrypted()
    frames = parse_bytes([blob])
    assert len(frames) == 1
    f = frames[0]
    assert isinstance(f, MeshFrame)
    assert f.src == 0x12345678
    assert f.to == 0xFFFFFFFF
    assert f.encrypted_bit is True
    assert f.hop_limit == 0


def test_parse_unencrypted_text_frame():
    frames = parse_bytes([frame_unencrypted_text()])
    assert len(frames) == 1
    assert frames[0].encrypted_bit is False
    assert frames[0].payload.startswith(b"\x08\x01")


def test_parse_position_frame_has_protobuf_envelope():
    frames = parse_bytes([frame_unencrypted_position()])
    assert len(frames) == 1
    f = frames[0]
    # Field 1 (portnum) tag at the head.
    assert f.payload[0] == 0x08
    # portnum = 3 (POSITION_APP)
    assert f.payload[1] == 0x03


def test_corpus_round_trip_all_frames():
    blobs = all_synthetic_frames()
    frames = parse_bytes(blobs)
    assert len(frames) == len(blobs)


def test_parse_pcap_yields_frames(tmp_path: Path):
    pcap = write_sample_pcap(tmp_path / "sample.pcap")
    frames = parse_pcap(pcap)
    assert len(frames) == 5
    # Source ids are exactly the ones the fixtures emit.
    sources = {f.src for f in frames}
    assert sources == {
        0x12345678, 0x12345679, 0x1234567A, 0x1234567B, 0x1234567C,
    }


def test_parser_rejects_too_short_input():
    frames = parse_bytes([b"\x00" * 4])
    assert frames == []


def test_parser_rejects_zero_source():
    # A frame whose src == 0 fails the plausibility check.
    bad = b"\xff\xff\xff\xff" + b"\x00\x00\x00\x00" + b"\x01\x00\x00\x00" \
          + b"\x00" + b"\x00" + b"\x00" + b"\x00" + b"\xaa"
    assert parse_bytes([bad]) == []
