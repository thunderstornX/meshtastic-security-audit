"""Tests for each detector, run against the synthetic fixture corpus."""
from __future__ import annotations

from audit.pcap_parser import parse_bytes
from audit.detectors import (
    detect_default_key,
    detect_node_enum,
    detect_unencrypted,
    detect_gps_leak,
)
from tests.fixtures.test_packets import (
    all_synthetic_frames,
    frame_default_channel_encrypted,
    frame_unencrypted_text,
    frame_unencrypted_position,
    frame_unicast_to_specific_node,
    frame_second_unicast_to_another_node,
)


def _frames(blobs):
    return parse_bytes(blobs)


# ─── default_key ────────────────────────────────────────────────────
def test_default_key_flags_longfast_frame():
    frames = _frames([frame_default_channel_encrypted()])
    findings = detect_default_key(frames)
    assert any(f.detector == "default_key" and f.severity == "high"
               for f in findings)
    assert any("LongFast" in f.title or "LongFast" in f.description
               for f in findings)


def test_default_key_silent_on_non_preset_channel():
    frames = _frames([frame_unicast_to_specific_node()])
    findings = detect_default_key(frames)
    assert findings == []


# ─── node_enum ──────────────────────────────────────────────────────
def test_node_enum_counts_distinct_sources():
    frames = _frames(all_synthetic_frames())
    findings = detect_node_enum(frames)
    info = [f for f in findings if f.severity == "info"]
    assert info, "expected at least one info finding"
    assert info[0].metadata["distinct_sources"] == 5


def test_node_enum_reports_unicast_destinations():
    frames = _frames([
        frame_unicast_to_specific_node(),
        frame_second_unicast_to_another_node(),
    ])
    findings = detect_node_enum(frames)
    mediums = [f for f in findings if f.severity == "medium"]
    assert len(mediums) == 1
    assert mediums[0].metadata["distinct_unicast_destinations"] == 2


# ─── unencrypted ────────────────────────────────────────────────────
def test_unencrypted_detects_flag_clear():
    frames = _frames([frame_unencrypted_text()])
    findings = detect_unencrypted(frames)
    assert any(f.title == "Frame flagged as unencrypted" for f in findings)


def test_unencrypted_detects_plaintext_protobuf():
    frames = _frames([frame_unencrypted_text()])
    findings = detect_unencrypted(frames)
    assert any(f.severity == "critical" and "plaintext" in f.title.lower()
               for f in findings)


def test_unencrypted_silent_on_encrypted_frame():
    frames = _frames([frame_default_channel_encrypted()])
    findings = detect_unencrypted(frames)
    # Encrypted-bit set + opaque payload → no plaintext / no flag hit.
    assert all(f.title != "Frame flagged as unencrypted" for f in findings)


# ─── gps_leak ───────────────────────────────────────────────────────
def test_gps_leak_recovers_coordinates():
    frames = _frames([frame_unencrypted_position()])
    findings = detect_gps_leak(frames)
    critical = [f for f in findings if f.severity == "critical"
                and "GPS coordinates" in f.title]
    assert critical, "expected a critical GPS finding"
    md = critical[0].metadata
    assert abs(md["latitude"] - 47.6062) < 1e-4
    assert abs(md["longitude"] - (-122.3321)) < 1e-4


def test_gps_leak_silent_on_text_payload():
    frames = _frames([frame_unencrypted_text()])
    findings = detect_gps_leak(frames)
    # Text isn't a position payload; detector should stay quiet.
    assert all("GPS coordinates" not in f.title for f in findings)
