"""Tests for the HTML + JSON reporter."""
from __future__ import annotations

import json

from audit.detectors import Finding
from audit.reporter import to_html, to_json


def _sample_findings():
    return [
        Finding(detector="default_key",  severity="high",
                title="Frame on default channel 'LongFast'",
                description="...", frame_index=0,
                metadata={"channel_hash": 0x0B, "preset_name": "LongFast"}),
        Finding(detector="gps_leak",     severity="critical",
                title="GPS coordinates recovered from unencrypted position payload",
                description="...", frame_index=2,
                metadata={"latitude": 47.6, "longitude": -122.3}),
        Finding(detector="node_enum",    severity="info",
                title="5 distinct source node id(s) observed",
                description="...", metadata={"distinct_sources": 5}),
    ]


def test_json_report_is_valid_json_and_carries_summary():
    out = to_json(_sample_findings(), pcap_path="samples/sample.pcap")
    parsed = json.loads(out)
    assert parsed["tool"] == "meshtastic-security-audit"
    assert parsed["summary"]["total"] == 3
    assert parsed["summary"]["by_severity"]["critical"] == 1
    assert parsed["summary"]["by_severity"]["high"] == 1
    assert parsed["summary"]["by_severity"]["info"] == 1
    assert parsed["pcap"] == "samples/sample.pcap"
    # Findings preserved end-to-end.
    titles = [f["title"] for f in parsed["findings"]]
    assert any("LongFast" in t for t in titles)


def test_html_report_renders_findings_and_severity_badges():
    out = to_html(_sample_findings(), pcap_path="samples/sample.pcap")
    assert out.startswith("<!doctype html>")
    assert "samples/sample.pcap" in out
    assert "CRITICAL" in out
    assert "HIGH" in out
    assert "INFO" in out
    # Critical badge colour from SEVERITY_COLOR
    assert "#a31621" in out


def test_html_handles_empty_findings():
    out = to_html([], pcap_path="empty.pcap")
    assert "Total findings: <strong>0</strong>" in out
