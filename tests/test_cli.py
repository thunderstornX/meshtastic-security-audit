"""End-to-end tests of the Click CLI against samples/sample.pcap."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cli import main as cli_main
from tests.fixtures.test_packets import write_sample_pcap


def test_cli_html_output(tmp_path):
    pcap = write_sample_pcap(tmp_path / "sample.pcap")
    report = tmp_path / "report.html"

    runner = CliRunner()
    result = runner.invoke(cli_main, [
        "--pcap",   str(pcap),
        "--output", str(report),
        "--format", "html",
    ])
    assert result.exit_code == 0, result.output
    assert report.exists()
    html = report.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert "LongFast" in html or "default channel" in html
    assert "GPS coordinates" in html


def test_cli_json_output(tmp_path):
    pcap = write_sample_pcap(tmp_path / "sample.pcap")
    report = tmp_path / "report.json"

    runner = CliRunner()
    result = runner.invoke(cli_main, [
        "--pcap",   str(pcap),
        "--output", str(report),
        "--format", "json",
    ])
    assert result.exit_code == 0
    doc = json.loads(report.read_text())
    assert doc["summary"]["total"] >= 4
    titles = [f["title"] for f in doc["findings"]]
    assert any("LongFast" in t for t in titles)
    assert any("GPS coordinates" in t for t in titles)


def test_cli_severity_threshold_filters_low_signal(tmp_path):
    pcap = write_sample_pcap(tmp_path / "sample.pcap")
    report = tmp_path / "report.json"

    runner = CliRunner()
    result = runner.invoke(cli_main, [
        "--pcap",   str(pcap),
        "--output", str(report),
        "--format", "json",
        "--severity-threshold", "high",
    ])
    assert result.exit_code == 0
    doc = json.loads(report.read_text())
    # 'info' and 'medium' findings should be filtered out.
    for f in doc["findings"]:
        assert f["severity"] in ("high", "critical")


def test_cli_detector_selection_runs_subset(tmp_path):
    pcap = write_sample_pcap(tmp_path / "sample.pcap")
    report = tmp_path / "report.json"

    runner = CliRunner()
    result = runner.invoke(cli_main, [
        "--pcap",   str(pcap),
        "--output", str(report),
        "--format", "json",
        "--detector", "gps_leak",
    ])
    assert result.exit_code == 0
    doc = json.loads(report.read_text())
    # Only gps_leak findings should appear.
    for f in doc["findings"]:
        assert f["detector"] == "gps_leak"
