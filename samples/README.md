# Sample captures

`sample.pcap` is a tiny synthetic capture used by the smoke tests and
the "working entry point" command in the project README. Five frames:

| # | Description                                       | Detector signal |
|---|---|---|
| 0 | Encrypted-looking frame on default `LongFast`     | `default_key` (high) |
| 1 | Plaintext text payload, encrypted-bit clear       | `unencrypted` (critical + high) |
| 2 | Plaintext position with lat/lon = +47.6062, −122.3321 | `gps_leak` (critical) |
| 3 | Encrypted unicast to node `!abcdef01`             | `node_enum` (medium) |
| 4 | Encrypted unicast to a different node `!44556677` | `node_enum` (medium) |

Regenerate the file with:

```bash
python tests/fixtures/test_packets.py samples/sample.pcap
```

To analyse a capture you produced yourself:

```bash
python cli.py --pcap your-capture.pcap --output your-report.html
```

Capturing live Meshtastic traffic over the air requires a software-
defined radio at the regional ISM-band frequency (433 / 868 / 915 MHz)
and a Meshtastic decoder such as `gr-lora_sdr` or the `meshtastic`
Python client's debug serial sniffer. PCAP serialisation of the
recovered frames is then up to the operator.
