"""Per-detector precision / recall on the synthetic labelled corpus."""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from audit.pcap_parser import parse_bytes   # noqa: E402
from audit.detectors    import ALL_DETECTORS  # noqa: E402
from tests.fixtures.test_packets import all_synthetic_frames  # noqa: E402


def _expected_per_frame() -> dict[int, set[str]]:
    corpus = json.loads((REPO / "eval" / "labelled_corpus.json").read_text())
    return {row["index"]: set(row["expected_detectors"])
            for row in corpus["frames"]}


def main() -> None:
    out_dir = REPO / "results"
    out_dir.mkdir(parents=True, exist_ok=True)

    blobs = all_synthetic_frames()
    frames = parse_bytes(blobs)
    expected = _expected_per_frame()

    # observed[frame_index] = set of detectors that produced a finding
    # whose ``frame_index`` matched that frame.
    observed_per_frame: dict[int, set[str]] = defaultdict(set)
    detector_signals_seen: dict[str, set[int]] = defaultdict(set)

    # For node_enum, the summary findings carry no frame_index; map
    # their signal to every observed source frame so the eval is fair.
    for name, detect in ALL_DETECTORS.items():
        for f in detect(frames):
            if f.frame_index is not None:
                observed_per_frame[f.frame_index].add(name)
                detector_signals_seen[name].add(f.frame_index)
            else:
                # Summary finding. node_enum / default_key / unencrypted /
                # gps_leak all emit one. Apply the signal to every frame
                # they have a per-frame finding on, OR to every frame in
                # the corpus for node_enum (which is fundamentally a
                # whole-mesh inventory).
                if name == "node_enum":
                    for f2 in frames:
                        observed_per_frame[f2.pcap_index].add(name)
                        detector_signals_seen[name].add(f2.pcap_index)

    # Compute per-detector confusion matrix.
    per_det = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for idx, exp in expected.items():
        obs = observed_per_frame.get(idx, set())
        for det in ALL_DETECTORS:
            in_exp = det in exp
            in_obs = det in obs
            if in_exp and in_obs:
                per_det[det]["tp"] += 1
            elif in_obs and not in_exp:
                per_det[det]["fp"] += 1
            elif in_exp and not in_obs:
                per_det[det]["fn"] += 1

    def _metrics(c):
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        p = tp / (tp + fp) if (tp + fp) else 1.0
        r = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        return {**c, "precision": round(p, 4), "recall": round(r, 4),
                "f1": round(f1, 4)}

    per_det_out = {d: _metrics(c) for d, c in per_det.items()}
    agg = {"tp": 0, "fp": 0, "fn": 0}
    for c in per_det.values():
        for k in agg:
            agg[k] += c[k]
    aggregate = _metrics(agg)

    summary = {
        "n_frames":  len(frames),
        "aggregate": aggregate,
        "per_detector": per_det_out,
    }
    (out_dir / "eval_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True))

    with (out_dir / "eval_raw.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["detector", "tp", "fp", "fn", "precision", "recall", "f1"])
        for d in sorted(per_det_out):
            m = per_det_out[d]
            w.writerow([d, m["tp"], m["fp"], m["fn"],
                        m["precision"], m["recall"], m["f1"]])
        w.writerow(["AGGREGATE",
                    aggregate["tp"], aggregate["fp"], aggregate["fn"],
                    aggregate["precision"], aggregate["recall"], aggregate["f1"]])

    print(f"[eval] {len(frames)} frames evaluated")
    print(f"[eval] aggregate: P={aggregate['precision']:.4f} "
          f"R={aggregate['recall']:.4f} F1={aggregate['f1']:.4f} "
          f"(tp={aggregate['tp']} fp={aggregate['fp']} fn={aggregate['fn']})")
    print("[eval] per-detector:")
    for d in sorted(per_det_out):
        m = per_det_out[d]
        print(f"  {d:<12} P={m['precision']:.4f} R={m['recall']:.4f} "
              f"F1={m['f1']:.4f}  (tp={m['tp']} fp={m['fp']} fn={m['fn']})")


if __name__ == "__main__":
    main()
