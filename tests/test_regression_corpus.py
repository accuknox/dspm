"""
Regression corpus built from real scans (anonymised, see tests/fixtures/detection_corpus.json).

Every 'fp' sample was reported by the engine before the accuracy overhaul and
reviewed as noise; every 'tp' sample is real (or a synthetic recall case).
The test fails when a reviewed false positive comes back or a true positive is
lost - fix the detector or, if the review was wrong, relabel the sample.
"""
import json
from collections import Counter
from pathlib import Path

from src.engine.detector import DetectionEngine
from src.pipeline import Cell, Record, UnitClassifier

CORPUS = Path(__file__).resolve().parent / "fixtures" / "detection_corpus.json"

# Precision/recall floors enforced on every run. Raise them as the corpus grows and the
# engine improves; a change that drops below a floor fails the build (see test_metrics_meet_floor).
MIN_PRECISION = 0.98
MIN_RECALL = 0.98


def _corpus():
    return json.loads(CORPUS.read_text())


def _load():
    return _corpus()["samples"]


def _unit_rows(unit):
    """Explicit rows, or a compact integer range (keeps a 120-row phone column out of the JSON body)."""
    if unit.get("rows") is not None:
        return [str(r) for r in unit["rows"]]
    lo, hi = unit["rows_int_range"]
    return [str(n) for n in range(lo, hi)]


def _classify_unit(unit):
    """Run one labelled column/document through the pipeline; return the detectors it reported."""
    engine = DetectionEngine({"enabled_regions": ["US", "IN", "GB"]})
    clf = UnitClassifier(engine, f"corpus://{unit['id']}", unit_name=unit.get("unit_name"))
    field = unit.get("field")
    for i, value in enumerate(_unit_rows(unit)):
        clf.feed(Record([Cell(value, field, f"Row {i}")]))
    return {f["detector"] for f in clf.finish()}


def _evaluate(samples):
    engine = DetectionEngine({"enabled_regions": ["US", "IN", "GB"]})
    fp_retained, tp_missed = [], []
    per_detector = Counter()
    for sample in samples:
        findings = engine.scan_text(sample["text"], field_name=sample.get("field"))
        detectors = {f["detector"] for f in findings}
        categories = {f["category"] for f in findings}
        if sample["kind"] == "fp":
            if detectors & set(sample["forbid_detectors"]) or categories & set(sample["forbid_categories"]):
                if not sample.get("tolerated"):
                    fp_retained.append((sample["id"], sample["old_detector"], sorted(detectors)))
                    per_detector[sample["old_detector"]] += 1
        else:
            if not detectors & set(sample["expect_any"]):
                tp_missed.append((sample["id"], sample.get("old_detector"), sample["expect_any"], sorted(detectors)))
    return fp_retained, tp_missed, per_detector


def test_corpus_is_well_formed():
    samples = _load()
    assert len(samples) > 400
    kinds = Counter(s["kind"] for s in samples)
    assert kinds["fp"] > 300 and kinds["tp"] > 100
    for s in samples:
        assert s["text"] and s["kind"] in ("fp", "tp"), s["id"]
        if s["kind"] == "tp":
            assert s["expect_any"], s["id"]
        else:
            assert s["forbid_detectors"] and s["forbid_categories"], s["id"]


def test_reviewed_false_positives_stay_gone():
    fp_retained, _, per_detector = _evaluate(_load())
    assert not fp_retained, f"{len(fp_retained)} reviewed false positives reported again {dict(per_detector)}: {fp_retained[:10]}"


def test_true_positives_are_still_detected():
    _, tp_missed, _ = _evaluate(_load())
    assert not tp_missed, f"{len(tp_missed)} true positives lost: {tp_missed[:10]}"


# --------------------------------------------------------------------------- unit-level (pipeline)

def _evaluate_units(units):
    """Column/document cases: the engine corpus is per-value and cannot express column-density
    or count logic, where the highest-value real false positives live (phone columns tripping
    weak-checksum national IDs)."""
    fp_retained, tp_missed = [], []
    for unit in units:
        reported = _classify_unit(unit)
        if unit["kind"] == "fp":
            hit = reported & set(unit["forbid_detectors"])
            if hit:
                fp_retained.append((unit["id"], sorted(hit)))
        else:
            missing = set(unit["expect_detectors"]) - reported
            if missing:
                tp_missed.append((unit["id"], sorted(missing), sorted(reported)))
    return fp_retained, tp_missed


def test_unit_corpus_is_well_formed():
    units = _corpus().get("units", [])
    assert len(units) >= 4
    for u in units:
        assert u.get("rows") is not None or u.get("rows_int_range"), u["id"]
        assert u["kind"] in ("fp", "tp"), u["id"]
        assert (u["forbid_detectors"] if u["kind"] == "fp" else u["expect_detectors"]), u["id"]


def test_unit_reviewed_false_positives_stay_gone():
    fp_retained, _ = _evaluate_units(_corpus().get("units", []))
    assert not fp_retained, f"{len(fp_retained)} column-level false positives reported again: {fp_retained}"


def test_unit_true_positives_are_still_detected():
    _, tp_missed = _evaluate_units(_corpus().get("units", []))
    assert not tp_missed, f"{len(tp_missed)} column-level true positives lost: {tp_missed}"


# --------------------------------------------------------------------------- measured precision / recall

def _metrics(samples):
    """TP / FP / FN across the engine corpus -> precision and recall as numbers, not pass/fail."""
    engine = DetectionEngine({"enabled_regions": ["US", "IN", "GB"]})
    tp = fp = fn = 0
    for s in samples:
        findings = engine.scan_text(s["text"], field_name=s.get("field"))
        detectors = {f["detector"] for f in findings}
        categories = {f["category"] for f in findings}
        if s["kind"] == "tp":
            if detectors & set(s["expect_any"]):
                tp += 1
            else:
                fn += 1
        elif detectors & set(s["forbid_detectors"]) or categories & set(s["forbid_categories"]):
            if not s.get("tolerated"):
                fp += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall, tp, fp, fn


def test_metrics_meet_floor():
    precision, recall, tp, fp, fn = _metrics(_load())
    print(f"\n  corpus precision={precision:.4f} recall={recall:.4f}  (tp={tp} fp={fp} fn={fn})")
    assert precision >= MIN_PRECISION, f"precision {precision:.4f} below floor {MIN_PRECISION} (fp={fp})"
    assert recall >= MIN_RECALL, f"recall {recall:.4f} below floor {MIN_RECALL} (fn={fn})"
