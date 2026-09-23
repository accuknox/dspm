"""Evaluate fully labelled synthetic cases without ignoring extra detections.

Run with ``python -m scripts.evaluate_accuracy --output /tmp/accuracy.json``.
The matching unit is (detector, exact value, cell/blob location), with duplicate
occurrences counted. This is a diagnostic regression benchmark, not an estimate
of production accuracy or a comparison with a commercial product.
"""
import argparse
import json
from collections import Counter
from pathlib import Path

from src.engine.detector import DetectionEngine
from src.pipeline import Cell, Record, TextBlob, UnitClassifier, document_record

DEFAULT_CORPUS = Path(__file__).resolve().parents[1] / "tests/fixtures/accuracy_cases.json"


def metrics(tp, fp, fn):
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def classify_case(case, config):
    config = {**config, **case.get("config", {}), "aggregation_threshold": 0}
    engine = DetectionEngine(config)
    classifier = UnitClassifier(engine, f"benchmark://{case['id']}", config=config)
    if "rows" in case:
        for row_index, row in enumerate(case["rows"]):
            classifier.feed(
                Record([
                    Cell(str(value), field, f"row:{row_index}:{field}")
                    for field, value in row.items() if value is not None
                ]),
            )
    elif "documents" in case:
        for index, document in enumerate(case["documents"]):
            classifier.feed(document_record(document, lambda path, i=index: f"doc:{i}:{path}"))
    else:
        classifier.feed(TextBlob(case["text"], location="text"))
    return classifier.finish()


def evaluate(corpus):
    per_detector = {}
    cases = []
    seen = set()
    for case in corpus["cases"]:
        if case["id"] in seen or sum(key in case for key in ("rows", "documents", "text")) != 1:
            raise ValueError(f"invalid or duplicate case: {case['id']}")
        seen.add(case["id"])
        expected = Counter(
            (item["detector"], item["value"], item["location"]) for item in case["expected"]
        )
        reported = Counter(
            (item["detector"], item["value"], item["location"])
            for item in classify_case(case, corpus["config"])
        )
        matched, extra, missing = expected & reported, reported - expected, expected - reported
        for counts, metric in ((matched, "tp"), (extra, "fp"), (missing, "fn")):
            for (detector, _value, _location), count in counts.items():
                per_detector.setdefault(detector, Counter())[metric] += count
        # Reports contain case identifiers and counts, never sensitive values.
        def by_detector(counts):
            out = Counter()
            for (detector, _value, _location), count in counts.items():
                out[detector] += count
            return dict(sorted(out.items()))

        cases.append({
            "id": case["id"], "passed": not extra and not missing,
            "tp": sum(matched.values()), "fp": sum(extra.values()), "fn": sum(missing.values()),
            "unexpected_detectors": by_detector(extra), "missed_detectors": by_detector(missing),
        })
    totals = Counter()
    for counts in per_detector.values():
        totals.update(counts)
    return {
        "schema_version": 1,
        "scope": "Fully labelled synthetic regression cases; not production accuracy",
        "matching": "detector, exact value, cell/blob location; aggregation disabled",
        "config": corpus["config"],
        "summary": {
            **metrics(totals["tp"], totals["fp"], totals["fn"]),
            "cases": len(cases), "cases_passed": sum(case["passed"] for case in cases),
        },
        "per_detector": {
            detector: metrics(counts["tp"], counts["fp"], counts["fn"])
            for detector, counts in sorted(per_detector.items())
        },
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true", help="Exit nonzero if any labelled case fails")
    args = parser.parse_args()
    report = evaluate(json.loads(args.corpus.read_text(encoding="utf-8")))
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    if args.check and report["summary"]["cases_passed"] != report["summary"]["cases"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
