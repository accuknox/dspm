"""Accuracy regressions for mixed content, encoded values and column statistics."""
import base64
import json

from scripts.evaluate_accuracy import DEFAULT_CORPUS, evaluate
from src.engine.detector import DetectionEngine
from src.pipeline import Cell, Record, UnitClassifier, document_record


def _engine():
    return DetectionEngine({"enabled_regions": ["US", "IN", "GB"], "ner": False})


def test_fully_labelled_accuracy_cases():
    report = evaluate(json.loads(DEFAULT_CORPUS.read_text(encoding="utf-8")))
    failures = [case for case in report["cases"] if not case["passed"]]
    assert not failures, failures
    assert report["summary"]["tp"] > 0


def test_false_alarm_cases_preserve_expected_detections():
    corpus = DEFAULT_CORPUS.with_name("false_alarm_cases.json")
    report = evaluate(json.loads(corpus.read_text(encoding="utf-8")))
    failures = [case for case in report["cases"] if not case["passed"]]
    assert not failures, failures
    assert report["summary"]["tp"] > 0


def test_weak_checksum_stays_possible_beside_identity_fields():
    classifier = UnitClassifier(_engine(), "unit://refs", config={"min_confidence": "possible"})
    classifier.feed(
        Record([
            Cell("Priya Sharma", "full_name", "name"),
            Cell("priya@acme-corp.io", "email", "email"),
            Cell("9434765919", "ref", "ref"),
        ]),
    )
    refs = [f for f in classifier.finish() if f["location"] == "ref"]
    assert len(refs) == 1 and refs[0]["detector"] == "UK_NHS"
    assert refs[0]["confidence"] == "possible"
    assert "needs_context" in refs[0]["evidence"] and "record:identity" not in refs[0]["evidence"]


def test_sibling_names_alone_do_not_promote_an_isolated_card_shape():
    classifier = UnitClassifier(_engine(), "unit://refs")
    corpus = json.loads(DEFAULT_CORPUS.read_text(encoding="utf-8"))
    cards = next(case for case in corpus["cases"] if case["id"] == "explicit_cards")
    card = cards["rows"][0]["card_number"]
    classifier.feed(
        Record([
            Cell(card, "ref", "ref"), Cell("12/27", "expiry", "expiry"), Cell("123", "cvv", "cvv"),
        ]),
    )
    assert classifier.finish() == []


def test_nested_siblings_only_strengthen_their_own_column_group():
    corpus = json.loads(DEFAULT_CORPUS.read_text(encoding="utf-8"))
    cards = next(case for case in corpus["cases"] if case["id"] == "explicit_cards")
    values = [row["card_number"] for row in cards["rows"]]
    unrelated = {
        "samples": [{"number": value} for value in values],
        "billing": {"expiry": "12/27", "cvv": "123"},
    }
    related = {"payments": [{"number": value, "expiry": "12/27", "cvv": "123"} for value in values]}
    for document, expected in ((unrelated, "likely"), (related, "very_likely")):
        classifier = UnitClassifier(_engine(), "unit://nested")
        classifier.feed(document_record(document, lambda path: path))
        findings = classifier.finish()
        assert len(findings) == len(values) and {f["detector"] for f in findings} == {"Credit Card"}
        assert {f["confidence"] for f in findings} == {expected}
        if document is unrelated:
            assert not any(e.startswith("siblings:") for f in findings for e in f["evidence"])


def test_evaluation_counts_extra_detections_on_positive_examples():
    # A positive example is not completely correct just because one expected
    # detector fired: an additional, unlabelled detection must count as an FP.
    corpus = {
        "config": {"ner": False},
        "cases": [{
            "id": "evaluation_contract",
            "text": "alice@acme-corp.io bob@acme-corp.io",
            "expected": [{"detector": "Email", "value": "alice@acme-corp.io", "location": "text"}],
        }],
    }
    report = evaluate(corpus)
    assert report["summary"]["tp"] == 1 and report["summary"]["fp"] == 1
    assert report["summary"]["precision"] == 0.5 and report["summary"]["recall"] == 1.0
    assert report["summary"]["cases_passed"] == 0
    assert "alice@" not in json.dumps(report) and "bob@" not in json.dumps(report)


def test_multiple_matches_count_as_one_cell_but_keep_occurrences():
    classifier = UnitClassifier(_engine(), "unit://notes", config={"aggregation_threshold": 2})
    for row in range(3):
        classifier.feed(
            Record([
                Cell(f"first{row}@acme-corp.io second{row}@acme-corp.io", "notes", f"Row {row}"),
            ]),
        )
    findings = classifier.finish()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["detector"] == "Email" and finding["occurrences"] == 6
    assert finding["column_sampled"] == finding["column_matches"] == finding["column_validated_matches"] == 3
    assert finding["column_ratio"] == finding["column_validated_ratio"] == 1.0


def test_array_elements_are_separate_sampled_cells():
    classifier = UnitClassifier(_engine(), "unit://contacts", config={"aggregation_threshold": 2})
    classifier.feed(
        document_record(
            {"contacts": [{"email": f"person{i}@acme-corp.io"} for i in range(3)]},
            lambda path: path,
        ),
    )
    findings = classifier.finish()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["column"] == "contacts[].email"
    assert finding["column_matches"] == finding["column_sampled"] == finding["occurrences"] == 3


def test_finishing_does_not_reuse_old_column_promotions():
    classifier = UnitClassifier(_engine(), "unit://notes", config={"aggregation_threshold": 0})
    for row in range(3):
        classifier.feed(Record([Cell(f"person{row}@acme-corp.io", "notes", f"Row {row}")]))
    first = classifier.finish()
    assert all(f["confidence"] == "very_likely" for f in first)
    assert classifier.finish() == first
    for row in range(3, 10):
        classifier.feed(Record([Cell("Nothing to report", "notes", f"Row {row}")]))
    final = classifier.finish()
    assert len(final) == 3 and all(f["confidence"] == "likely" for f in final)
    assert all(not any(e.startswith("column:") for e in f["evidence"]) for f in final)
    assert all(f["confidence"] == "very_likely" for f in first)


def test_different_types_in_one_encoded_cell_are_independent():
    classifier = UnitClassifier(_engine(), "unit://payloads", config={"aggregation_threshold": 0})
    for row in range(3):
        decoded = f"person{row}@acme-corp.io; telephone +44 20 7946 0958"
        encoded = base64.b64encode(decoded.encode()).decode()
        classifier.feed(Record([Cell(encoded, "payload", f"Row {row}")]))
    findings = classifier.finish()
    assert len(findings) == 6
    assert {f["detector"] for f in findings} == {"Email", "Phone Number"}


def test_distinct_email_claims_survive_jwt_overlap_resolution():
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    token = ".".join([
        encode({"alg": "HS256", "typ": "JWT"}),
        encode({"email": "alice@acme-corp.io", "preferred_username": "bob@acme-corp.io"}),
        base64.urlsafe_b64encode(b"synthetic-signature-for-offline-test").decode().rstrip("="),
    ])
    findings = _engine().scan_text(token)
    assert sum(f["detector"] == "JWT Token" for f in findings) == 1
    emails = [f["value"] for f in findings if f["detector"] == "Email"]
    assert len(emails) == 2  # JWT and base64 scans must not duplicate the same claims.
    assert set(emails) == {
        "alice@acme-corp.io", "bob@acme-corp.io",
    }
