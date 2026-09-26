"""Unit tests for scripts/benchmark_public_datasets.py: validators, payload sniffing and the scorer.
No dataset download is needed; the loaders are not exercised here."""
from scripts.benchmark_public_datasets import (
    GROUPS, Record, _payload_format, card_valid, iban_valid, imei_valid, routing_valid, score, ssn_valid,
)


def test_validators_accept_checksum_valid_values_only():
    assert card_valid("4111 1111 1111 1111") and not card_valid("4111111111111112")
    assert iban_valid("GB82 WEST 1234 5698 7654 32") and not iban_valid("GB82 WEST 1234 5698 7654 33")
    assert routing_valid("021000021") and not routing_valid("271210785")
    assert ssn_valid("219-09-9999")
    assert not ssn_valid("666-12-3456") and not ssn_valid("000-12-3456") and not ssn_valid("219-00-9999")
    assert imei_valid("490154203237518") and not imei_valid("490154203237519")


def test_payload_format_sniffing():
    assert _payload_format('{"a": 1}') == "json"
    assert _payload_format("<table><tr>") == "xml/html"
    assert _payload_format("INSERT INTO t VALUES (1)") == "sql"
    assert _payload_format("plain words") == "other"


SPEC = {"email": ("target", "email"), "ssn": ("target", "ssn"), "url": ("ambiguous", "url")}


def _hit(detector, start, end, confidence="likely", value=""):
    return {"detector": detector, "start": start, "end": end, "confidence": confidence, "value": value}


def test_scorer_counts_overlap_hits_wrong_types_and_tiers():
    text = "mail a@b.com ssn 219-09-9999 site http://x.io free 123-45-6789 company Acme"
    record = Record(
        "r1", text, [
            ("email", 5, 12, "a@b.com"),          # target, hit by Email
            ("ssn", 17, 28, "219-09-9999"),       # target, hit only by a Phone Number (wrong type)
            ("url", 34, 45, "http://x.io"),       # ambiguous, URL hit is fine
            ("company", 71, 75, "Acme"),          # unscored label
        ], {},
    )
    hits = [
        _hit("Email", 5, 12),
        _hit("Phone Number", 17, 28),
        _hit("URL", 34, 45),
        _hit("US SSN", 51, 62, "possible"),   # no gold span: a false positive, but only at `possible`
        _hit("PII.PersonName", 71, 75),       # on an unscored span: left out of precision
    ]
    likely = score([record], [hits], SPEC, "likely", by_value=False)
    assert likely["summary"]["accepted_hits"] == 1
    assert likely["summary"]["fp_wrong_type"] == 1 and likely["summary"]["fp_no_gold"] == 0
    assert likely["summary"]["hits_on_unscored_spans"] == 1
    assert likely["per_label"]["email"]["recall"] == 1.0 and likely["per_label"]["ssn"]["recall"] == 0.0
    assert likely["per_label"]["ssn"]["gold_valid"] == 1 and likely["per_label"]["ssn"]["recall_on_valid"] == 0.0
    assert likely["unscored_label_spans"] == {"company": 1}
    assert likely["summary"]["precision"] == 0.5 and likely["summary"]["recall"] == 0.5

    possible = score([record], [hits], SPEC, "possible", by_value=False)
    assert possible["summary"]["fp_no_gold"] == 1
    assert possible["false_positives_by_detector"] == {"Phone Number": 1, "US SSN": 1}


def test_scorer_matches_by_value_in_document_mode():
    record = Record("r2", '{"email": "a@b.com"}', [("email", 11, 18, "a@b.com")], {"format": "json"})
    hits = [_hit("Email", -1, -1, value="a@b.com")]
    assert score([record], [hits], SPEC, "likely", by_value=True)["per_label"]["email"]["tp"] == 1
    assert "Email" in GROUPS["email"]
