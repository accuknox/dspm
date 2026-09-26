"""Benchmark the detection engine on public PII datasets.

Datasets, cached under output/benchmarks/datasets/ (downloaded from Hugging Face, see README there):

    privy     beki/privy (MIT). Synthetic API payloads as JSON, SQL, XML and HTML protocol traces,
              26 Presidio-style labels. File: test-large.json inside privy-dataset.zip (streamed, reservoir-sampled).
    nemotron  nvidia/Nemotron-PII (CC BY 4.0). Persona-grounded documents, US and international locales,
              55 labels. File: nemotron-pii-test.parquet (random sample).
    gretel    gretelai/synthetic_pii_finance_multilingual (Apache 2.0). Full-length financial documents,
              29 labels. File: gretel-english-test.parquet (whole English test split).

Run:

    .venv/bin/python -m scripts.benchmark_public_datasets --dataset all --limit 5000 --seed 7
    .venv/bin/python -m scripts.benchmark_public_datasets --dataset privy --privy-mode json

Scoring. Every record is one TextBlob through UnitClassifier with aggregation off and the reporting
floor at `possible`; metrics are computed afterwards at each tier (possible / likely / very_likely).
A gold span counts as detected when an engine hit of an accepted detector overlaps it (lenient span
matching). Dataset labels are classed as target (scored for recall), ambiguous (an accepted hit is fine,
a miss is not counted) or unscored (the engine has no detector for them: dates, companies, demographics).
Engine hits that overlap no gold span are false positives ("no_gold"); hits on a scored span with a
detector of another type are "wrong_type"; hits on unscored spans are left out of precision.
Gold values that fail their own checksum (Luhn, IBAN mod-97, ABA routing, SSN structure) are reported
separately: LLM-generated datasets contain many invalid numbers, and `recall_on_valid` is the fair column.

Privy has a second mode (`--privy-mode json`): JSON payloads are fed as documents through
document_record, so field names drive the verdict as they do for a database or a JSON file, and gold
spans are matched by value instead of offset.

Reports hold labels, detector names and counts only, never values.
"""
import argparse
import ast
import json
import os
import random
import re
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "output" / "benchmarks" / "datasets"
REPORT_DIR = ROOT / "output" / "benchmarks"
MAPPING_FILES = ("findings-mapping.json", "findings-mapping-v2.json", "findings-mapping-v1.json")

TIERS = ("possible", "likely", "very_likely")
RANK = {tier: index for index, tier in enumerate(TIERS)}

# Detectors that never count as false positives: document-level keyword verdicts and disabled types.
IGNORED_DETECTORS = {"Healthcare Data Detection", "URL", "UUID"}


# ---------------------------------------------------------------------------- detector groups
def _load_categories() -> Dict[str, str]:
    for name in MAPPING_FILES:
        path = ROOT / "fixtures" / name
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            data = data[0] if isinstance(data, list) else data
            return {detector: entry.get("category", "") for detector, entry in data.items()}
    return {}


CATEGORY = _load_categories()
SECRET_DETECTORS = {d for d, c in CATEGORY.items() if c in ("Credentials and Secrets", "Entropy-Based Secret Detection")}
REGIONAL_DETECTORS = {d for d, c in CATEGORY.items() if c == "Regional Compliance"}

GROUPS: Dict[str, Set[str]] = {
    "name": {"PII.PersonName"},
    "email": {"Email"},
    "phone": {"Phone Number", "ZA_MOBILE_NUMBER", "ZA_TELEPHONE_NUMBER", "PH_MOBILE_NUMBER"},
    "card": {"Credit Card"},
    "iban": {"IBAN"},
    "bank": {"Bank Account", "IBAN", "ABA_ROUTING_NUMBER", "GB_SORT_CODE", "AU_BSB"},
    "routing": {"ABA_ROUTING_NUMBER", "Bank Account"},
    "swift": {"SWIFT/BIC"},
    "ssn": {"US SSN"},
    "itin": {"US_ITIN", "US SSN"},
    "passport": {"US_PASSPORT", "UK_PASSPORT", "PASSPORT_MRZ", "IN PASSPORT", "DE_PASSPORT", "ES_PASSPORT",
                 "IT_PASSPORT", "FR_PASSPORT", "JP_PASSPORT", "KR_PASSPORT", "PH_PASSPORT", "ZA_PASSPORT"},
    "driver": {"US_DRIVER_LICENSE", "UK_DRIVING_LICENCE", "IT_DRIVER_LICENSE", "KR_DRIVER_LICENSE",
               "ZA_DRIVER_LICENSE", "DE_FUEHRERSCHEIN"},
    "ip": {"PII.IPAddress"},
    "mac": {"MAC_ADDRESS"},
    "imei": {"IMEI"},
    "coordinate": {"GEO_COORDINATES"},
    "address": {"Address"},
    "dob": {"Date of Birth"},
    "secret": set(SECRET_DETECTORS) or {"Password Pattern", "API Key", "Bearer Token", "High Entropy Secret"},
    "mrn": {"MEDICAL_RECORD_NUMBER"},
    "health_member": {"US_HEALTH_INSURANCE_MEMBER_ID", "US_MBI"},
    "vin": {"VIN"},
    "plate": {"UK_VEHICLE_REGISTRATION", "TR_LICENSE_PLATE", "DE_KFZ", "ZA_LICENSE_PLATE",
              "IN_VEHICLE_REGISTRATION", "NG_VEHICLE_REGISTRATION"},
    "user": {"PII.UserIdentifier"},
    "postcode": {"UK_POSTCODE", "CA_POSTAL_CODE", "DE_PLZ", "Address"},
    "regional": set(REGIONAL_DETECTORS),
    "device": {"IMEI", "ICCID", "MAC_ADDRESS"},
    "licence": {"MEDICAL_LICENSE", "US_NPI"} | {"US_DRIVER_LICENSE", "UK_DRIVING_LICENCE"},
    "url": {"URL"},
    "uuid": {"UUID"},
}
GROUPS["financial"] = GROUPS["bank"] | GROUPS["swift"] | GROUPS["card"] | GROUPS["iban"]
GROUPS.update({
    "in_pan": {"IN PAN"}, "in_aadhaar": {"IN Aadhaar"}, "in_upi": {"IN_UPI_ID"}, "in_ifsc": {"IN_IFSC"},
    "in_voter": {"IN VOTER ID"}, "in_gst": {"IN GST"}, "in_plate": {"IN_VEHICLE_REGISTRATION"},
    "medical_id": {"MEDICAL_RECORD_NUMBER", "US_HEALTH_INSURANCE_MEMBER_ID", "US_MBI"} | set(REGIONAL_DETECTORS),
})

# Which group's values carry a checksum the benchmark can verify.
VALIDATED_GROUPS = {"card": "card", "iban": "iban", "routing": "routing", "ssn": "ssn", "imei": "imei"}

# ---------------------------------------------------------------------------- dataset label specs
# label -> (class, group). class: target (scored) | ambiguous (accepted hit fine, miss not counted).
# Labels missing from the spec are unscored. Privy's "O" spans are negatives and are dropped from gold.
PRIVY_SPEC = {
    "PERSON": ("target", "name"), "EMAIL_ADDRESS": ("target", "email"), "PHONE_NUMBER": ("target", "phone"),
    "CREDIT_CARD": ("target", "card"), "IBAN_CODE": ("target", "iban"), "US_BANK_NUMBER": ("target", "bank"),
    "US_SSN": ("target", "ssn"), "US_ITIN": ("target", "itin"), "US_PASSPORT": ("target", "passport"),
    "US_DRIVER_LICENSE": ("target", "driver"), "IP_ADDRESS": ("target", "ip"), "MAC_ADDRESS": ("target", "mac"),
    "IMEI": ("target", "imei"), "COORDINATE": ("target", "coordinate"), "PASSWORD": ("target", "secret"),
    "FINANCIAL": ("ambiguous", "financial"), "LOCATION": ("ambiguous", "address"), "DATE_TIME": ("ambiguous", "dob"),
    "URL": ("ambiguous", "url"), "US_LICENSE_PLATE": ("ambiguous", "plate"),
}
NEMOTRON_SPEC = {
    "first_name": ("target", "name"), "last_name": ("target", "name"), "email": ("target", "email"),
    "phone_number": ("target", "phone"), "fax_number": ("target", "phone"), "street_address": ("target", "address"),
    "date_of_birth": ("target", "dob"), "credit_debit_card": ("target", "card"), "ssn": ("target", "ssn"),
    "bank_routing_number": ("target", "routing"), "account_number": ("target", "bank"), "swift_bic": ("target", "swift"),
    "ipv4": ("target", "ip"), "ipv6": ("target", "ip"), "mac_address": ("target", "mac"),
    "coordinate": ("target", "coordinate"), "password": ("target", "secret"), "api_key": ("target", "secret"),
    "http_cookie": ("target", "secret"), "medical_record_number": ("target", "mrn"),
    "health_plan_beneficiary_number": ("target", "health_member"), "tax_id": ("target", "regional"),
    "vehicle_identifier": ("ambiguous", "vin"), "license_plate": ("ambiguous", "plate"),
    "certificate_license_number": ("ambiguous", "licence"), "user_name": ("ambiguous", "user"),
    "pin": ("ambiguous", "secret"), "device_identifier": ("ambiguous", "device"), "unique_id": ("ambiguous", "uuid"),
    "url": ("ambiguous", "url"), "postcode": ("ambiguous", "postcode"), "cvv": ("ambiguous", "secret"),
}
GRETEL_SPEC = {
    "name": ("target", "name"), "first_name": ("target", "name"), "last_name": ("target", "name"),
    "email": ("target", "email"), "phone_number": ("target", "phone"), "street_address": ("target", "address"),
    "date_of_birth": ("target", "dob"), "credit_card_number": ("target", "card"), "ssn": ("target", "ssn"),
    "bank_routing_number": ("target", "routing"), "bban": ("target", "bank"), "iban": ("target", "iban"),
    "swift_bic_code": ("target", "swift"), "ipv4": ("target", "ip"), "ipv6": ("target", "ip"),
    "local_latlng": ("target", "coordinate"), "passport_number": ("target", "passport"),
    "driver_license_number": ("target", "driver"), "password": ("target", "secret"), "api_key": ("target", "secret"),
    "account_pin": ("ambiguous", "secret"), "user_name": ("ambiguous", "user"),
    "credit_card_security_code": ("ambiguous", "secret"),
}
GRETEL_GENERAL_SPEC = {
    **NEMOTRON_SPEC,
    "name": ("target", "name"), "address": ("target", "address"), "credit_card_number": ("target", "card"),
    "national_id": ("target", "regional"), "unique_identifier": ("ambiguous", "uuid"),
}
YLEMIS_SPEC = {
    "person": ("target", "name"), "indian_phone": ("target", "phone"), "address": ("target", "address"),
    "pan": ("target", "in_pan"), "aadhaar": ("target", "in_aadhaar"), "email": ("target", "email"),
    "upi_id": ("target", "in_upi"), "ifsc": ("target", "in_ifsc"), "voter_id": ("target", "in_voter"),
    "gstin": ("target", "in_gst"), "indian_passport": ("target", "passport"),
    "vehicle_registration": ("target", "in_plate"), "account_id": ("ambiguous", "bank"),  # policy_1467545_783-style ids, not account numbers
    "medical_id": ("ambiguous", "medical_id"), "location": ("ambiguous", "address"),
}
SPECS = {"privy": PRIVY_SPEC, "nemotron": NEMOTRON_SPEC, "gretel": GRETEL_SPEC, "gretel-general": GRETEL_GENERAL_SPEC, "ylemis": YLEMIS_SPEC}
LICENCES = {
    "privy": "beki/privy, MIT", "nemotron": "nvidia/Nemotron-PII, CC BY 4.0",
    "gretel": "gretelai/synthetic_pii_finance_multilingual, Apache 2.0",
    "gretel-general": "gretelai/gretel-pii-masking-en-v1, Apache 2.0",
    "ylemis": "Pranshurs/ylemis-india-pii-benchmark, CC0 1.0",
}
# Ylemis slices whose text is Latin-script; the Indic-script slices are out of scope for an English engine
YLEMIS_LANGUAGES = ("en-IN", "hi-Latn", "code-mixed-IN", "mixed-script-IN", "ocr-en-IN", "llm-prompt-IN")


# ---------------------------------------------------------------------------- validators
def _digits(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        d = ord(char) - 48
        if index % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card_valid(value: str) -> bool:
    d = _digits(value)
    return 13 <= len(d) <= 19 and luhn_ok(d)


def imei_valid(value: str) -> bool:
    d = _digits(value)
    return len(d) == 15 and luhn_ok(d)


def iban_valid(value: str) -> bool:
    s = re.sub(r"\s+", "", value or "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    number = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return int(number) % 97 == 1


def routing_valid(value: str) -> bool:
    d = _digits(value)
    if len(d) != 9:
        return False
    n = [int(c) for c in d]
    return (3 * (n[0] + n[3] + n[6]) + 7 * (n[1] + n[4] + n[7]) + (n[2] + n[5] + n[8])) % 10 == 0


def ssn_valid(value: str) -> bool:
    d = _digits(value)
    if len(d) != 9:
        return False
    area, group, serial = int(d[:3]), int(d[3:5]), int(d[5:])
    return area not in (0, 666) and area < 900 and group != 0 and serial != 0


VALIDATORS = {"card": card_valid, "iban": iban_valid, "routing": routing_valid, "ssn": ssn_valid, "imei": imei_valid}


# ---------------------------------------------------------------------------- loaders
class Record:
    __slots__ = ("id", "text", "gold", "meta")

    def __init__(self, rid: str, text: str, gold: List[Tuple[str, int, int, str]], meta: Dict[str, Any]):
        self.id, self.text, self.gold, self.meta = rid, text, gold, meta


def _parse_spans(raw: Any) -> List[Dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, str):
        return list(raw)
    try:
        return json.loads(raw)
    except ValueError:
        return ast.literal_eval(raw)


def _payload_format(text: str) -> str:
    head = text.lstrip()[:8]
    if head[:1] in "{[":
        return "json"
    if head[:1] == "<":
        return "xml/html"
    if head[:6].upper() in ("INSERT", "SELECT", "UPDATE"):
        return "sql"
    return "other"


def load_privy(limit: Optional[int], seed: int) -> List[Record]:
    """Reservoir-samples test-large.json straight out of the zip; never extracts 700 MB to disk."""
    import ijson

    archive = DATA_DIR / "privy-dataset.zip"
    rng = random.Random(seed)
    sample: List[Record] = []
    seen = 0
    with zipfile.ZipFile(archive).open("test-large.json") as handle:
        for item in ijson.items(handle, "item"):
            text = item["full_text"]
            gold = [
                (s["entity_type"], int(s["start_position"]), int(s["end_position"]), s.get("entity_value") or text[s["start_position"]:s["end_position"]])
                for s in item.get("spans", []) if s["entity_type"] != "O"
            ]
            record = Record(f"privy:{item.get('template_id')}:{seen}", text, gold, {"format": _payload_format(text)})
            seen += 1
            if limit is None:
                sample.append(record)
            elif len(sample) < limit:
                sample.append(record)
            else:
                slot = rng.randrange(seen)
                if slot < limit:
                    sample[slot] = record
    return sample


def load_nemotron(limit: Optional[int], seed: int) -> List[Record]:
    import pandas as pd

    frame = pd.read_parquet(DATA_DIR / "nemotron-pii-test.parquet", columns=["uid", "text", "spans", "locale", "document_format"])
    if limit is not None and limit < len(frame):
        frame = frame.sample(n=limit, random_state=seed)
    records = []
    for row in frame.itertuples(index=False):
        gold = [(s["label"], int(s["start"]), int(s["end"]), row.text[int(s["start"]):int(s["end"])]) for s in _parse_spans(row.spans)]
        records.append(Record(f"nemotron:{row.uid}", row.text, gold, {"locale": row.locale, "format": row.document_format}))
    return records


def load_gretel(limit: Optional[int], seed: int) -> List[Record]:
    import pandas as pd

    frame = pd.read_parquet(DATA_DIR / "gretel-english-test.parquet", columns=["generated_text", "pii_spans", "document_type"])
    if limit is not None and limit < len(frame):
        frame = frame.sample(n=limit, random_state=seed)
    records = []
    for position, row in enumerate(frame.itertuples(index=False)):
        text = row.generated_text
        gold = [(s["label"], int(s["start"]), int(s["end"]), text[int(s["start"]):int(s["end"])]) for s in _parse_spans(row.pii_spans)]
        records.append(Record(f"gretel:{position}", text, gold, {"document_type": row.document_type}))
    return records


def load_gretel_general(limit: Optional[int], seed: int) -> List[Record]:
    """gretel-pii-masking-en-v1 lists entity values without offsets: every verbatim occurrence becomes a gold span."""
    import pandas as pd

    frame = pd.read_parquet(DATA_DIR / "gretel-general-test.parquet", columns=["uid", "text", "entities", "domain", "document_type"])
    if limit is not None and limit < len(frame):
        frame = frame.sample(n=limit, random_state=seed)
    records = []
    for row in frame.itertuples(index=False):
        text = row.text
        gold = []
        for entity in _parse_spans(row.entities):
            value = entity.get("entity") or ""
            if not value:
                continue
            position = text.find(value)
            while position >= 0:
                for label in entity.get("types", []):
                    gold.append((label, position, position + len(value), value))
                position = text.find(value, position + len(value))
        records.append(Record(f"gretel-general:{row.uid}", text, gold, {"domain": row.domain, "document_type": row.document_type}))
    return records


def load_ylemis(limit: Optional[int], seed: int) -> List[Record]:
    """Ylemis India-PII benchmark: Latin-script slices only, hard negatives and benign rows included."""
    rows = []
    with (DATA_DIR / "ylemis-india-benchmark.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("language") in YLEMIS_LANGUAGES:
                rows.append(row)
    if limit is not None and limit < len(rows):
        rows = random.Random(seed).sample(rows, limit)
    records = []
    for row in rows:
        text = row["text"]
        gold = [(e["type"], int(e["start"]), int(e["end"]), text[int(e["start"]):int(e["end"])]) for e in row.get("entities", [])]
        records.append(Record(f"ylemis:{row['id']}", text, gold, {"language": row.get("language"), "category": row.get("category")}))
    return records


LOADERS = {"privy": load_privy, "nemotron": load_nemotron, "gretel": load_gretel, "gretel-general": load_gretel_general, "ylemis": load_ylemis}


# ---------------------------------------------------------------------------- engine
def build_engine(args):
    if args.ner_model:
        os.environ["NER_MODEL"] = args.ner_model
    os.environ["NER_ENABLED"] = "false" if args.no_ner else "true"
    sys.path.insert(0, str(ROOT))
    from src.engine.detector import DetectionEngine  # noqa: WPS433 (after env is set)

    config = {
        "aggregation_threshold": 0,
        "min_confidence": "possible",
        "enabled_regions": [r.strip().upper() for r in args.regions.split(",") if r.strip()],
        "report_private_ips": True,  # the datasets label every IP address, private ranges included
        "ner": not args.no_ner,
    }
    return DetectionEngine(config), config


def scan_text(engine, config, record: Record) -> List[Dict[str, Any]]:
    from src.pipeline import TextBlob, UnitClassifier

    classifier = UnitClassifier(engine, record.id, config=config)
    classifier.feed(TextBlob(record.text, location="text", locate=lambda start, end: f"{start}:{end}"))
    hits = []
    for finding in classifier.finish():
        match = re.fullmatch(r"(\d+):(\d+)", str(finding.get("location", "")))
        if not match:
            continue  # document-level verdicts carry no span
        hits.append({
            "detector": finding["detector"], "start": int(match.group(1)), "end": int(match.group(2)),
            "confidence": finding["confidence"], "value": str(finding.get("value", "")),
        })
    return hits


def scan_json_document(engine, config, record: Record) -> Optional[List[Dict[str, Any]]]:
    """Privy JSON mode: the payload as a document, so field names count. None when it is not a JSON object."""
    from src.pipeline import UnitClassifier, document_record

    try:
        document = json.loads(record.text)
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None
    classifier = UnitClassifier(engine, record.id, config=config)
    classifier.feed(document_record(document, lambda path: path))
    return [
        {"detector": f["detector"], "start": -1, "end": -1, "confidence": f["confidence"], "value": str(f.get("value", ""))}
        for f in classifier.finish()
    ]


# ---------------------------------------------------------------------------- scoring
def _overlaps(hit: Dict[str, Any], start: int, end: int) -> bool:
    return hit["start"] < end and hit["end"] > start


def _value_match(hit_value: str, gold_value: str) -> bool:
    a, b = hit_value.strip().strip("\"'"), gold_value.strip().strip("\"'")
    return bool(a) and bool(b) and (a == b or a in b or b in a)


def score(records: List[Record], results: List[List[Dict[str, Any]]], spec: Dict[str, Tuple[str, str]], tier: str, by_value: bool) -> Dict[str, Any]:
    per_label: Dict[str, Counter] = defaultdict(Counter)
    per_group: Dict[str, Counter] = defaultdict(Counter)
    fp_by_detector: Counter = Counter()
    fp_kind: Counter = Counter()
    unscored_labels: Counter = Counter()
    accepted_hits = 0

    for record, hits in zip(records, results):
        live = [h for h in hits if RANK[h["confidence"]] >= RANK[tier] and h["detector"] not in IGNORED_DETECTORS]
        matched_hits: Set[int] = set()
        for label, start, end, value in record.gold:
            klass, group = spec.get(label, ("unscored", None))
            if klass == "unscored":
                unscored_labels[label] += 1
                continue
            accepted = GROUPS[group]
            found = None
            for index, hit in enumerate(live):
                near = _value_match(hit["value"], value) if by_value else _overlaps(hit, start, end)
                if near and hit["detector"] in accepted:
                    found = index
                    break
            if found is not None:
                matched_hits.add(found)
            if klass != "target":
                continue
            counters = per_label[label]
            counters["gold"] += 1
            counters["tp" if found is not None else "fn"] += 1
            if group == "email" and re.search(r"@(?:[\w.-]*\.)?example\.(?:com|org|net)$", value.strip().lower()):
                counters["demo_domain_gold"] += 1  # the engine skips example.* addresses on purpose
            validator = VALIDATORS.get(VALIDATED_GROUPS.get(group, ""))
            if validator is not None:
                if validator(value):
                    counters["gold_valid"] += 1
                    counters["tp_valid" if found is not None else "fn_valid"] += 1
                else:
                    counters["gold_invalid"] += 1
            per_group[group]["gold"] += 1
            per_group[group]["tp" if found is not None else "fn"] += 1

        for index, hit in enumerate(live):
            if index in matched_hits:
                accepted_hits += 1
                continue
            touching = []
            for label, start, end, value in record.gold:
                near = _value_match(hit["value"], value) if by_value else _overlaps(hit, start, end)
                if near:
                    touching.append(spec.get(label, ("unscored", None))[0])
            if not touching:
                fp_kind["no_gold"] += 1
                fp_by_detector[hit["detector"]] += 1
            elif all(k == "unscored" for k in touching):
                fp_kind["on_unscored_span"] += 1  # not counted against precision
            else:
                fp_kind["wrong_type"] += 1
                fp_by_detector[hit["detector"]] += 1

    tp = sum(c["tp"] for c in per_label.values())
    fn = sum(c["fn"] for c in per_label.values())
    fp = fp_kind["no_gold"] + fp_kind["wrong_type"]
    precision = accepted_hits / (accepted_hits + fp) if accepted_hits + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None

    def label_row(counters: Counter) -> Dict[str, Any]:
        row = {"gold": counters["gold"], "tp": counters["tp"], "fn": counters["fn"],
               "recall": round(counters["tp"] / counters["gold"], 3) if counters["gold"] else None}
        if counters["demo_domain_gold"]:
            row["demo_domain_gold"] = counters["demo_domain_gold"]
        if counters["gold_valid"] or counters["gold_invalid"]:
            row["gold_valid"] = counters["gold_valid"]
            row["gold_invalid"] = counters["gold_invalid"]
            row["recall_on_valid"] = round(counters["tp_valid"] / counters["gold_valid"], 3) if counters["gold_valid"] else None
        return row

    return {
        "tier": tier,
        "summary": {
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
            "accepted_hits": accepted_hits, "false_positives": fp, "gold_target_spans": tp + fn,
            "fp_no_gold": fp_kind["no_gold"], "fp_wrong_type": fp_kind["wrong_type"],
            "hits_on_unscored_spans": fp_kind["on_unscored_span"],
        },
        "per_label": {label: label_row(c) for label, c in sorted(per_label.items())},
        "per_group": {group: {"gold": c["gold"], "recall": round(c["tp"] / c["gold"], 3) if c["gold"] else None}
                      for group, c in sorted(per_group.items())},
        "false_positives_by_detector": dict(fp_by_detector.most_common(20)),
        "unscored_label_spans": dict(unscored_labels.most_common()),
    }


# ---------------------------------------------------------------------------- driver
def run(dataset: str, args, engine, config) -> Dict[str, Any]:
    spec = SPECS[dataset]
    started = time.time()
    records = LOADERS[dataset](args.limit, args.seed)
    by_value = dataset == "privy" and args.privy_mode == "json"
    if by_value:
        records = [r for r in records if r.meta.get("format") == "json"]
    print(f"[{dataset}] {len(records)} records loaded in {time.time() - started:.0f}s", file=sys.stderr, flush=True)

    results: List[List[Dict[str, Any]]] = []
    kept: List[Record] = []
    started = time.time()
    for index, record in enumerate(records, 1):
        hits = scan_json_document(engine, config, record) if by_value else scan_text(engine, config, record)
        if hits is None:
            continue
        kept.append(record)
        results.append(hits)
        if index % 250 == 0:
            print(f"[{dataset}] {index}/{len(records)} scanned, {time.time() - started:.0f}s", file=sys.stderr, flush=True)
    seconds = time.time() - started
    if args.save_hits:
        suffix = "-json" if by_value else ""
        with (args.output_dir / f"{dataset}{suffix}-hits.jsonl").open("w", encoding="utf-8") as handle:
            for record, hits in zip(kept, results):
                handle.write(json.dumps({
                    "id": record.id, "meta": record.meta,
                    "gold": [(label, start, end, value if by_value else "") for label, start, end, value in record.gold],
                    "hits": [{k: h[k] for k in ("detector", "start", "end", "confidence", *(("value",) if by_value else ()))} for h in hits],
                }) + "\n")

    if args.show_misses:
        shown = 0
        for record, hits in zip(kept, results):
            for label, start, end, value in record.gold:
                klass, group = spec.get(label, ("unscored", None))
                if klass != "target":
                    continue
                ok = any((_value_match(h["value"], value) if by_value else _overlaps(h, start, end)) and h["detector"] in GROUPS[group] for h in hits)
                if not ok and shown < args.show_misses:
                    shown += 1
                    context = record.text[max(0, start - 40):end + 40].replace("\n", " ")
                    print(f"  MISS {label:<28} {value!r:<32} ...{context}...", file=sys.stderr)

    report = {
        "dataset": dataset, "licence": LICENCES[dataset], "mode": "json-document" if by_value else "text",
        "records": len(kept), "limit": args.limit, "seed": args.seed, "seconds": round(seconds, 1),
        "config": {**config, "ner_model": os.environ.get("NER_MODEL") or "default"},
        "matching": "value" if by_value else "lenient span overlap",
        "tiers": {tier: score(kept, results, spec, tier, by_value) for tier in TIERS},
    }
    if dataset == "privy" and not by_value:
        report["formats"] = dict(Counter(r.meta.get("format") for r in kept))
    return report


def markdown_summary(reports: List[Dict[str, Any]]) -> str:
    lines = ["| Dataset | Mode | Records | Tier | Precision | Recall | F1 | Accepted hits | False positives | Gold spans |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for report in reports:
        for tier in TIERS:
            s = report["tiers"][tier]["summary"]
            lines.append(f"| {report['dataset']} | {report['mode']} | {report['records']} | {tier} | {s['precision']} | {s['recall']} | {s['f1']} | {s['accepted_hits']} | {s['false_positives']} | {s['gold_target_spans']} |")
    lines.append("")
    for report in reports:
        likely = report["tiers"]["likely"]
        lines.append(f"### {report['dataset']} ({report['mode']}), per label at `likely`")
        lines.append("")
        lines.append("| Label | Gold | Recall | Valid gold | Recall on valid |")
        lines.append("| --- | --- | --- | --- | --- |")
        for label, row in likely["per_label"].items():
            lines.append(f"| {label} | {row['gold']} | {row['recall']} | {row.get('gold_valid', '')} | {row.get('recall_on_valid', '')} |")
        lines.append("")
        lines.append("False positives by detector at `likely`: " + ", ".join(f"{d} {n}" for d, n in likely["false_positives_by_detector"].items()))
        lines.append("")
    return "\n".join(lines)


def rescore(path: Path, args) -> Dict[str, Any]:
    """Re-score a saved hits file with the current label specs (no engine run)."""
    name = path.name.replace("-hits.jsonl", "")
    dataset, by_value = name.replace("-json", ""), name.endswith("-json")
    records, results = [], []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            records.append(Record(row["id"], "", [tuple(g) for g in row["gold"]], row["meta"]))
            results.append([{**h, "value": h.get("value", "")} for h in row["hits"]])
    return {
        "dataset": dataset, "licence": LICENCES[dataset], "mode": "json-document" if by_value else "text",
        "records": len(records), "rescored_from": str(path), "matching": "value" if by_value else "lenient span overlap",
        "tiers": {tier: score(records, results, SPECS[dataset], tier, by_value) for tier in TIERS},
    }


def summarize(output_dir: Path) -> Path:
    reports = []
    for path in sorted(output_dir.glob("*.json")):
        if path.name.endswith(("-hits.jsonl", "-rescored.json")):
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if "tiers" in data:
            reports.append(data)
    lines = ["# Public-dataset benchmark results", "",
             "Engine: src/engine + src/pipeline, aggregation off, NER model per report. Matching: lenient span overlap "
             "(value match in JSON-document mode). Precision counts accepted hits against false positives of kind no_gold and "
             "wrong_type; recall is over target labels only. `recall_on_valid` is recall on gold values that pass their own "
             "checksum, the fair column for LLM-generated numbers.", ""]
    lines += markdown_summary(reports).splitlines()
    lines += ["", "## Runs", ""]
    for report in reports:
        lines.append(f"- {report['dataset']} ({report['mode']}): {report['records']} records, seed {report.get('seed')}, "
                     f"{report.get('seconds', '?')} s, NER {report.get('config', {}).get('ner_model', '?')}, licence {report['licence']}")
    out = output_dir / "RESULTS.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", default="all", choices=["all", "privy", "nemotron", "gretel", "gretel-general", "ylemis"])
    parser.add_argument("--privy-mode", default="text", choices=["text", "json"])
    parser.add_argument("--limit", type=int, default=5000, help="records per dataset (Gretel's English test split is smaller)")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--regions", default="US,IN,GB", help="country packs, the product default")
    parser.add_argument("--ner-model", default="", help="en_core_web_trf (default when installed) or en_core_web_sm")
    parser.add_argument("--no-ner", action="store_true")
    parser.add_argument("--show-misses", type=int, default=0, help="print this many missed target spans per dataset to stderr")
    parser.add_argument("--output-dir", type=Path, default=REPORT_DIR)
    parser.add_argument("--save-hits", action="store_true", default=True, help="write <dataset>-hits.jsonl (spans and detectors, no values) for --rescore")
    parser.add_argument("--rescore", type=Path, help="re-score a saved -hits.jsonl with the current label specs instead of running the engine")
    parser.add_argument("--summarize", action="store_true", help="write RESULTS.md from every report in --output-dir and exit")
    args = parser.parse_args()
    if args.summarize:
        print(f"results: {summarize(args.output_dir)}")
        return
    if args.rescore:
        report = rescore(args.rescore, args)
        for tier in TIERS:
            print(f"[{report['dataset']}] {tier:<12} {json.dumps(report['tiers'][tier]['summary'])}", flush=True)
        out = args.rescore.with_name(args.rescore.name.replace("-hits.jsonl", "-rescored.json"))
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"report: {out}", flush=True)
        return

    engine, config = build_engine(args)
    datasets = ["privy", "nemotron", "gretel", "gretel-general", "ylemis"] if args.dataset == "all" else [args.dataset]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    reports = []
    for dataset in datasets:
        report = run(dataset, args, engine, config)
        suffix = "-json" if dataset == "privy" and args.privy_mode == "json" else ""
        path = args.output_dir / f"{dataset}{suffix}.json"
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        reports.append(report)
        for tier in TIERS:
            print(f"[{dataset}{suffix}] {tier:<12} {json.dumps(report['tiers'][tier]['summary'])}", flush=True)
        print(f"[{dataset}{suffix}] report: {path}", flush=True)
    summary = args.output_dir / ("summary" + ("-privy-json" if args.privy_mode == "json" and args.dataset == "privy" else "") + ".md")
    summary.write_text(markdown_summary(reports), encoding="utf-8")
    print(f"summary: {summary}", flush=True)


if __name__ == "__main__":
    main()
