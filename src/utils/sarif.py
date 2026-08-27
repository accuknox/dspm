"""
Converts DSPM findings into SARIF 2.1.0 for interchange with code-scanning
tools (GitHub code scanning, AccuKnox SARIF ingestion, IDE viewers).

Also usable standalone on a worker findings JSON:
    python -m src.utils.sarif findings.json out.sarif [--mask]
"""
import json
from typing import Any, Dict, List, Union

from src.scanners.base import mask_value

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "AccuKnox DSPM Scanner"
TOOL_URI = "https://github.com/accuknox/dspm"
TOOL_VERSION = "0.1.0"

# SARIF levels: error | warning | note
SEVERITY_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}

RUN_METADATA_KEYS = ("object_type", "object_name", "scan_time", "files_scanned", "time_taken", "errors")


def _rule_id(detector: str) -> str:
    return "dspm/" + "".join(c if c.isalnum() else "-" for c in detector.lower()).strip("-")


def _flatten(scan_output: Union[Dict[str, Any], List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Accepts a worker findings JSON (grouped per resource) or a flat findings list."""
    if isinstance(scan_output, list):
        return scan_output
    flat = []
    for group in scan_output.get("findings", []):
        for items in group.values():
            flat.extend(items)
    return flat


def findings_to_sarif(
    scan_output: Union[Dict[str, Any], List[Dict[str, Any]]],
    mask: bool = False,
) -> Dict[str, Any]:
    findings = _flatten(scan_output)
    metadata = scan_output if isinstance(scan_output, dict) else {}

    rules: List[Dict[str, Any]] = []
    rule_index: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        detector = f.get("detector", "Unknown")
        severity = str(f.get("severity", "Medium"))
        rid = _rule_id(detector)

        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append({
                "id": rid,
                "name": detector,
                "shortDescription": {"text": detector},
                "fullDescription": {"text": f"{detector} ({f.get('category', 'Sensitive Data')})"},
                "defaultConfiguration": {"level": SEVERITY_TO_LEVEL.get(severity.lower(), "warning")},
                "properties": {"category": f.get("category", ""), "severity": severity},
            })

        value = f.get("value", "")
        if mask:
            value = mask_value(value)
        location = f.get("location", "")
        resource = f.get("resource_id", "unknown")

        result = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": SEVERITY_TO_LEVEL.get(severity.lower(), "warning"),
            "message": {"text": f"{detector} detected at {location}: {value}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(resource).replace(" ", "%20")},
                },
                "logicalLocations": [{"fullyQualifiedName": location, "kind": "member"}],
            }],
            "properties": {k: f[k] for k in ("detector", "category", "severity", "aggregated", "occurrences", "column") if k in f},
        }
        results.append(result)

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "informationUri": TOOL_URI,
                "version": TOOL_VERSION,
                "rules": rules,
            },
        },
        "results": results,
    }
    run_properties = {k: metadata[k] for k in RUN_METADATA_KEYS if k in metadata}
    if run_properties:
        run["properties"] = run_properties

    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Convert DSPM findings JSON to SARIF 2.1.0")
    parser.add_argument("input", help="Findings JSON (worker output or flat findings list)")
    parser.add_argument("output", help="Path for the SARIF file")
    parser.add_argument(
        "--mask", action="store_true",
        help="Mask finding values (recommended for findings produced before masking was enabled)",
    )
    args = parser.parse_args()

    with open(args.input) as fh:
        payload = json.load(fh)
    sarif = findings_to_sarif(payload, mask=args.mask)
    with open(args.output, "w") as fh:
        json.dump(sarif, fh, indent=2, default=str)
    print(
        f"Wrote {len(sarif['runs'][0]['results'])} results "
        f"({len(sarif['runs'][0]['tool']['driver']['rules'])} rules) to {args.output}",
    )
