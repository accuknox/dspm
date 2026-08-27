#!/usr/bin/env python3
"""
Run this only inside your own trusted environment.

It connects to a MySQL or MariaDB database, scans for PII, PHI, and secrets,
and writes unredacted JSON or SARIF to a local file. It never sends data to a
remote service.

Install dependency:
  python3 -m pip install pymysql

Example:
  MYSQL_URI='mysql://user:password@host:3306/database' \
    python3 mysql_dspm_unredacted_exporter.py --format json --out findings.raw.json
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
from urllib.parse import urlparse, unquote

RULES = {
    "PII.EmailAddress": {"category": "PII", "dataClass": "EmailAddress", "level": "warning"},
    "PII.IPAddress": {"category": "PII", "dataClass": "IPAddress", "level": "warning"},
    "PII.PersonName": {"category": "PII", "dataClass": "PersonName", "level": "note"},
    "PII.UserIdentifier": {"category": "PII", "dataClass": "UserIdentifier", "level": "note"},
    "Secret.PasswordHash": {"category": "Secret", "dataClass": "PasswordHash", "level": "error"},
    "Secret.ActivationOrAuthKey": {"category": "Secret", "dataClass": "AuthKey", "level": "error"},
    "Secret.TokenLikeValue": {"category": "Secret", "dataClass": "Token", "level": "warning"},
    "PHI.HealthData": {"category": "PHI", "dataClass": "HealthData", "level": "warning"},
}

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
TOKEN_RE = re.compile(r"(?i)\b(?:[a-f0-9]{32,}|[A-Za-z0-9_=-]{40,})\b")
PHI_RE = re.compile(r"(?i)\b(patient|diagnosis|medication|prescription|medical|health|doctor|clinic|hospital|disease|treatment|insurance|mrn)\b")

COLUMN_RULES = [
    (re.compile(r"(?i)(email|e-mail)"), "PII.EmailAddress"),
    (re.compile(r"(?i)(^ip$|_ip$|ip_address|address_ip)"), "PII.IPAddress"),
    (re.compile(r"(?i)(^comment_author$|display_name|user_nicename|first_name|last_name|full_name|nickname)"), "PII.PersonName"),
    (re.compile(r"(?i)(user_login|username|^user_id$|userid|account_id)"), "PII.UserIdentifier"),
    (re.compile(r"(?i)(user_pass|post_password|password|pwd|credential)"), "Secret.PasswordHash"),
    (re.compile(r"(?i)(activation_key|auth_token|auth_key|secret|access_token|refresh_token|session_token|session_tokens|nonce|cookie|salt)"), "Secret.ActivationOrAuthKey"),
    (PHI_RE, "PHI.HealthData"),
]

META_SECRET_KEY_RE = re.compile(r"(?i)(password|secret|token|session|nonce|auth|activation|cookie|salt|key)")
META_NAME_KEY_RE = re.compile(r"(?i)(first_name|last_name|nickname|display_name|name)")
META_EMAIL_KEY_RE = re.compile(r"(?i)(email|e-mail)")


def parse_mysql_uri(uri):
    parsed = urlparse(uri)
    if parsed.scheme not in ("mysql", "mariadb"):
        raise ValueError("URI must start with mysql:// or mariadb://")
    return {
        "host": parsed.hostname,
        "port": parsed.port or 3306,
        "user": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "database": (parsed.path or "/").lstrip("/"),
    }


def column_rules(column):
    return [rule_id for regex, rule_id in COLUMN_RULES if regex.search(column)]


def value_rules(value):
    if value is None:
        return []
    text = str(value)
    rules = []
    if EMAIL_RE.search(text):
        rules.append("PII.EmailAddress")
    if IP_RE.search(text):
        rules.append("PII.IPAddress")
    if TOKEN_RE.search(text):
        rules.append("Secret.TokenLikeValue")
    if PHI_RE.search(text):
        rules.append("PHI.HealthData")
    return rules


def json_safe(value):
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return value


def scan(uri, row_limit=None):
    import pymysql

    cfg = parse_mysql_uri(uri)
    conn = pymysql.connect(
        connect_timeout=10,
        read_timeout=60,
        cursorclass=pymysql.cursors.DictCursor,
        **cfg,
    )
    findings = []
    tables = {}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION() AS version")
            mysql_version = cur.fetchone()["version"]
            cur.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema=%s ORDER BY table_name",
                (cfg["database"],),
            )
            table_names = [row["table_name"] for row in cur.fetchall()]
            for table in table_names:
                safe_table = table.replace("`", "``")
                cur.execute(
                    "SELECT column_name, column_key FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position",
                    (cfg["database"], table),
                )
                cols_meta = cur.fetchall()
                pk_cols = [c["column_name"] for c in cols_meta if c["column_key"] == "PRI"]
                cur.execute(f"SELECT COUNT(*) AS c FROM `{safe_table}`")
                count = int(cur.fetchone()["c"])
                tables[table] = {"rows": count, "columns": [c["column_name"] for c in cols_meta]}
                limit_sql = "" if row_limit is None else f" LIMIT {int(row_limit)}"
                cur.execute(f"SELECT * FROM `{safe_table}`{limit_sql}")
                for row_index, row in enumerate(cur.fetchall(), start=1):
                    pk = {k: json_safe(row.get(k)) for k in pk_cols} if pk_cols else {"row_index": row_index}
                    kv_name = str(row.get("meta_key") or row.get("option_name") or "")
                    kv_value_col = "meta_value" if "meta_value" in row else "option_value" if "option_value" in row else None
                    derived = {}
                    if kv_value_col and row.get(kv_value_col) not in (None, ""):
                        if META_SECRET_KEY_RE.search(kv_name):
                            derived.setdefault(kv_value_col, set()).add("Secret.ActivationOrAuthKey")
                        if META_EMAIL_KEY_RE.search(kv_name) or EMAIL_RE.search(str(row.get(kv_value_col))):
                            derived.setdefault(kv_value_col, set()).add("PII.EmailAddress")
                        if META_NAME_KEY_RE.search(kv_name):
                            derived.setdefault(kv_value_col, set()).add("PII.PersonName")
                    for column, value in row.items():
                        if value in (None, ""):
                            continue
                        matched = set(column_rules(column)) | set(value_rules(value)) | derived.get(column, set())
                        for rule_id in sorted(matched):
                            rule = RULES[rule_id]
                            findings.append({
                                "ruleId": rule_id,
                                "category": rule["category"],
                                "dataClass": rule["dataClass"],
                                "severity": rule["level"],
                                "database": cfg["database"],
                                "table": table,
                                "column": column,
                                "primaryKey": pk,
                                "value": json_safe(value),
                            })
        return {
            "scanner": "dspm-mysql-unredacted-local-exporter",
            "scannedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "host": cfg["host"],
            "port": cfg["port"],
            "database": cfg["database"],
            "mysqlVersion": mysql_version,
            "tables": tables,
            "findings": findings,
        }
    finally:
        conn.close()


def to_sarif(raw):
    rules = []
    for rule_id, meta in RULES.items():
        rules.append({
            "id": rule_id,
            "name": meta["dataClass"],
            "shortDescription": {"text": f"{meta['dataClass']} detected"},
            "defaultConfiguration": {"level": meta["level"]},
            "properties": {"category": meta["category"], "dataClass": meta["dataClass"]},
        })
    results = []
    for f in raw["findings"]:
        pk_text = ",".join(f"{k}={v}" for k, v in f["primaryKey"].items())
        uri = f"mysql://{raw['host']}:{raw['port']}/{raw['database']}/{f['table']}#{pk_text}.{f['column']}"
        fp = hashlib.sha256(f"{f['ruleId']}|{f['table']}|{f['column']}|{pk_text}".encode()).hexdigest()
        results.append({
            "ruleId": f["ruleId"],
            "level": f["severity"],
            "message": {"text": f"{f['dataClass']} found in {f['table']}.{f['column']}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"snippet": {"text": str(f["value"])}}
                },
                "logicalLocations": [{"name": f"{f['table']}.{f['column']}", "kind": "field"}],
            }],
            "partialFingerprints": {"primaryLocationLineHash": fp},
            "properties": f,
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "dspm-mysql-unredacted-local-exporter", "rules": rules}},
            "invocations": [{"executionSuccessful": True, "endTimeUtc": raw["scannedAtUtc"]}],
            "results": results,
            "properties": {k: raw[k] for k in ("host", "port", "database", "mysqlVersion")},
        }],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--uri", default=os.environ.get("MYSQL_URI"), help="mysql://user:password@host:3306/database")
    parser.add_argument("--out", required=True, help="Output file path")
    parser.add_argument("--format", choices=["json", "sarif"], default="json")
    parser.add_argument("--row-limit", type=int, default=None, help="Optional per-table row limit for test runs")
    args = parser.parse_args()
    if not args.uri:
        parser.error("Pass --uri or set MYSQL_URI")

    raw = scan(args.uri, args.row_limit)
    output = raw if args.format == "json" else to_sarif(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)
    print(json.dumps({
        "out": args.out,
        "format": args.format,
        "tables": len(raw["tables"]),
        "rowsDeclared": sum(t["rows"] for t in raw["tables"].values()),
        "findings": len(raw["findings"]),
        "containsUnredactedValues": True,
    }, indent=2))


if __name__ == "__main__":
    main()
