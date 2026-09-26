"""
Worker handler tests: the findings JSON must have the same layout whether the
target is an S3 bucket or a database, and failures must surface the same way.
Settings are patched so a developer .env never points the tests at real endpoints.
"""
import json
import os
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import settings
import src.dspm_scanner_worker_handler as handler

_NEUTRAL_SETTINGS = {
    "DB_URI": None, "DB_HOST": None, "DB_PORT": None, "DB_USERNAME": None, "DB_PASSWORD": None,
    "CSPM_URL": None, "ARTIFACT_TOKEN": None, "LABEL_ID": "test", "AWS_ACCOUNT_ID": None,
    "AWS_ACCESS_KEY_ID": None, "AWS_SECRET_ACCESS_KEY": None, "OBJECT_REGION": None,
    "OBJECTS_TO_SCAN": None, "OBJECT_NAME": None, "OBJECT_TYPE": None, "NER_ENABLED": False, "SAMPLE_STRATEGY": "head",
    "DISABLED_DETECTORS": [], "ALLOW_LIST": [], "ALLOW_REGEX": [], "COLUMN_RATIO": None, "MIN_COUNT": None,
    "AGGREGATION_THRESHOLD": 25, "SAMPLE_LIMIT": 10000, "REPORT_PRIVATE_IPS": False, "REPORT_TOKEN_LIKE_VALUES": False,
    "MIN_CONFIDENCE": "likely", "ADAPTIVE_SAMPLING": False, "KEEP_SCANNED_FILES": False,
    "AZURE_SUBSCRIPTION_ID": None, "AZURE_STORAGE_ACCOUNT": None, "AZURE_STORAGE_ENDPOINT_SUFFIX": None,
    "AZURE_STORAGE_CONNECTION_STRING": None, "AZURE_STORAGE_SAS_TOKEN": None, "AZURE_STORAGE_ACCOUNT_KEY": None,
    "AZURE_COSMOS_ENDPOINT": None, "AZURE_COSMOS_KEY": None, "DB_AUTH": "password",
}


def _isolated(**overrides):
    """Context stack: neutral settings (+overrides), temp FINDINGS_DIR, sqlite engine alias."""
    stack = ExitStack()
    for key, value in {**_NEUTRAL_SETTINGS, **overrides}.items():
        stack.enter_context(patch.object(settings, key, value))
    findings_dir = Path(tempfile.mkdtemp()) / "findings"
    stack.enter_context(patch.object(handler, "FINDINGS_DIR", findings_dir))
    stack.enter_context(patch.dict(handler.DB_OBJECT_TYPES, {"SQLITE": "sqlite"}))
    return stack, findings_dir


def _create_sqlite_db():
    from sqlalchemy import create_engine, text

    db_path = os.path.join(tempfile.mkdtemp(), "worker.db")
    conn_str = f"sqlite:///{db_path}"
    sa_engine = create_engine(conn_str)
    with sa_engine.begin() as conn:
        conn.execute(text("CREATE TABLE users (id INTEGER, email TEXT, password TEXT)"))
        conn.execute(text("INSERT INTO users VALUES (1, 'john.doe@accuknox.com', 'SuperSecret123!')"))
        conn.execute(text("CREATE TABLE settings (id INTEGER, flag TEXT)"))
        conn.execute(text("INSERT INTO settings VALUES (1, 'on')"))
    sa_engine.dispose()
    return conn_str


def _read_findings(findings_dir, name):
    files = list(findings_dir.glob(f"{name}-*.json"))
    assert len(files) == 1, files
    return json.loads(files[0].read_text())


def _fake_object_store_scanner(files, scan_side_effect, errors=0, resource_id_fn=None):
    """A stand-in S3Scanner / AzureBlobScanner: iter_scan yields (resource_id, key, findings) per listed object."""
    scanner = MagicMock()
    scanner.stats = {"objects_scanned": len(files), "objects_skipped": 0, "errors": errors}
    resource_id_fn = resource_id_fn or (lambda target, key: f"arn:aws:s3:::{target['bucket']}/{key}")

    def iter_scan(target):
        for file in files:
            key = file["Key"]
            object_target = {**target, "key": key, "version_id": file.get("VersionId"), "last_modified": file.get("LastModified")}
            yield resource_id_fn(target, key), key, scan_side_effect(object_target)

    scanner.iter_scan.side_effect = iter_scan
    return scanner


_fake_s3_scanner = _fake_object_store_scanner


def test_worker_db_scan_layout():
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    conn_str = _create_sqlite_db()
    stack, findings_dir = _isolated(DB_URI=conn_str)
    with stack:
        result = handler.process_bucket("testdb", "SQLITE")
        doc = _read_findings(findings_dir, "testdb")

    assert result["status"] == "success" and result["errors"] == []
    assert result["files_scanned"] == 2
    # One entry per relation, schema-qualified, clean ones included with []
    assert set(doc["findings"]) == {"main.users", "main.settings"}
    assert doc["findings"]["main.settings"] == []
    clubbed = doc["findings"]["main.users"]
    assert {c["name"] for c in clubbed} == {"Email", "Password Pattern"}
    for entry in clubbed:
        assert set(entry) == {"name", "type", "confidence", "finding_values", "total_count"}
        assert entry["confidence"] in ("likely", "very_likely")
        assert entry["total_count"] == 1
    assert doc["object_name"] == "testdb" and doc["object_type"] == "SQLITE"
    assert doc["account_id"] is None and doc["errors"] == []
    assert not list(findings_dir.glob("*.zip"))


def test_worker_s3_scan_layout():
    def fake_scan(target):
        key = target["key"]
        rid = f"arn:aws:s3:::{target['bucket']}/{key}"
        if key.endswith(".xlsx"):
            return [{
                "resource_id": f"{rid} [Employees]", "detector": "Email", "category": "PII",
                "severity": "medium", "value": "e@corp.com", "location": "Sheet 'Employees', Row 0, Column 'Contact'",
            }]
        if key == "clean.txt":
            return []
        return [{
            "resource_id": rid, "detector": "Credit Card", "category": "Financial Data",
            "severity": "high", "value": "4111", "location": "Line 1, Column 1-19",
        }]

    # (empty and oversized objects are skipped by S3Scanner.iter_scan itself, see tests/test_scanners.py)
    files = [{"Key": "data.xlsx", "Size": 10}, {"Key": "clean.txt", "Size": 5}, {"Key": "cards.txt", "Size": 20}]
    scanner = _fake_s3_scanner(files, fake_scan)
    stack, findings_dir = _isolated(AWS_ACCOUNT_ID="123456789012")
    with stack, patch.object(handler.boto3, "client") as boto_client, patch.object(handler, "S3Scanner", return_value=scanner):
        result = handler.process_bucket("my-bucket", "s3", "ap-south-1")
        doc = _read_findings(findings_dir, "my-bucket")

    assert boto_client.call_args.kwargs["region_name"] == "ap-south-1"
    assert scanner.iter_scan.call_args.args[0] == {"bucket": "my-bucket"}
    assert result["status"] == "success" and result["files_scanned"] == 3
    # Same layout as the database case: one entry per scanned unit, clean ones with []
    assert set(doc["findings"]) == {"data.xlsx [Employees]", "clean.txt", "cards.txt"}
    assert doc["findings"]["clean.txt"] == []
    assert doc["findings"]["cards.txt"][0]["name"] == "Credit Card"
    assert doc["account_id"] == "123456789012"


def test_worker_scanner_errors_are_reported_for_both_connectors():
    # S3: per-object failures counted by the scanner become an error entry (status "error")
    scanner = _fake_s3_scanner([{"Key": "a.txt", "Size": 5}], lambda target: [], errors=2)
    stack, _ = _isolated(AWS_ACCOUNT_ID="123456789012")
    with stack, patch.object(handler.boto3, "client"), patch.object(handler, "S3Scanner", return_value=scanner):
        result = handler.process_bucket("bucket", "s3")
    assert result["status"] == "error"
    assert result["errors"] == ["2 error(s) during S3 scan, see logs"]

    # DB: an unreachable database is reported the same way
    stack, _ = _isolated(DB_URI="sqlite:////nonexistent-dir/none.db")
    with stack:
        result = handler.process_bucket("ghost", "SQLITE")
    assert result["status"] == "error"
    # the failing unit is named in the error so scan gaps are visible in the findings file
    assert len(result["errors"]) == 1
    assert result["errors"][0].startswith("1 error(s) during sqlite scan: connect:")

    # Either branch: an exception outside the scanner is captured, never raised
    stack, _ = _isolated()
    with stack, patch.object(handler, "SQLScanner", side_effect=RuntimeError("boom")):
        result = handler.process_bucket("db", "POSTGRES")
    assert result["errors"] == ["postgres scan failed: boom"]
    # ExitStack consumes its patches on exit; each scenario needs a fresh one.
    stack, _ = _isolated()
    with stack, patch.object(handler.boto3, "client", side_effect=RuntimeError("no creds")):
        result = handler.process_bucket("bucket", "S3")
    assert result["errors"] == ["S3 scan failed: no creds"]


def test_worker_upload_contract_and_retries():
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    conn_str = _create_sqlite_db()
    ok = MagicMock(status_code=200, text="created")
    stack, findings_dir = _isolated(DB_URI=conn_str, CSPM_URL="https://cspm.example.com/", ARTIFACT_TOKEN="tok", LABEL_ID="lbl")
    with stack, patch.object(handler.requests, "post", return_value=ok) as post:
        result = handler.process_bucket("testdb", "SQLITE")
    assert result["status"] == "success" and post.call_count == 1
    call = post.call_args.kwargs
    assert call["url"] == "https://cspm.example.com/api/v1/artifact/"
    assert call["params"] == {"data_type": "DSPM", "save_to_s3": "false", "label_id": "lbl"}
    assert call["headers"] == {"Authorization": "Bearer tok"}
    name, _, content_type = call["files"]["file"]
    assert name.startswith("testdb-") and name.endswith(".zip") and content_type == "application/zip"
    assert list(findings_dir.glob("testdb-*.json")) and not list(findings_dir.glob("*.zip"))

    down = MagicMock(status_code=503, text="down")
    stack, findings_dir = _isolated(DB_URI=conn_str, CSPM_URL="https://cspm.example.com/")
    with stack, patch.object(handler.requests, "post", return_value=down) as post, patch.object(handler.time, "sleep") as sleep:
        result = handler.process_bucket("testdb", "SQLITE")
    assert post.call_count == handler.UPLOAD_RETRIES
    assert [c.args[0] for c in sleep.call_args_list] == [2, 4]
    assert result["status"] == "error" and "upload to CSPM Backend failed" in result["errors"][0]
    assert list(findings_dir.glob("testdb-*.json")) and not list(findings_dir.glob("*.zip"))


def test_worker_target_parsing_and_guards():
    stack, _ = _isolated(OBJECTS_TO_SCAN='{"b1": "s3", "appdb": "postgres"}')
    with stack:
        assert handler.parse_objects_to_scan() == {"b1": "s3", "appdb": "postgres"}
    stack, _ = _isolated(OBJECTS_TO_SCAN='["b1", "b2"]', OBJECT_TYPE="S3")
    with stack:
        assert handler.parse_objects_to_scan() == {"b1": "S3", "b2": "S3"}
    stack, _ = _isolated(OBJECT_NAME="appdb", OBJECT_TYPE="POSTGRES")
    with stack:
        assert handler.parse_objects_to_scan() == {"appdb": "POSTGRES"}

    stack, _ = _isolated()
    with stack:
        response = handler.lambda_handler()
    assert response["statusCode"] == 200 and json.loads(response["body"])["message"] == "No objects to scan"

    # AWS_ACCOUNT_ID is only required when an S3 target is configured
    stack, _ = _isolated(OBJECT_NAME="b1", OBJECT_TYPE="s3")
    with stack:
        assert handler.lambda_handler()["statusCode"] == 400
    # AZURE_SUBSCRIPTION_ID likewise for Azure Blob targets
    stack, _ = _isolated(OBJECT_NAME="uploads", OBJECT_TYPE="AZURE_BLOB")
    with stack:
        assert handler.lambda_handler()["statusCode"] == 400
    stack, _ = _isolated(OBJECT_NAME="thing", OBJECT_TYPE="ORACLE")
    with stack:
        response = handler.lambda_handler()
    body = json.loads(response["body"])
    assert response["statusCode"] == 500 and body["status"] == "error"
    assert "Unsupported object type 'ORACLE'" in body["results"][0]["errors"][0]


def test_keep_scanned_files_reaches_the_scan_config():
    out_dir = Path(tempfile.mkdtemp())
    stack, _findings_dir = _isolated(KEEP_SCANNED_FILES=True)
    with stack, patch.object(handler, "OUTPUT_DIR", out_dir):
        assert handler.scan_config()["keep_files_dir"] == str(out_dir / "scanned")
    stack, _findings_dir = _isolated()
    with stack:
        assert "keep_files_dir" not in handler.scan_config()


def test_env_settings_reach_the_scan_config():
    import importlib
    import os

    env = {
        "DISABLED_DETECTORS": "PII.IPAddress, MAC_ADDRESS", "ALLOW_LIST": '["support@acme-corp.io", "+91 80 4000 0000"]',
        "ALLOW_REGEX": '["@partner-example$"]', "COLUMN_RATIO": "0.6", "MIN_COUNT": "8", "AGGREGATION_THRESHOLD": "40",
        "SAMPLE_LIMIT": "2500", "MIN_CONFIDENCE": "very_likely", "SAMPLE_STRATEGY": "random", "NER_ENABLED": "false",
        "REPORT_PRIVATE_IPS": "true", "ENABLED_REGIONS": "US,IN", "KEEP_SCANNED_FILES": "true",
    }
    with patch.dict(os.environ, env, clear=False):
        fresh = importlib.reload(settings)
    try:
        assert fresh.DISABLED_DETECTORS == ["PII.IPAddress", "MAC_ADDRESS"]
        assert fresh.ALLOW_LIST == ["support@acme-corp.io", "+91 80 4000 0000"] and fresh.ALLOW_REGEX == ["@partner-example$"]
        assert fresh.COLUMN_RATIO == 0.6 and fresh.MIN_COUNT == 8 and fresh.AGGREGATION_THRESHOLD == 40 and fresh.SAMPLE_LIMIT == 2500
        assert fresh.MIN_CONFIDENCE == "very_likely" and fresh.SAMPLE_STRATEGY == "random" and fresh.NER_ENABLED is False
        assert fresh.REPORT_PRIVATE_IPS is True and fresh.ENABLED_REGIONS == ["US", "IN"]
        assert fresh.KEEP_SCANNED_FILES is True
        config = handler.scan_config()
        assert config["disabled_detectors"] == ["PII.IPAddress", "MAC_ADDRESS"] and config["column_ratio"] == 0.6
        assert config["min_count"] == 8 and config["aggregation_threshold"] == 40 and config["min_confidence"] == "very_likely"
        assert config["sample_strategy"] == "random" and config["ner"] is False and config["report_private_ips"] is True
        assert config["keep_files_dir"] == str(handler.OUTPUT_DIR / "scanned")
    finally:
        with patch.dict(os.environ, {k: "" for k in env}, clear=False):
            importlib.reload(settings)
    # defaults come back once the variables are unset
    assert settings.DISABLED_DETECTORS == [] and settings.COLUMN_RATIO is None and settings.MIN_CONFIDENCE == "likely"


def test_worker_azure_blob_scan_layout():
    def fake_scan(target):
        key = target["key"]
        rid = f"https://acct.blob.core.windows.net/{target['container']}/{key}"
        if key.endswith(".xlsx"):
            return [{
                "resource_id": f"{rid} [Employees]", "detector": "Email", "category": "PII",
                "severity": "medium", "value": "e@corp.com", "location": "Sheet 'Employees', Row 0, Column 'Contact'",
            }]
        if key == "clean.txt":
            return []
        return [{
            "resource_id": rid, "detector": "Credit Card", "category": "Financial Data",
            "severity": "high", "value": "4111", "location": "Line 1, Column 1-19",
        }]

    files = [{"Key": "data.xlsx", "Size": 10}, {"Key": "clean.txt", "Size": 5}, {"Key": "cards.txt", "Size": 20}]
    scanner = _fake_object_store_scanner(
        files, fake_scan, resource_id_fn=lambda target, key: f"https://acct.blob.core.windows.net/{target['container']}/{key}",
    )
    stack, findings_dir = _isolated(
        AZURE_SUBSCRIPTION_ID="2f1c7e0a-0000-0000-0000-000000000000", AZURE_STORAGE_ACCOUNT="acct",
        AZURE_STORAGE_SAS_TOKEN="sv=1&sig=x",
    )
    with stack, patch.object(handler, "AzureBlobScanner", return_value=scanner):
        result = handler.process_bucket("uploads", "AZURE_BLOB")
        doc = _read_findings(findings_dir, "uploads")

    target = scanner.iter_scan.call_args.args[0]
    assert target["account"] == "acct" and target["container"] == "uploads" and target["sas_token"] == "sv=1&sig=x"
    assert result["status"] == "success" and result["files_scanned"] == 3
    # Same layout as the S3 case: one entry per scanned unit, per sheet for workbooks, clean ones with []
    assert set(doc["findings"]) == {"data.xlsx [Employees]", "clean.txt", "cards.txt"}
    assert doc["findings"]["clean.txt"] == [] and doc["findings"]["cards.txt"][0]["name"] == "Credit Card"
    assert doc["account_id"] == "2f1c7e0a-0000-0000-0000-000000000000" and doc["object_type"] == "AZURE_BLOB"

    # account/container names and container URLs override AZURE_STORAGE_ACCOUNT
    stack, findings_dir = _isolated(AZURE_SUBSCRIPTION_ID="sub", AZURE_STORAGE_ACCOUNT="acct")
    with stack, patch.object(handler, "AzureBlobScanner", return_value=scanner):
        handler.process_bucket("other/exports", "azure_blob")
        doc = _read_findings(findings_dir, "other_exports")
    target = scanner.iter_scan.call_args.args[0]
    assert (target["account"], target["container"]) == ("other", "exports") and doc["object_name"] == "other/exports"
    assert handler.split_azure_target("https://acct2.blob.core.windows.net/bucket") == ("https://acct2.blob.core.windows.net", "bucket")
    assert handler.split_azure_target("http://127.0.0.1:10000/devstoreaccount1/bucket") == ("http://127.0.0.1:10000/devstoreaccount1", "bucket")

    # scanner errors surface like the S3 ones, naming the failed blobs
    scanner.stats = {
        "objects_scanned": 0, "objects_skipped": 0, "errors": 1,
        "error_details": ["https://acct.blob.core.windows.net/uploads/a.txt: 403"],
    }
    stack, _ = _isolated(AZURE_SUBSCRIPTION_ID="sub", AZURE_STORAGE_ACCOUNT="acct")
    with stack, patch.object(handler, "AzureBlobScanner", return_value=scanner):
        result = handler.process_bucket("uploads", "AZURE_BLOB")
    assert result["errors"] == ["1 error(s) during Azure Blob scan: https://acct.blob.core.windows.net/uploads/a.txt: 403"]


def test_worker_cosmos_and_azure_database_aliases():
    # Cosmos DB for NoSQL: one entry per container, attributed to the subscription
    cosmos = MagicMock()
    cosmos.stats = {"containers_scanned": 2, "documents_scanned": 5, "errors": 0}
    cosmos.iter_scan.return_value = [
        (
            "https://acct.documents.azure.com/appdb/users", "users", [{
                "resource_id": "https://acct.documents.azure.com/appdb/users", "detector": "Email", "category": "PII",
                "severity": "medium", "value": "e@corp.com", "location": "Database 'appdb', Container 'users', Field 'email' (3 matches)",
            }],
        ),
        ("https://acct.documents.azure.com/appdb/audit", "audit", []),
    ]
    stack, findings_dir = _isolated(AZURE_SUBSCRIPTION_ID="sub", AZURE_COSMOS_ENDPOINT="acct", AZURE_COSMOS_KEY="k")
    with stack, patch.object(handler, "CosmosNoSQLScanner", return_value=cosmos):
        result = handler.process_bucket("appdb", "COSMOS_NOSQL")
        doc = _read_findings(findings_dir, "appdb")
    assert cosmos.iter_scan.call_args.args[0] == {"endpoint": "acct", "key": "k", "database": "appdb", "sample_limit": 10000}
    assert result["status"] == "success" and set(doc["findings"]) == {"users", "audit"}
    assert doc["findings"]["users"][0]["name"] == "Email" and doc["account_id"] == "sub"

    # Azure database aliases route to the existing SQL / Mongo connectors; DB_AUTH reaches the target
    sql = MagicMock()
    sql.stats = {"tables_scanned": 0, "rows_scanned": 0, "errors": 0}
    sql.iter_scan.return_value = []
    stack, _ = _isolated(
        DB_HOST="appdb.postgres.database.azure.com", DB_USERNAME="dspm-scanner-vm", DB_AUTH="azure_entra",
        AZURE_SUBSCRIPTION_ID="sub",
    )
    with stack, patch.object(handler, "SQLScanner", return_value=sql):
        result = handler.process_bucket("appdb", "AZURE_POSTGRES")
    target = sql.iter_scan.call_args.args[0]
    assert result["status"] == "success" and target["engine"] == "postgres" and target["auth"] == "azure_entra"
    assert target["host"] == "appdb.postgres.database.azure.com"

    mongo = MagicMock()
    mongo.stats = {"collections_scanned": 0, "documents_scanned": 0, "errors": 0}
    mongo.iter_scan.return_value = []
    stack, _ = _isolated(DB_URI="mongodb://acct:key@acct.mongo.cosmos.azure.com:10255/?ssl=true")
    with stack, patch.object(handler, "MongoScanner", return_value=mongo):
        handler.process_bucket("crm", "COSMOS_MONGO")
    target = mongo.iter_scan.call_args.args[0]
    assert target["uri"].startswith("mongodb://") and target["host"] == "acct.mongo.cosmos.azure.com" and "auth" not in target
