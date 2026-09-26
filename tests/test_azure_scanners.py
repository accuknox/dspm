"""
Azure connector tests: Blob / ADLS Gen2 listing, skip rules, download and resource ids
(never carrying a SAS token), credential precedence, and Cosmos DB for NoSQL item
streaming. Clients are injected fakes; nothing talks to Azure.
"""
import os
import tempfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.engine.detector import DetectionEngine
from src.scanners.azure import common
from src.scanners.azure.blob import AzureBlobScanner
from src.scanners.azure.cosmos import CosmosNoSQLScanner
from src.scanners.base import resource_path

SAMPLE_TEXT = b"Admin password: SecretPassword123!\nUser email: john.doe@accuknox.com\n"
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
_STORAGE_ENV = (
    "AZURE_STORAGE_CONNECTION_STRING", "AZURE_STORAGE_SAS_TOKEN", "AZURE_STORAGE_ACCOUNT_KEY",
    "AZURE_STORAGE_ACCOUNT", "AZURE_STORAGE_ENDPOINT_SUFFIX",
)


def _blob(name, size=len(SAMPLE_TEXT), **overrides):
    """A BlobProperties stand-in with the attributes the skip rules read."""
    props = {
        "name": name, "size": size, "metadata": {}, "blob_type": "BlockBlob", "blob_tier": "Hot",
        "archive_status": None, "deleted": False, "last_modified": NOW,
    }
    props.update(overrides)
    return SimpleNamespace(**props)


def _fake_service(blobs, content=SAMPLE_TEXT, download_error=None):
    """A BlobServiceClient stand-in: one container whose blobs download `content`."""
    service = MagicMock()
    # a real client repeats its SAS token in .url; resource ids must never carry it
    service.url = "https://acct.blob.core.windows.net/?sv=2024-01-01&sig=SHOULDNOTLEAK"
    service.blob_clients = []
    container = service.get_container_client.return_value
    container.list_blobs.return_value = blobs

    def get_blob_client(name, **kwargs):
        client = MagicMock(name=name)
        if download_error:
            client.download_blob.side_effect = download_error
        else:
            client.download_blob.return_value.readinto.side_effect = lambda fh: fh.write(content)
        service.blob_clients.append(client)
        return client

    container.get_blob_client.side_effect = get_blob_client
    return service, container


def test_blob_scanner_lists_skips_and_scans():
    blobs = [
        _blob("exports/data.txt"),
        _blob("exports/", size=0, metadata={"hdi_isfolder": "true"}),   # ADLS Gen2 directory placeholder
        _blob("cold.csv", blob_tier="Archive"),                         # needs rehydration first
        _blob("disk.vhd", blob_type="PageBlob"),                        # disk image
        _blob("huge.bin", size=200 * 1024 * 1024),
        _blob("old.txt", last_modified=NOW - timedelta(days=30)),       # unchanged since last scan
        _blob("empty.txt", size=0),
        _blob("gone.txt", deleted=True),
    ]
    service, container = _fake_service(blobs)
    scanner = AzureBlobScanner(DetectionEngine(), client=service)
    units = list(
        scanner.iter_scan({
            "account": "acct", "container": "uploads", "prefix": "exports/",
            "last_scan_time": (NOW - timedelta(days=1)).isoformat(),
        }),
    )

    assert [name for _, name, _ in units] == ["exports/data.txt"]
    resource_id, _, findings = units[0]
    assert resource_id == "https://acct.blob.core.windows.net/uploads/exports/data.txt"
    assert {f["detector"] for f in findings} == {"Password Pattern", "Email"}
    assert all(f["resource_id"] == resource_id for f in findings)
    assert container.list_blobs.call_args.kwargs == {"name_starts_with": "exports/", "include": ["metadata"]}
    assert service.blob_clients[0].download_blob.call_args.kwargs == {"max_concurrency": 2}
    assert scanner.stats == {"objects_scanned": 1, "objects_skipped": 7, "errors": 0}
    service.close.assert_not_called()  # injected clients stay owned by the caller


def test_blob_scanner_single_blob_with_version_and_snapshot():
    service, container = _fake_service([])
    scanner = AzureBlobScanner(DetectionEngine(), client=service)
    findings = scanner.scan({
        "account": "acct", "container": "uploads", "blob": "a.txt",
        "version_id": "v7", "snapshot": "2026-01-01T00:00:00.0000000Z",
    })
    assert {f["detector"] for f in findings} == {"Password Pattern", "Email"}
    container.list_blobs.assert_not_called()
    assert container.get_blob_client.call_args.args == ("a.txt",)
    assert container.get_blob_client.call_args.kwargs == {"snapshot": "2026-01-01T00:00:00.0000000Z"}
    assert service.blob_clients[0].download_blob.call_args.kwargs == {"max_concurrency": 2, "version_id": "v7"}


def test_blob_scanner_keeps_downloaded_files_under_the_mirrored_path():
    keep_root = tempfile.mkdtemp()
    service, _ = _fake_service([_blob("exports/data.txt")])
    scanner = AzureBlobScanner(DetectionEngine(), config={"keep_files_dir": keep_root}, client=service)
    list(scanner.iter_scan({"account": "acct", "container": "uploads"}))

    kept = os.path.join(keep_root, "azblob", "acct", "uploads", "exports", "data.txt")
    assert os.path.exists(kept)
    with open(kept, "rb") as fh:
        assert fh.read() == SAMPLE_TEXT
    assert resource_path("https://acct.blob.core.windows.net/uploads/exports/data.txt") == os.path.join(
        "azblob", "acct", "uploads", "exports", "data.txt",
    )
    assert resource_path("https://acct.blob.core.usgovcloudapi.net/c/k.csv") == os.path.join("azblob", "acct", "c", "k.csv")


def test_blob_scanner_records_failures_without_leaking_credentials():
    error = RuntimeError("GET https://acct.blob.core.windows.net/uploads/a.txt?sv=2024&sig=abc123 failed; AccountKey=k9J2x7")
    service, _ = _fake_service([_blob("a.txt"), _blob("b.txt")], download_error=error)
    scanner = AzureBlobScanner(DetectionEngine(), client=service)
    assert list(scanner.iter_scan({"account": "acct", "container": "uploads"})) == []  # a failed blob never looks clean
    assert scanner.stats["errors"] == 2 and scanner.stats["objects_scanned"] == 0
    detail = scanner.stats["error_details"][0]
    assert detail.startswith("https://acct.blob.core.windows.net/uploads/a.txt: ")
    assert "abc123" not in detail and "k9J2x7" not in detail and "<redacted>" in detail

    # a listing failure (missing role, firewall) is one "connect" error
    service, container = _fake_service([])
    container.list_blobs.side_effect = RuntimeError("403 AuthorizationPermissionMismatch")
    scanner = AzureBlobScanner(DetectionEngine(), client=service)
    assert list(scanner.iter_scan({"account": "acct", "container": "uploads"})) == []
    assert scanner.stats["error_details"] == ["connect: 403 AuthorizationPermissionMismatch"]

    # a missing container is a configuration error, raised to the caller
    try:
        list(scanner.iter_scan({"account": "acct"}))
        assert False, "expected AzureConfigError"
    except common.AzureConfigError as e:
        assert "container" in str(e)


def test_blob_client_credential_precedence():
    with patch.object(common, "BlobServiceClient") as client_cls, \
            patch.object(common, "default_credential") as default_cred, \
            patch.dict(os.environ, {}, clear=False):
        for var in _STORAGE_ENV:  # a developer shell may carry these; patch.dict restores them
            os.environ.pop(var, None)

        common.blob_service_client({"connection_string": "UseDevelopmentStorage=true"}, {})
        client_cls.from_connection_string.assert_called_once_with("UseDevelopmentStorage=true")

        common.blob_service_client({"account": "acct", "sas_token": "?sv=2024-01-01&sig=abc"}, {})
        assert client_cls.call_args.args == ("https://acct.blob.core.windows.net",)
        assert client_cls.call_args.kwargs == {"credential": "sv=2024-01-01&sig=abc"}

        common.blob_service_client({"account": "acct", "account_key": "k", "endpoint_suffix": "core.usgovcloudapi.net"}, {})
        assert client_cls.call_args.args == ("https://acct.blob.core.usgovcloudapi.net",)
        assert client_cls.call_args.kwargs == {"credential": {"account_name": "acct", "account_key": "k"}}

        common.blob_service_client({}, {"account": "https://acct.blob.core.windows.net"})
        assert client_cls.call_args.kwargs == {"credential": default_cred.return_value}
        default_cred.assert_called_once()

        os.environ["AZURE_STORAGE_ACCOUNT"] = "envacct"
        common.blob_service_client({}, {})
        assert client_cls.call_args.args == ("https://envacct.blob.core.windows.net",)
        os.environ.pop("AZURE_STORAGE_ACCOUNT")

        try:
            common.blob_service_client({}, {})
            assert False, "expected AzureConfigError"
        except common.AzureConfigError as e:
            assert "AZURE_STORAGE_ACCOUNT" in str(e) and "key" not in str(e).lower()


def test_azure_helpers():
    assert common.account_url("acct") == "https://acct.blob.core.windows.net"
    assert common.account_url("acct", "core.chinacloudapi.cn") == "https://acct.blob.core.chinacloudapi.cn"
    assert common.account_url("http://127.0.0.1:10000/devstoreaccount1/") == "http://127.0.0.1:10000/devstoreaccount1"
    assert common.account_name("https://acct.blob.core.windows.net") == "acct"
    assert common.account_name("http://127.0.0.1:10000/devstoreaccount1") == "devstoreaccount1"
    assert common.strip_query("https://acct.blob.core.windows.net/?sig=x") == "https://acct.blob.core.windows.net"
    assert common.redact("sig=abc&se=2026 AccountKey=zzz; SharedAccessSignature=qqq") == (
        "sig=<redacted>&se=2026 AccountKey=<redacted>; SharedAccessSignature=<redacted>"
    )
    assert common.parse_timestamp("2026-08-01T00:00:00Z") == datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert common.parse_timestamp(datetime(2026, 8, 1)) == datetime(2026, 8, 1, tzinfo=timezone.utc)
    assert common.parse_timestamp("not a date") is None and common.parse_timestamp(None) is None
    assert common.cosmos_endpoint("myacct") == "https://myacct.documents.azure.com:443/"
    assert common.cosmos_endpoint("https://localhost:8081") == "https://localhost:8081/"
    assert common.display_endpoint("https://myacct.documents.azure.com:443/") == "https://myacct.documents.azure.com"
    assert common.display_endpoint("https://localhost:8081/") == "https://localhost:8081"


def _fake_cosmos(items_by_container):
    """A CosmosClient stand-in: databases -> containers -> the items query_items returns."""
    client = MagicMock()
    client.list_databases.return_value = [{"id": name} for name in items_by_container]
    containers = {}

    def get_database_client(db_name):
        database = MagicMock()
        database.list_containers.return_value = [{"id": name} for name in items_by_container.get(db_name, {})]

        def get_container_client(container_name):
            container = MagicMock()
            container.query_items.return_value = items_by_container[db_name][container_name]
            containers[(db_name, container_name)] = container
            return container

        database.get_container_client.side_effect = get_container_client
        return database

    client.get_database_client.side_effect = get_database_client
    return client, containers


def test_cosmos_scanner_streams_items_and_strips_system_properties():
    items = [
        {
            "id": "u1", "_rid": "AAAA==", "_self": "dbs/x/colls/y/docs/z/", "_etag": '"00"', "_attachments": "attachments/",
            "_ts": 1_700_000_000, "email": "carol.smith@yahoo.com", "profile": {"work_email": "carol@zoho.com"},
            "api_key": "sk_live_abcdef1234567890",  # pragma: allowlist secret
        },
        {"id": "u2", "_ts": 1_700_000_001, "status": "ok"},
    ]
    client, containers = _fake_cosmos({"appdb": {"users": items, "audit": [{"id": "e1", "_ts": 1, "status": "ok"}]}, "empty": {}})
    scanner = CosmosNoSQLScanner(DetectionEngine(), client=client)
    units = list(scanner.iter_scan({"account": "myacct"}))

    assert [name for _, name, _ in units] == ["appdb.users", "appdb.audit"]
    resource_id, _, findings = units[0]
    assert resource_id == "https://myacct.documents.azure.com/appdb/users"
    detectors = {f["detector"] for f in findings}
    assert "Email" in detectors and "API Key" in detectors
    assert any("Field 'profile.work_email'" in f["location"] for f in findings)
    assert all("Document id=u1" in f["location"] for f in findings)
    assert not any("_rid" in f["location"] or "_self" in f["location"] for f in findings)
    assert units[1][2] == []
    assert scanner.stats == {"containers_scanned": 2, "documents_scanned": 3, "errors": 0}
    assert containers[("appdb", "users")].query_items.call_args.kwargs == {
        "query": "SELECT TOP @limit * FROM c",
        "parameters": [{"name": "@limit", "value": 10000}],
        "enable_cross_partition_query": True,
        "max_item_count": 1000,
    }

    # pinned database + container, incremental on _ts, smaller pages
    scanner = CosmosNoSQLScanner(DetectionEngine(), config={"chunk_size": 100}, client=client)
    units = list(
        scanner.iter_scan({
            "endpoint": "https://myacct.documents.azure.com:443/", "database": "appdb", "container": "users",
            "sample_limit": 50, "last_scan_time": "2026-08-01T00:00:00Z",
        }),
    )
    assert [name for _, name, _ in units] == ["users"]
    kwargs = containers[("appdb", "users")].query_items.call_args.kwargs
    assert kwargs["query"] == "SELECT TOP @limit * FROM c WHERE c._ts > @since"
    assert kwargs["parameters"] == [
        {"name": "@limit", "value": 50},
        {"name": "@since", "value": int(datetime(2026, 8, 1, tzinfo=timezone.utc).timestamp())},
    ]
    assert kwargs["max_item_count"] == 100


def test_cosmos_scanner_reports_listing_failures():
    client, _ = _fake_cosmos({"appdb": {}})
    client.get_database_client.side_effect = None
    client.get_database_client.return_value.list_containers.side_effect = RuntimeError("403 Request blocked by Auth")
    scanner = CosmosNoSQLScanner(DetectionEngine(), client=client)
    assert list(scanner.iter_scan({"account": "myacct", "database": "appdb"})) == []
    assert scanner.stats["error_details"] == ["database appdb: 403 Request blocked by Auth"]

    client.list_databases.side_effect = RuntimeError("Unauthorized")
    scanner = CosmosNoSQLScanner(DetectionEngine(), client=client)
    assert list(scanner.iter_scan({"account": "myacct"})) == []
    assert scanner.stats["error_details"] == ["connect: Unauthorized"]
