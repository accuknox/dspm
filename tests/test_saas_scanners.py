"""SaaS connectors (Google Drive, Salesforce) against fake authorized sessions."""
from src.engine.detector import DetectionEngine
from src.scanners.saas.gdrive import GoogleDriveScanner
from src.scanners.saas.salesforce import SalesforceScanner


class _FakeResponse:
    def __init__(self, json_data=None, content=b"", status_code=200):
        self._json = json_data
        self.content = content
        self.status_code = status_code
        self.text = ""

    def json(self):
        return self._json


class _FakeDriveSession:
    """Drive v3: one listing page, one text file, one Slides export, one folder."""

    def __init__(self):
        self.requests = []

    def get(self, url, params=None, timeout=None):
        self.requests.append((url, params))
        params = params or {}
        if url.endswith("/files"):
            return _FakeResponse(
                json_data={
                    "files": [
                        {"id": "f1", "name": "notes.txt", "mimeType": "text/plain", "size": "120"},
                        {"id": "f2", "name": "Quarterly deck", "mimeType": "application/vnd.google-apps.presentation"},
                        {"id": "f3", "name": "stuff", "mimeType": "application/vnd.google-apps.folder"},
                        {"id": "f4", "name": "huge.bin", "mimeType": "application/octet-stream", "size": str(200 * 1024 * 1024)},
                    ],
                },
            )
        if url.endswith("/files/f1"):
            assert params.get("alt") == "media"
            return _FakeResponse(content=b"Contact: john.doe@accuknox.com\npassword = SuperSecret123!\n")
        if url.endswith("/files/f2/export"):
            assert params.get("mimeType") == "text/plain"
            return _FakeResponse(content=b"Reach us at jane.roe@accuknox.com for the numbers.\n")
        raise AssertionError(f"unexpected Drive request: {url}")


def test_gdrive_scanner_scans_downloads_and_exports():
    engine = DetectionEngine()
    session = _FakeDriveSession()
    scanner = GoogleDriveScanner(engine, config={}, client=session)

    units = list(scanner.iter_scan({"impersonate_user": "someone@example.com"}))

    names = [name for _rid, name, _f in units]
    assert names == ["notes.txt", "Quarterly deck"]  # folder skipped, oversized file skipped
    assert scanner.stats["files_scanned"] == 2
    assert scanner.stats["errors"] == 0

    by_name = {name: findings for _rid, name, findings in units}
    detectors_txt = {f["detector"] for f in by_name["notes.txt"]}
    assert "Email" in detectors_txt
    assert "Password Pattern" in detectors_txt
    assert {f["detector"] for f in by_name["Quarterly deck"]} == {"Email"}
    assert all(f["resource_id"].startswith("gdrive://someone@example.com/") for f in by_name["notes.txt"])

    # The listing asked for the impersonated user's corpus, never a shared drive
    _url, list_params = session.requests[0]
    assert list_params["corpora"] == "user"
    assert "trashed = false" in list_params["q"]


def test_gdrive_incremental_filter_in_listing_query():
    engine = DetectionEngine()
    session = _FakeDriveSession()
    scanner = GoogleDriveScanner(engine, config={}, client=session)
    list(scanner.iter_scan({"drive_id": "0AbC", "last_scan_time": "2026-08-01T00:00:00Z"}))
    _url, params = session.requests[0]
    assert params["corpora"] == "drive"
    assert params["driveId"] == "0AbC"
    assert "modifiedTime > '2026-08-01T00:00:00Z'" in params["q"]


class _FakeSalesforceSession:
    """REST API: describe global, describe Contact, SOQL queries, one file body."""

    def __init__(self):
        self.requests = []

    def get(self, url, params=None, timeout=None):
        self.requests.append((url, params))
        params = params or {}
        if url.endswith("/sobjects"):
            return _FakeResponse(
                json_data={
                    "sobjects": [
                        {"name": "Contact", "queryable": True},
                        {"name": "ContactShare", "queryable": True},   # excluded suffix
                        {"name": "ContactHistory", "queryable": True},  # excluded suffix
                        {"name": "ApexClass", "queryable": True},       # excluded prefix
                        {"name": "ContentVersion", "queryable": True},  # scanned as files, not records
                        {"name": "CaseComment", "queryable": False},    # not queryable
                    ],
                },
            )
        if url.endswith("/limits/recordCount"):
            return _FakeResponse(json_data={"sObjects": [{"name": "Contact", "count": 2}]})
        if url.endswith("/sobjects/Contact/describe"):
            return _FakeResponse(
                json_data={
                    "fields": [
                        {"name": "Email", "type": "email"},
                        {"name": "FirstName", "type": "string"},
                        {"name": "Phone", "type": "phone"},
                        {"name": "AnnualRevenue", "type": "currency"},  # not a text type
                        {"name": "SystemModstamp", "type": "datetime"},
                    ],
                },
            )
        if url.endswith("/query") and "FROM Contact" in (params.get("q") or ""):
            return _FakeResponse(
                json_data={
                    "done": True, "records": [
                        {"attributes": {}, "Id": "003A", "Email": "john.doe@accuknox.com", "FirstName": "John"},
                        {"attributes": {}, "Id": "003B", "Email": "jane.roe@accuknox.com", "FirstName": "Jane"},
                    ],
                },
            )
        if url.endswith("/query") and "FROM ContentVersion" in (params.get("q") or ""):
            return _FakeResponse(
                json_data={
                    "done": True, "records": [
                        {"attributes": {}, "Id": "068A", "Title": "creds", "FileExtension": "txt", "ContentSize": 60},
                    ],
                },
            )
        if url.endswith("/query") and "FROM Attachment" in (params.get("q") or ""):
            return _FakeResponse(json_data={"done": True, "records": []})
        if url.endswith("/sobjects/ContentVersion/068A/VersionData"):
            return _FakeResponse(content=b"password = SuperSecret123!\n")
        raise AssertionError(f"unexpected Salesforce request: {url} {params}")


def test_salesforce_scanner_records_and_files():
    engine = DetectionEngine()
    session = _FakeSalesforceSession()
    scanner = SalesforceScanner(engine, config={}, client=session)

    units = list(scanner.iter_scan({"instance_url": "https://acme.my.salesforce.com"}))
    names = [name for _rid, name, _f in units]
    assert names == ["Contact", "Files/creds.txt"]

    by_name = {name: findings for _rid, name, findings in units}
    assert "Email" in {f["detector"] for f in by_name["Contact"]}
    assert any("Field 'Email'" in f["location"] for f in by_name["Contact"])
    assert {f["detector"] for f in by_name["Files/creds.txt"]} >= {"Password Pattern"}

    assert scanner.stats["objects_scanned"] == 1
    assert scanner.stats["records_scanned"] == 2
    assert scanner.stats["files_scanned"] == 1
    assert scanner.stats["errors"] == 0

    # Excluded system objects were never described or queried
    urls = [u for u, _p in session.requests]
    assert not any("ContactShare" in u or "ContactHistory" in u or "ApexClass" in u for u in urls)
    # Only text-typed fields appear in the SOQL
    contact_query = next(p["q"] for u, p in session.requests if u.endswith("/query") and "FROM Contact" in (p or {}).get("q", ""))
    assert "AnnualRevenue" not in contact_query
    assert contact_query.startswith("SELECT Id, Email, FirstName, Phone FROM Contact")


def test_salesforce_incremental_and_pinned_objects():
    engine = DetectionEngine()
    session = _FakeSalesforceSession()
    scanner = SalesforceScanner(engine, config={}, client=session)

    units = list(
        scanner.iter_scan({
            "instance_url": "https://acme.my.salesforce.com",
            "objects": ["Contact"],
            "include_files": False,
            "last_scan_time": "2026-08-01T00:00:00Z",
            "sample_limit": 50,
        }),
    )
    assert [name for _rid, name, _f in units] == ["Contact"]

    contact_query = next(p["q"] for u, p in session.requests if u.endswith("/query"))
    assert "WHERE SystemModstamp > 2026-08-01T00:00:00Z" in contact_query
    assert contact_query.endswith("LIMIT 50")
    # Pinned objects skip global describe and recordCount entirely
    assert not any(u.endswith("/sobjects") or "recordCount" in u for u, _p in session.requests)
