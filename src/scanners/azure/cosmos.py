"""
CosmosNoSQLScanner: Azure Cosmos DB for NoSQL (the "Core" / SQL API).

Cosmos DB for MongoDB is served by MongoScanner through its connection string;
this connector covers accounts that speak the NoSQL API, where a database holds
containers and a container holds JSON items. Items stream as Records with
dotted field paths (src.pipeline.document_record), like MongoDB documents.

Reads: SELECT TOP @limit * FROM c across partitions, with c._ts > @since for
incremental scans (Cosmos stamps every item with _ts, epoch seconds). The
system properties _rid, _self, _etag, _attachments and _ts are dropped before
classification. The NoSQL API has no server-side random sample, so
sample_strategy "random" reads the head and says so in the log. The SDK
retries 429 (request rate too large) on its own.

Auth: the account key (target["key"] / AZURE_COSMOS_KEY; use the read-only key)
or the identity chain (src.utils.azure.default_credential) with the data-plane
role "Cosmos DB Built-in Data Reader" assigned to the scanner identity through
`az cosmosdb sql role assignment create`; the portal's IAM blade cannot grant
data-plane roles.

Resource id: https://<account>.documents.azure.com/<database>/<container>.
"""
import os
from typing import Any, Dict, Iterator, List, Tuple

try:
    from azure.cosmos import CosmosClient
except ImportError:
    CosmosClient = None

from src.pipeline.records import Record, document_record
from src.scanners.azure.common import cosmos_endpoint, display_endpoint, parse_timestamp, redact
from src.scanners.base import BaseScanner
from src.utils.azure import default_credential
from src.utils.logger import get_logger

logger = get_logger(__name__)

SYSTEM_PROPERTIES = {"_rid", "_self", "_etag", "_attachments", "_ts"}


class CosmosNoSQLScanner(BaseScanner):
    """Scans the containers of a Cosmos DB for NoSQL account for sensitive data."""

    def __init__(self, engine, config: Dict[str, Any] = None, client=None):
        super().__init__(engine, config, client)
        # client, when injected, is a CosmosClient (tests)
        self.stats = {"containers_scanned": 0, "documents_scanned": 0, "errors": 0}

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        return self.collect(target)

    def iter_scan(self, target: Dict[str, Any]) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        """
        Scans one container at a time, yielding (resource_id, container_name,
        findings) as each finishes. container_name is relative to the target:
        'users' when the target pins a database, 'appdb.users' otherwise.

        Target structure:
        {
            "endpoint": "https://myaccount.documents.azure.com:443/",  # or "account": "myaccount";
                                                                         # default AZURE_COSMOS_ENDPOINT
            "key": "...",                    # optional read-only key; omit for Entra RBAC (default AZURE_COSMOS_KEY)
            "database": "appdb",             # optional, every database when omitted
            "container": "users",            # optional, every container when omitted
            "last_scan_time": "2026-08-01T00:00:00Z",  # optional, only items with _ts after it
            "sample_limit": 10000            # optional, max items per container
        }
        """
        endpoint = cosmos_endpoint(
            target.get("endpoint") or target.get("account")
            or self.config.get("cosmos_endpoint") or os.environ.get("AZURE_COSMOS_ENDPOINT"),
        )
        base = display_endpoint(endpoint)
        client = self.client
        owns_client = client is None
        pinned_db = target.get("database")
        logger.info(f"Starting Cosmos DB scan for {base}")
        try:
            if owns_client:
                if CosmosClient is None:
                    self.record_error("connect: azure-cosmos is not installed")
                    logger.warning("azure-cosmos is not installed. Skipping Cosmos DB scan.")
                    return
                key = target.get("key") or self.config.get("cosmos_key") or os.environ.get("AZURE_COSMOS_KEY")
                client = CosmosClient(endpoint, credential=key or default_credential())

            db_names = [pinned_db] if pinned_db else [d["id"] for d in client.list_databases()]
            for db_name in db_names:
                database = client.get_database_client(db_name)
                try:
                    if target.get("container"):
                        container_names = [target["container"]]
                    else:
                        container_names = [c["id"] for c in database.list_containers()]
                except Exception as e:
                    self.record_error(f"database {db_name}: {redact(e)[:200]}")
                    logger.error(f"Failed to list containers for database '{db_name}': {redact(e)}")
                    continue

                for container_name in container_names:
                    resource_id = f"{base}/{db_name}/{container_name}"
                    findings = self._scan_container(
                        database.get_container_client(container_name), resource_id, db_name, container_name, target,
                    )
                    yield (
                        resource_id,
                        container_name if pinned_db else f"{db_name}.{container_name}",
                        self.dedup_findings(findings),
                    )
        except Exception as e:
            self.record_error(f"connect: {redact(e)[:200]}")
            logger.error(f"Error scanning Cosmos DB {base}: {redact(e)}")
        finally:
            if owns_client and client is not None:
                close = getattr(client, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass

    def _scan_container(
        self, container: Any, resource_id: str, db_name: str, container_name: str, target: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        logger.info(f"Scanning container {db_name}.{container_name}")
        sample_limit = int(target.get("sample_limit", 10000) or 10000)
        query = "SELECT TOP @limit * FROM c"
        parameters: List[Dict[str, Any]] = [{"name": "@limit", "value": sample_limit}]
        since = parse_timestamp(target.get("last_scan_time") or self.config.get("last_scan_time"))
        if since:
            query += " WHERE c._ts > @since"
            parameters.append({"name": "@since", "value": int(since.timestamp())})
        strategy = str(target.get("sample_strategy") or self.config.get("sample_strategy") or "head").lower()
        if strategy == "random":
            logger.info(f"Cosmos DB for NoSQL has no server-side random sample; reading the head of {container_name}")
        page_size = int(self.config.get("chunk_size", 1000))
        if self.config.get("log_queries"):
            logger.info(f"Executing query on {db_name}.{container_name}: {query} {parameters}")

        def documents() -> Iterator[Record]:
            count = 0
            try:
                items = container.query_items(
                    query=query, parameters=parameters, enable_cross_partition_query=True, max_item_count=page_size,
                )
                for idx, item in enumerate(items):
                    if isinstance(item, dict):
                        doc = {k: v for k, v in item.items() if k not in SYSTEM_PROPERTIES}
                        doc_id = item.get("id", f"index {idx}")
                    else:
                        doc, doc_id = item, f"index {idx}"
                    # The dotted field path is context for the engine, never part of the scanned text
                    yield document_record(
                        doc,
                        lambda path, d=doc_id: (
                            f"Database '{db_name}', Container '{container_name}', Document id={d}, Field '{path}'"
                        ),
                    )
                    count += 1
            finally:
                self.stats["documents_scanned"] += count

        errors_before = self.stats["errors"]
        findings = self.classify(
            resource_id, documents(),
            location_fn=lambda field, n: f"Database '{db_name}', Container '{container_name}', Field '{field}' ({n} matches)",
            unit_name=container_name,
        )
        if self.stats["errors"] == errors_before:
            self.stats["containers_scanned"] += 1
        return findings
