"""
Shared plumbing for the Azure connectors: the storage client factory, endpoint
building for the public cloud, sovereign clouds and Azurite, timestamp parsing
for incremental scans, and redaction so a SAS signature or account key never
reaches a log line, an error detail or a resource id.

Storage authentication, in the order tried:
  1. an injected client         tests, callers that manage their own session
  2. a connection string        target["connection_string"] / AZURE_STORAGE_CONNECTION_STRING
                                ("UseDevelopmentStorage=true" reaches a local Azurite)
  3. a SAS token                target["sas_token"] / AZURE_STORAGE_SAS_TOKEN: read + list only, when issued so
  4. an account key             target["account_key"] / AZURE_STORAGE_ACCOUNT_KEY: full access, discouraged
  5. the identity chain         src.utils.azure.default_credential(): service principal, AKS workload
                                identity, the VM's managed identity, `az login`. Needs the role
                                Storage Blob Data Reader on the account or its resource group.
"""
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from src.utils.azure import AzureConfigError, default_credential

try:
    from azure.storage.blob import BlobServiceClient
except ImportError:
    BlobServiceClient = None

DEFAULT_ENDPOINT_SUFFIX = "core.windows.net"
COSMOS_ENDPOINT_SUFFIX = "documents.azure.com"

_SAS_SIGNATURE = re.compile(r"(?i)(sig=)[^&\s\"'>]+")
_KEY_VALUE = re.compile(r"(?i)(AccountKey=|SharedAccessSignature=)[^;\s\"'>]+")


def redact(text: Any) -> str:
    """Masks SAS signatures and account keys in any text destined for logs or findings."""
    masked = _SAS_SIGNATURE.sub(r"\1<redacted>", str(text))
    return _KEY_VALUE.sub(r"\1<redacted>", masked)


def setting(target: Optional[Dict[str, Any]], config: Optional[Dict[str, Any]], key: str, env: str) -> Optional[str]:
    """The target, then the scan config, then the environment; empty strings count as unset."""
    for source in (target, config):
        value = source.get(key) if source else None
        if value not in (None, ""):
            return value
    return os.environ.get(env) or None


def parse_timestamp(value: Any) -> Optional[datetime]:
    """ISO 8601 string or datetime -> aware UTC datetime; None when unset or unparseable."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        stamp = value
    else:
        try:
            stamp = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc)


def account_url(account: Optional[str], suffix: Optional[str] = None, service: str = "blob") -> str:
    """
    https://<account>.<service>.<suffix> for an account name. An account given as a URL
    (Azurite's http://127.0.0.1:10000/devstoreaccount1, a sovereign-cloud endpoint) is
    used as given.
    """
    if not account:
        raise AzureConfigError(
            "Set AZURE_STORAGE_ACCOUNT (or target['account']) to the storage account name or its https:// URL",
        )
    account = str(account).strip()
    if "://" in account:
        return account.rstrip("/")
    return f"https://{account}.{service}.{(suffix or DEFAULT_ENDPOINT_SUFFIX).strip().strip('.')}"


def account_name(url: str) -> str:
    """The storage account behind a service URL: the first host label, or Azurite's path segment."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if host.count(".") >= 2 and not host.replace(".", "").isdigit():
        return host.split(".", 1)[0]
    return parts.path.strip("/").split("/", 1)[0] or host


def strip_query(url: Any) -> str:
    """A client's URL without its query string: BlobServiceClient.url repeats a SAS token there."""
    return str(url).split("?", 1)[0].rstrip("/")


def blob_service_client(target: Dict[str, Any], config: Dict[str, Any]):
    """A BlobServiceClient for the target, following the module's credential order."""
    if BlobServiceClient is None:
        raise AzureConfigError("azure-storage-blob is not installed; install requirements.txt")
    connection_string = setting(target, config, "connection_string", "AZURE_STORAGE_CONNECTION_STRING")
    if connection_string:
        return BlobServiceClient.from_connection_string(connection_string)
    url = account_url(
        setting(target, config, "account", "AZURE_STORAGE_ACCOUNT"),
        setting(target, config, "endpoint_suffix", "AZURE_STORAGE_ENDPOINT_SUFFIX"),
    )
    sas_token = setting(target, config, "sas_token", "AZURE_STORAGE_SAS_TOKEN")
    if sas_token:
        return BlobServiceClient(url, credential=str(sas_token).lstrip("?"))
    account_key = setting(target, config, "account_key", "AZURE_STORAGE_ACCOUNT_KEY")
    if account_key:
        return BlobServiceClient(url, credential={"account_name": account_name(url), "account_key": account_key})
    return BlobServiceClient(url, credential=default_credential())


def cosmos_endpoint(value: Optional[str]) -> str:
    """https://<account>.documents.azure.com:443/ for an account name; a URL is used as given."""
    if not value:
        raise AzureConfigError("Set AZURE_COSMOS_ENDPOINT (or target['endpoint']) to the Cosmos DB account URL or name")
    value = str(value).strip()
    if "://" in value:
        return value if value.endswith("/") else value + "/"
    return f"https://{value}.{COSMOS_ENDPOINT_SUFFIX}:443/"


def display_endpoint(url: str) -> str:
    """The endpoint as it appears in resource ids: scheme and host, the default port dropped."""
    parts = urlsplit(url)
    netloc = parts.netloc
    if parts.scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    return f"{parts.scheme}://{netloc}"
