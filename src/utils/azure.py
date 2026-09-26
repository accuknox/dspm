"""
Azure identity helpers shared by the Azure connectors (src/scanners/azure) and
the handlers.

default_credential()        the one credential chain every Azure call uses (below)
is_keyvault_uri(value)      True for https://<vault>.vault.azure.net/secrets/<name>[/<version>]
get_keyvault_secret(uri)    a Key Vault secret by URI, read with that identity through the
                            REST API (no extra SDK). A JSON value comes back as a dict, like an
                            AWS Secrets Manager secret; a plain value as {"password": value}.
entra_db_token()            an access token for Azure Database for PostgreSQL / MySQL Flexible
                            Server, the password of every connection when DB_AUTH=azure_entra

The chain is azure-identity's DefaultAzureCredential in its own order: a service
principal from AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET, AKS workload
identity (AZURE_FEDERATED_TOKEN_FILE), the VM's managed identity through the instance
metadata service (a bare AZURE_CLIENT_ID selects a user-assigned identity), then
`az login` on a developer machine. Interactive and shared-token-cache credentials are
excluded so the chain behaves the same inside a read-only container running as an
unnamed UID. Tokens are cached and refreshed by the SDK; the scanner never stores one.
"""
import json
import os
from typing import Any, Dict
from urllib.parse import urlsplit

import requests

from src.utils.logger import get_logger

# Conditional import for soft failures, like pymongo in the Mongo connector
try:
    from azure.identity import DefaultAzureCredential
except ImportError:
    DefaultAzureCredential = None

logger = get_logger(__name__)

# Azure Database for PostgreSQL / MySQL Flexible Server token audience
OSSRDBMS_SCOPE = "https://ossrdbms-aad.database.windows.net/.default"
KEYVAULT_API_VERSION = "7.4"


class AzureConfigError(ValueError):
    """Missing or contradictory Azure settings. The message never carries a credential."""


def default_credential(**overrides: Any):
    """DefaultAzureCredential configured for a headless container; see the module docstring."""
    if DefaultAzureCredential is None:
        raise AzureConfigError("azure-identity is not installed; install requirements.txt")
    kwargs: Dict[str, Any] = {
        "exclude_interactive_browser_credential": True,
        "exclude_shared_token_cache_credential": True,
    }
    client_id = os.environ.get("AZURE_CLIENT_ID")
    if client_id and not os.environ.get("AZURE_CLIENT_SECRET") and not os.environ.get("AZURE_FEDERATED_TOKEN_FILE"):
        kwargs["managed_identity_client_id"] = client_id  # user-assigned managed identity
    kwargs.update(overrides)
    return DefaultAzureCredential(**kwargs)


def is_keyvault_uri(value: Any) -> bool:
    try:
        parts = urlsplit(str(value or ""))
    except ValueError:
        return False
    return parts.scheme == "https" and ".vault." in parts.netloc and "/secrets/" in parts.path


def get_keyvault_secret(secret_uri: str) -> Dict[str, Any]:
    """
    Reads one Key Vault secret with the scanner identity (role: Key Vault Secrets User).
    Returns {} on any failure, like src.utils.aws.get_secret.
    """
    try:
        parts = urlsplit(secret_uri)
        vault_suffix = parts.netloc.split(".", 1)[1]  # vault.azure.net, vault.usgovcloudapi.net, ...
        token = default_credential().get_token(f"https://{vault_suffix}/.default").token
        response = requests.get(
            f"{parts.scheme}://{parts.netloc}{parts.path}",
            params={"api-version": KEYVAULT_API_VERSION},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if response.status_code >= 300:
            logger.error(f"Key Vault returned HTTP {response.status_code} for {secret_uri}")
            return {}
        value = response.json().get("value", "")
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            parsed = None
        return parsed if isinstance(parsed, dict) else {"password": value}
    except Exception as e:
        logger.error(f"Failed to retrieve Key Vault secret '{secret_uri}': {str(e)}")
    return {}


def entra_db_token() -> str:
    """A fresh access token for Azure Database for PostgreSQL / MySQL Flexible Server."""
    return default_credential().get_token(OSSRDBMS_SCOPE).token
