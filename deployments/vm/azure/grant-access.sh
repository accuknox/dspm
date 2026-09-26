#!/usr/bin/env bash
# Grant the scanner identity read-only access to the data it scans. Idempotent.
#
#   PRINCIPAL_ID=<managed identity or service principal object id> ./grant-access.sh \
#       --storage-account <rg>/<account> [--storage-account ...] \
#       --resource-group-scope <rg>            # every storage account in the group instead
#       --cosmos-account <rg>/<account>        # Cosmos DB for NoSQL data-plane reader
#       --key-vault <rg>/<vault>               # secrets used with password_secret / DB passwords
#       --custom-role                          # DSPM Scanner Reader (dspm-scanner-reader.json) instead of Storage Blob Data Reader
#
# Roles: Storage Blob Data Reader (blobs, ADLS Gen2), Cosmos DB Built-in Data Reader (data-plane role,
# assigned through the Cosmos CLI; the portal's IAM blade cannot), Key Vault Secrets User. Databases use
# their own logins or an Entra principal created on the server (instances/azure-postgres.env.example).
set -euo pipefail

: "${PRINCIPAL_ID:?set PRINCIPAL_ID to the object id of the identity (az vm show --query identity.principalId)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOB_ROLE="Storage Blob Data Reader"
COSMOS_READER_ROLE_ID="00000000-0000-0000-0000-000000000001"   # built-in Cosmos DB Built-in Data Reader
storage_accounts=()
cosmos_accounts=()
key_vaults=()
group_scopes=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --storage-account) storage_accounts+=("$2"); shift 2 ;;
    --resource-group-scope) group_scopes+=("$2"); shift 2 ;;
    --cosmos-account) cosmos_accounts+=("$2"); shift 2 ;;
    --key-vault) key_vaults+=("$2"); shift 2 ;;
    --custom-role) BLOB_ROLE="DSPM Scanner Reader"; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

SUBSCRIPTION_ID="$(az account show --query id --output tsv)"

if [[ $BLOB_ROLE == "DSPM Scanner Reader" ]]; then
  if ! az role definition list --name "$BLOB_ROLE" --query '[0].roleName' --output tsv | grep -q .; then
    echo "==> creating custom role $BLOB_ROLE in subscription $SUBSCRIPTION_ID"
    sed "s/SUBSCRIPTION_ID/$SUBSCRIPTION_ID/" "$HERE/dspm-scanner-reader.json" > /tmp/dspm-scanner-reader.json
    az role definition create --role-definition /tmp/dspm-scanner-reader.json --output none
    rm -f /tmp/dspm-scanner-reader.json
  fi
fi

assign() {  # role, scope
  echo "==> $1 on $2"
  az role assignment create --assignee-object-id "$PRINCIPAL_ID" --assignee-principal-type ServicePrincipal \
    --role "$1" --scope "$2" --output none
}

for entry in "${storage_accounts[@]}"; do
  rg="${entry%%/*}"; name="${entry##*/}"
  scope="$(az storage account show --resource-group "$rg" --name "$name" --query id --output tsv)"
  assign "$BLOB_ROLE" "$scope"
done

for rg in "${group_scopes[@]}"; do
  assign "$BLOB_ROLE" "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$rg"
done

for entry in "${cosmos_accounts[@]}"; do
  rg="${entry%%/*}"; name="${entry##*/}"
  echo "==> Cosmos DB Built-in Data Reader on $name (data plane)"
  az cosmosdb sql role assignment create --resource-group "$rg" --account-name "$name" \
    --role-definition-id "$COSMOS_READER_ROLE_ID" --principal-id "$PRINCIPAL_ID" --scope "/" --output none
done

for entry in "${key_vaults[@]}"; do
  rg="${entry%%/*}"; name="${entry##*/}"
  scope="$(az keyvault show --resource-group "$rg" --name "$name" --query id --output tsv)"
  assign "Key Vault Secrets User" "$scope"
done

echo "done. Role assignments take a few minutes to propagate; a 403 AuthorizationPermissionMismatch right after this is normal."
