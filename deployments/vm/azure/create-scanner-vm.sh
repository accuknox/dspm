#!/usr/bin/env bash
# Create the scanner VM on Azure: a Linux VM with a system-assigned managed identity in a private subnet,
# an NSG with no inbound rules, Docker installed by cloud-init and the image pulled. Prints the identity's
# principal id, which grant-access.sh takes.
#
#   RESOURCE_GROUP=dspm-rg LOCATION=eastus VNET=app-vnet SUBNET=scanner ./create-scanner-vm.sh
#
# Optional: VM_NAME (dspm-scanner), VM_SIZE (Standard_D4s_v5: 4 vCPU / 16 GB), ADMIN_USER (dspm),
# SSH_KEY (~/.ssh/id_ed25519.pub), DSPM_IMAGE (the tag in ../image.env), NSG_NAME (<VM_NAME>-nsg).
# The VNet and subnet must exist; the storage / database firewalls then allow that subnet.
set -euo pipefail

: "${RESOURCE_GROUP:?set RESOURCE_GROUP}"
: "${LOCATION:?set LOCATION}"
: "${VNET:?set VNET}"
: "${SUBNET:?set SUBNET}"
VM_NAME="${VM_NAME:-dspm-scanner}"
VM_SIZE="${VM_SIZE:-Standard_D4s_v5}"
ADMIN_USER="${ADMIN_USER:-dspm}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519.pub}"
NSG_NAME="${NSG_NAME:-$VM_NAME-nsg}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${DSPM_IMAGE:-}" ]]; then
  # shellcheck disable=SC1091
  source "$HERE/../image.env"
fi

if [[ ! -f "$SSH_KEY" ]]; then
  echo "SSH public key not found: $SSH_KEY (set SSH_KEY)" >&2
  exit 1
fi

echo "==> network security group $NSG_NAME (no inbound; outbound 443 + database ports only)"
az network nsg create --resource-group "$RESOURCE_GROUP" --name "$NSG_NAME" --location "$LOCATION" --output none
az network nsg rule create --resource-group "$RESOURCE_GROUP" --nsg-name "$NSG_NAME" --name deny-all-inbound \
  --priority 4096 --direction Inbound --access Deny --protocol '*' --source-address-prefixes '*' \
  --destination-port-ranges '*' --output none
az network nsg rule create --resource-group "$RESOURCE_GROUP" --nsg-name "$NSG_NAME" --name allow-https-out \
  --priority 100 --direction Outbound --access Allow --protocol Tcp --destination-port-ranges 443 --output none
az network nsg rule create --resource-group "$RESOURCE_GROUP" --nsg-name "$NSG_NAME" --name allow-databases-out \
  --priority 110 --direction Outbound --access Allow --protocol Tcp --destination-address-prefixes VirtualNetwork \
  --destination-port-ranges 5432 3306 1433 10255 27017 --output none
az network nsg rule create --resource-group "$RESOURCE_GROUP" --nsg-name "$NSG_NAME" --name deny-all-outbound \
  --priority 4000 --direction Outbound --access Deny --protocol '*' --destination-address-prefixes Internet \
  --destination-port-ranges '*' --output none

CLOUD_INIT="$(mktemp)"
trap 'rm -f "$CLOUD_INIT"' EXIT
cat > "$CLOUD_INIT" <<CLOUDINIT
#cloud-config
package_update: true
packages: [docker.io]
runcmd:
  - systemctl enable --now docker
  - docker pull ${DSPM_IMAGE} || true
CLOUDINIT

echo "==> virtual machine $VM_NAME ($VM_SIZE) with a system-assigned managed identity"
az vm create --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --location "$LOCATION" \
  --image Ubuntu2404 --size "$VM_SIZE" --admin-username "$ADMIN_USER" --ssh-key-values "$SSH_KEY" \
  --vnet-name "$VNET" --subnet "$SUBNET" --nsg "$NSG_NAME" --public-ip-address "" \
  --assign-identity '[system]' --os-disk-size-gb 64 --storage-sku Premium_LRS \
  --custom-data "$CLOUD_INIT" --output none

PRINCIPAL_ID="$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --query identity.principalId --output tsv)"
echo
echo "VM $VM_NAME created. Managed identity principal id: $PRINCIPAL_ID"
echo "Next: PRINCIPAL_ID=$PRINCIPAL_ID ./grant-access.sh --storage-account <rg>/<account> ..."
echo "Then copy deployments/vm to the VM (no public IP: through Bastion or the serial console) and run install.sh."
