# Scanner on a VM

One VM per region. One env file per scanner instance. The published container, unchanged.

```
/etc/dspm/
├── common.env             shared by every instance: CSPM_URL, ARTIFACT_TOKEN, ENABLED_REGIONS, MIN_CONFIDENCE, NER_MODEL …
├── image.env              DSPM_IMAGE=<registry>/dspm:<tag>
├── aws-config             one [profile] per AWS account the VM reads from (assume-role, no keys)
├── keys/                  CA bundles and service-account key files, mounted read-only into every container
└── instances/
    ├── s3-account-a.env   OBJECT_TYPE=S3, its buckets, AWS_PROFILE=account-a, AWS_ACCOUNT_ID, LABEL_ID
    ├── postgres-appdb.env OBJECT_TYPE=POSTGRES, the databases on that host, DB_HOST, DB_USERNAME, DB_PASSWORD, LABEL_ID
    └── mongodb-crm.env
/var/lib/dspm/output/<instance>/findings/*.json      local copy of every uploaded JSON, kept 30 days
```

`dspm@<instance>.timer` starts `dspm@<instance>.service`, which runs
`docker run --env-file /etc/dspm/common.env --env-file /etc/dspm/instances/<instance>.env <image>`.
That is the whole design. Each instance scans its targets, writes one findings JSON per target, zips it and
POSTs it to `<CSPM_URL>/api/v1/artifact/`, exactly what the image's default command does everywhere else.
No scanner code is specific to this deployment.

## What an instance is

An instance is **one credential set**:

* **S3**: one instance per AWS account, all of that account's buckets in this region in one `OBJECTS_TO_SCAN` list.
* **Databases**: one instance per host, every database on it in one list. `DB_HOST` / `DB_URI` and the user are
  shared inside an instance, which is why two hosts need two instance files.
* **Google Workspace / Salesforce**: one instance per tenant.

In practice that is one instance per `OBJECT_TYPE`, sometimes two.

## 1. The VM

* A private subnet in the region that holds the data, **no inbound rules**. Outbound: 443 to the CSPM, the database
  subnets, and the registry unless the image is mirrored.
* An S3 gateway endpoint on the VPC, so bucket reads never touch the internet or the egress meter.
* An identity: instance role on AWS, managed identity on Azure, attached service account on GCP. On AWS the role
  carries `aws/instance-role-policy.json` (permission to assume the member-account roles) and, if the VM's own
  account holds data too, `aws/member-role-policy.json`.
* AWS only: IMDSv2 hop limit **2** (`http_put_response_hop_limit = 2`). With the default of 1 a container on the
  Docker bridge never reaches the metadata service and boto3 finds no credentials.
* Docker (Podman works: replace `/usr/bin/docker` in `systemd/*.service`).
* Size: 4 vCPU / 8 GB runs any number of instances one at a time with the transformer NER model. Read
  "Schedule and memory" before running instances in parallel.

## 2. Env files

Copy this folder to the VM (`scp -r deployments/vm <vm>:dspm-vm`, a Terraform `file` provisioner, or bake it into
the image), then:

```bash
cp common.env.example common.env                                  # CSPM_URL, ARTIFACT_TOKEN, ENABLED_REGIONS …
cp instances/s3-account-a.env.example   instances/s3-account-a.env
cp instances/postgres-appdb.env.example instances/postgres-appdb.env
cp aws-config.example aws-config                                  # only with S3 instances
"$EDITOR" common.env aws-config image.env instances/*.env
```

Every variable is documented in the repository `README.md` and `.env.example`; nothing here is new. Real `*.env`
files, `aws-config` and `keys/` are git-ignored, only the `.example` files are committed. Docker env-file syntax:
`KEY=VALUE`, no quotes around values, `#` comments on their own line.

## 3. Install

```bash
sudo ./install.sh                 # a timer per instance, all at 02:00 (+ up to 10 min jitter)
sudo ./install.sh --sequential    # one timer that runs the instances one after another
```

The installer copies the config to `/etc/dspm` (env files at mode 0600), installs the units, the retention rule and
the helper script, then enables `dspm@<instance>.timer` for every `instances/*.env` (or `dspm-all.timer` with
`--sequential`). `/etc/dspm` is the live configuration; re-running the installer copies the real files from this
folder over it, so keep one place of truth. Then:

```bash
sudo systemctl start dspm@s3-account-a.service      # run one instance now (blocks until it finishes)
journalctl -u dspm@s3-account-a.service -f          # follow it
systemctl list-timers 'dspm*'                       # what runs when
ls /var/lib/dspm/output/s3-account-a/findings/      # local copy of the uploaded JSON
```

Exit code 0 means every target was scanned and uploaded; 1 means a scan error, an unsupported `OBJECT_TYPE` or a
failed upload, with details in the journal and in the `errors` field of the JSON. `systemctl status dspm@<instance>`
therefore shows the last run's result.

## 4. Findings

Each instance uploads `<target>-<date>.zip`, one JSON per target, tagged with the `LABEL_ID` from its env file.
Name the label after region and instance, for example `us-east-1-s3-account-a`. On the CSPM side, "no upload for
label X since yesterday" is the health check for this design.

## Cross-account S3 without keys (AWS)

Leave `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` unset. Give each S3 instance `AWS_PROFILE=<account>` and define
that profile in `aws-config` (`common.env` points `AWS_CONFIG_FILE` at it, the unit mounts it read-only):

```ini
[profile account-a]
role_arn = arn:aws:iam::111122223333:role/dspm-scanner-readonly
credential_source = Ec2InstanceMetadata
external_id = <the external id in that account's trust policy>
region = us-east-1
```

boto3 assumes the role from the VM's instance identity and refreshes the session by itself; the scanner does not
know it is reading another account. In each member account create `dspm-scanner-readonly` from
`aws/member-role-trust.json` (trusts the VM's instance role plus the external id) and `aws/member-role-policy.json`.
That policy allows list and get **only for requests in `REGION`**, so a bucket that lives elsewhere fails loudly
instead of being read across the border (S3 would redirect and boto3 would follow); `GetBucketLocation` stays
allowed so the failure names the region. Static keys still work: put them in the instance env and omit `AWS_PROFILE`.

## Schedule and memory

An instance with more than one target scans two targets at a time in two processes, and each process loads the
NER model: about 2.7 GB resident with `en_core_web_trf`, about 0.5 GB with `en_core_web_sm`. Pick one mode:

| Mode | How | 4 instances, transformer model |
|---|---|---|
| Staggered | default units; move each timer with a drop-in (below) | 4 vCPU / 8 GB |
| Sequential | `install.sh --sequential`: `dspm-all.timer` runs `dspm-run-all`, which starts each instance and waits for it | 4 vCPU / 8 GB |
| Parallel | leave every timer at 02:00 | 8 vCPU / 32 GB |

Moving one instance to 03:00 (the empty `OnCalendar=` clears the template's time; drop-ins survive re-installs):

```bash
sudo systemctl edit dspm@postgres-appdb.timer
```
```ini
[Timer]
OnCalendar=
OnCalendar=*-*-* 03:00:00
```

`NER_MODEL=en_core_web_sm` in `common.env` makes every mode fit in 8 GB, at some cost in person-name recall inside
free text.

## Updating the image

Edit the tag in `/etc/dspm/image.env`. The service pulls before every run; the pull is allowed to fail so that a
registry outage never blocks a scan with the image already present. When the VM has no route to `public.ecr.aws`,
mirror the image into a private registry (ECR pull-through cache, ACR import, Artifact Registry remote repository)
and point `DSPM_IMAGE` there.

## TLS bundles and key files

Put CA bundles and service-account keys in `keys/` next to this file (or straight into `/etc/dspm/keys/`); the unit
mounts that directory read-only at the same path inside the container. Reference them from the instance env, for
example `DB_URI=mongodb://…/?tls=true&tlsCAFile=/etc/dspm/keys/global-bundle.pem` for DocumentDB or
`GOOGLE_SA_KEY_FILE=/etc/dspm/keys/gws-scanner.json` for Google Workspace.

## Other clouds

The VM, the files and the units are identical; only step 1 changes.

| Cloud | Step 1 differences | Instances available today |
|---|---|---|
| AWS | instance role + `aws-config` profiles, S3 gateway endpoint | S3 per account, Postgres / MySQL / MSSQL per host, MongoDB / DocumentDB, Drive, Salesforce |
| Azure | managed identity for Key Vault; databases over private endpoints | Azure Database for PostgreSQL / MySQL, Azure SQL (`MSSQL`), Cosmos DB for MongoDB, Drive, Salesforce. No Blob connector yet |
| GCP | attached service account; Private Google Access; databases over private IP | Cloud SQL Postgres / MySQL / SQL Server, self-managed Mongo, Drive, Salesforce. No GCS connector yet |
| OCI | Object Storage through its S3-compatible API: `AWS_ENDPOINT_URL_S3=https://<namespace>.compat.objectstorage.<region>.oraclecloud.com` plus customer secret keys in the instance env, path-style addressing in `aws-config` (verify before promising it) | Object Storage, MySQL HeatWave, self-managed Mongo. No Oracle Database connector yet |
| OpenStack | Swift through its S3 API the same way; databases over the tenant network | Swift, Postgres / MySQL / MariaDB, Mongo |

## Limits of this design

* Changing targets means editing a file on the VM (or re-running the Terraform / cloud-init that wrote it).
* Health is inferred by the CSPM from uploads per label; a VM that never runs is silent.
* Only the AWS member policy enforces the region rule; on other clouds keeping each instance to its own region is
  the operator's job.
* A run stopped midway (`systemctl stop`, a reboot) uploads nothing; the timer reruns it the next night.
* Scale is the VM: a very large region gets a bigger VM, or a second VM with half of the instance files.
