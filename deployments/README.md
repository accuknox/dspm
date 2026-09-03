# Deployments

The scanner is one container image (`public.ecr.aws/k9v9d5v2/dspm`, tag in `release.txt`) driven entirely by
environment variables. It runs inside the customer's cloud, in the region where the data lives, reads that data
in place, and the only thing that leaves is the findings archive posted to the CSPM. These folders package that
container for two kinds of host:

| Folder | Use when | What it is |
|---|---|---|
| [`vm/`](vm/README.md) | **Default.** Any cloud, no cluster required | One VM per region, one scanner instance (container) per credential set, systemd timers, findings uploaded per instance.
| [`kubernetes/`](kubernetes/cronjob.yaml) | The customer already runs OpenShift / Kubernetes in that region | CronJob + Secret template that works under the restricted SCC |

Placement rule for both: **one scanner per region**, plus one per network the scanner cannot otherwise reach. Another
account in the same region is another instance (VM) or another role (Kubernetes), never another machine. Reads stay in
the region; only findings cross the boundary.
