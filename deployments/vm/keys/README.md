CA bundles and service-account key files for the instances go here (or straight into `/etc/dspm/keys/`).
`install.sh` copies this directory to `/etc/dspm/keys` (mode 0640, group 0) and every container mounts it
read-only at the same path, so an instance env can say `tlsCAFile=/etc/dspm/keys/global-bundle.pem` or
`GOOGLE_SA_KEY_FILE=/etc/dspm/keys/gws-scanner.json`. Everything in this directory except this file is git-ignored.
