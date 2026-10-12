# CIS Ubuntu 24.04 LTS Hardening

This project audits and remediates CIS Level 1 settings on Ubuntu 24.04.

## Run

```bash
sudo ./hardening.sh audit
sudo ./hardening.sh verify
sudo ./hardening.sh remediate
sudo ./test.sh
```

`audit`, `verify`, and `test.sh` are read-only. Remediation changes system
configuration; review `cis.conf` and keep a recovery path before running it.
Run `sudo ./test.sh` for privileged host checks; without root, checks that
require reading protected SSH, firewall, audit, or account settings are skipped.
To fix the root inactivity result on an already configured host, run
`sudo chage -I 30 root`, confirm with `sudo chage -l root`, then rerun
`sudo ./test.sh`.

Package upgrades are disabled by default because they can restart services or
affect applications. After approving a maintenance window, set
`APPLY_PACKAGE_UPDATES="yes"` in `cis.conf` before remediation. Site-specific
settings such as remote logging, GRUB credentials, and SSH account allowlists
must be supplied for the environment and may remain skipped by local tests.
