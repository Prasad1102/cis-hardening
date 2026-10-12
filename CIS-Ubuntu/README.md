# CIS Ubuntu 24.04 LTS Hardening

The project uses three files: `hardening.sh` contains the controller, embedded
CIS configuration, common helpers, and all six hardening sections. `test.sh`
contains the separate read-only test suite. This README contains usage notes.

## Run

```bash
sudo ./hardening.sh audit
sudo ./hardening.sh verify
sudo ./hardening.sh remediate
sudo ./test.sh
```

`audit`, `verify`, and `test.sh` are read-only. Remediation changes system
configuration; review the embedded settings near the top of `hardening.sh` and
keep a recovery path before running it. Run `sudo ./test.sh` for privileged
host checks; without root, checks that require protected SSH, firewall, audit,
or account settings are skipped.
To fix the root inactivity result on an already configured host, run
`sudo chage -I 30 root`, confirm with `sudo chage -l root`, then rerun
`sudo ./test.sh`.

Package upgrades are disabled by default because they can restart services or
affect applications. After approving a maintenance window, set
`APPLY_PACKAGE_UPDATES="yes"` in `hardening.sh` before remediation. Site-specific
settings such as remote logging, GRUB credentials, and SSH account allowlists
must be supplied for the environment and may remain skipped by local tests.
