# CIS Ubuntu 24.04 LTS Hardening

This project provides a CIS Level 1 hardening and local test suite for Ubuntu
24.04 LTS. It is organized as three files:

- `hardening.sh` — controller, embedded configuration, common helpers, and all
  six hardening sections.
- `test.sh` — separate read-only test suite for the project and local host.
- `README.md` — setup, safety, and usage instructions.

There is no separate `cis.conf`, `lib/`, or `sections/` directory. Review and
edit the configuration variables near the top of `hardening.sh`.

## Requirements

- Ubuntu 24.04 LTS.
- Bash and the standard system utilities used by the scripts.
- `sudo` access for the full host audit, remediation, verification, and
  privileged host checks.

The test script can be started without root, but some host checks may be
restricted or skipped. Run it with `sudo` for a full privileged check.

## Prepare

From the directory containing these three files:

```bash
chmod +x hardening.sh test.sh
```

Before making changes, inspect the configuration near the top of
`hardening.sh`, especially SSH, firewall, password, logging, and site-specific
settings. Confirm that the values fit your server and that you have a recovery
path (for example, console access or a tested backup). Hardening can affect
SSH access and services.

Package upgrades are disabled by default. Leave
`APPLY_PACKAGE_UPDATES="no"` unless package upgrades have been approved for a
maintenance window. Enable them by setting it to `"yes"` in `hardening.sh`.

## Recommended workflow

1. Run a read-only audit to record the current state:

   ```bash
   sudo ./hardening.sh audit
   ```

2. Run the separate read-only test suite:

   ```bash
   sudo ./test.sh
   ```

3. Review the results and configuration. When ready to apply the selected
   settings, run remediation:

   ```bash
   sudo ./hardening.sh remediate
   ```

   Remediation changes system configuration and runs a final audit to show
   remaining failures or manual items. Review its output; site-specific
   controls may require additional configuration.

4. Run the test suite again to check the resulting host:

   ```bash
   sudo ./test.sh
   ```

## Commands

```bash
sudo ./hardening.sh audit
sudo ./hardening.sh verify
sudo ./hardening.sh remediate
sudo ./test.sh
sudo ./test.sh --audit
```

- `audit` performs the configured audit without intentionally changing system
  settings.
- `verify` currently runs the same read-only checks as `audit`.
- `remediate` applies configured hardening changes, then performs a final
  audit.
- `test.sh` runs the standalone test suite; it does **not** run remediation.
- `test.sh --audit` runs the test suite and additionally invokes
  `hardening.sh audit`.

The test summary reports passed, failed, and skipped checks. Some checks are
conditional or site-specific, so review skipped results as well as failures.
The test script checks the local machine and expects Ubuntu 24.04; results from
other operating systems are not a substitute for testing on Ubuntu 24.04.

## Site-specific settings

Some controls need environment-specific values, such as remote syslog
destinations, GRUB credentials, SSH user or group allowlists, and permitted
firewall ports. Configure these in `hardening.sh` before remediation. A control
may be reported as skipped when the required site-specific information is not
provided.
