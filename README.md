# CIS Ubuntu 24.04 LTS Hardening

This repository contains a Bash-based CIS hardening and audit project for
Ubuntu 24.04 LTS. It is organized into a main controller, a shared
configuration file, reusable library functions, and six control-specific
sections.

> **Important:** `remediate` changes operating-system configuration. Review
> `CIS-Ubuntu/cis.conf`, take an appropriate system backup, and test on a
> disposable or otherwise recoverable host before using it on production.
> Firewall, SSH, PAM, boot, filesystem, and kernel settings can affect
> connectivity or system access.

## Index

- [Overview](#overview)
- [Repository layout](#repository-layout)
- [What each file does](#what-each-file-does)
- [Remediation and audit behavior](#remediation-and-audit-behavior)
- [Configuration](#configuration)
- [Requirements](#requirements)
- [How to run](#how-to-run)
- [Logs, reports, and backups](#logs-reports-and-backups)
- [Deployment workflow](#deployment-workflow)
- [Operational safety notes](#operational-safety-notes)

## Overview

The project provides two commands:

- **Audit** reads the host's current state and reports controls that pass,
  fail, warn, or require manual review.
- **Remediate** runs a baseline audit, applies configured changes, validates
  selected configuration syntax, then runs a final verification audit.

The project is intended for Ubuntu 24.04 LTS and must be run as root (usually
with `sudo`). The settings and optional actions are controlled by
`CIS-Ubuntu/cis.conf`.

## Repository layout

```text
.
├── .github/
│   └── workflows/
│       └── deploy.yml
├── CIS-Ubuntu/
│   ├── cis.conf
│   ├── hardening.sh
│   ├── lib/
│   │   └── common.sh
│   └── sections/
│       ├── 01_filesystem_boot.sh
│       ├── 02_services_network.sh
│       ├── 03_firewall_ssh.sh
│       ├── 04_pam_accounts.sh
│       ├── 05_logging_audit.sh
│       └── 06_permissions.sh
└── README.md
```

The `CIS-Ubuntu` directory is the runnable project root. Run `hardening.sh`
from that directory so relative command examples and paths resolve as shown.

## What each file does

### Repository documentation and automation

| File | Purpose |
|---|---|
| `README.md` | This guide: project layout, configuration, operation, logging, and safety information. |
| `.github/workflows/deploy.yml` | GitHub Actions deployment workflow. On a push to `main`, it connects to the configured EC2 host over SSH and fetches/resets the checkout to `origin/main`. (CICD File)|

### Main project files

| File | Purpose |
|---|---|
| `CIS-Ubuntu/hardening.sh` | Main command-line controller. It checks the action, root privileges, OS, required files, configuration, and section syntax; initializes logs; and dispatches audits or remediation across the sections. |
| `CIS-Ubuntu/cis.conf` | Central policy and behavior configuration. It supplies expected audit values and controls optional remediation features such as IPv6 hardening, filesystem mount configuration, package/service setup, and firewall ports. Review this file before remediation. |
| `CIS-Ubuntu/lib/common.sh` | Shared functions used by the controller and sections, including logging, audit result reporting, backups, package helpers, sysctl helpers, and other common operations. |

### Control sections

The controller runs sections in numerical order.

| File | Responsibility |
|---|---|
| `CIS-Ubuntu/sections/01_filesystem_boot.sh` | Filesystem and boot-related controls: temporary filesystem settings, GRUB password configuration, kernel sysctls, AppArmor, apport, login banners and MOTD/PAM MOTD, and AIDE. |
| `CIS-Ubuntu/sections/02_services_network.sh` | Service and network controls: Telnet/FTP clients, selected kernel modules, IPv4 sysctls, and optionally IPv6 sysctls. |
| `CIS-Ubuntu/sections/03_firewall_ssh.sh` | UFW firewall setup and defaults, SSH access rules, SSH configuration, and SSH configuration permissions. UFW may load `/etc/ufw/sysctl.conf`; network sysctl policy should account for those entries as well as the normal sysctl configuration. |
| `CIS-Ubuntu/sections/04_pam_accounts.sh` | PAM and account policy: faillock, password quality/history, password aging, account checks, and related account defaults. |
| `CIS-Ubuntu/sections/05_logging_audit.sh` | Rsyslog configuration, log and directory permissions, auditd service/configuration, and audit rules. |
| `CIS-Ubuntu/sections/06_permissions.sh` | Auditing and remediation of selected sensitive-file, sudo, temporary-directory, cron, SSH-directory, and world-writable permissions. |

Each section contains the audit/remediation functions for its scope. The
controller sources the relevant section and invokes the appropriate entry
point; the common library provides the shared helpers those functions use.

## Remediation and audit behavior

The normal `audit` action is read-only with respect to the hardening
configuration. It gathers the current state and reports results.

The `remediate` action follows this general sequence:

1. Run a baseline audit.
2. Check that remediation is enabled in `cis.conf`.
3. Create backups for the paths managed by the project.
4. Run the six remediation sections in order.
5. Validate selected configuration syntax.
6. Run a final verification audit.
7. Write the final report and return a failing status if failures remain.

Consequently, failures near the beginning of a remediation run can be
baseline findings. Use the output under **Running final verification audit**
to determine which controls still fail after remediation.

Some changes are host-specific or require manual follow-up. A successful
remediation command does not guarantee that every control can be applied
safely to every server or that no external service will later change runtime
settings.

## Configuration

Edit `CIS-Ubuntu/cis.conf` before running remediation. Keep the file under
version control free of secrets and host-specific credentials.

The main configuration groups include:

- **General behavior:** remediation enablement and expected host metadata.
- **SSH:** port, authentication limits, forwarding, root login, banners, and
  optional user/group allow or deny lists.
- **Password and account policy:** password aging, quality, history, lockout,
  inactive-account behavior, and default umask.
- **Kernel and networking:** expected kernel values, IPv4 and IPv6 network
  sysctls, and whether IPv6 hardening is enabled.
- **Filesystem and boot:** temporary filesystem configuration, GRUB
  superuser/hash settings, and optional mount controls.
- **Services and modules:** whether to remove Telnet/FTP clients, disable
  selected kernel modules, configure AppArmor, apport, AIDE, rsyslog, and
  auditd.
- **Firewall:** SSH safety requirement and the TCP/UDP ports to allow through
  UFW.
- **Remote logging:** enablement, host, port, and protocol for remote rsyslog.
- **Reboot policy:** whether the project allows a reboot.

Read the comments alongside each setting in `cis.conf`. In particular:

- Add all required SSH and application ports before enabling UFW. An
  incorrect firewall policy can interrupt remote access.
- Set filesystem options only after confirming the host's mount layout.
- Configure a real GRUB password hash only when that policy is required.
- Configure a real remote logging destination before enabling remote syslog.
- Review whether disabling a kernel module or enabling a system service is
  appropriate for the workload.

## Requirements

- Ubuntu 24.04 LTS (the controller checks the operating system).
- Bash.
- Root privileges; invoke through `sudo`.
- Commands used by the configured checks and remediations, including `sysctl`,
  `systemctl`, `mount`, `grep`, `sed`, `awk`, and `dpkg-query`.
- Network/package repository access if a selected remediation must install
  packages.
- A reachable SSH port configured in `UFW_ALLOWED_TCP_PORTS` before UFW is
  enabled on a remote host.

The controller performs its own basic command and configuration checks before
dispatching the selected action. Package and service availability can still
affect individual controls.

## How to run

Change to the project directory:

```bash
cd CIS-Ubuntu
```

### 1. Review configuration

Read and edit `cis.conf` for the target host. Confirm all required network
ports and optional features before making changes.

### 2. Run an audit

```bash
sudo ./hardening.sh audit
```

This reports the current state without intentionally applying the configured
remediation.

### 3. Run remediation

```bash
sudo ./hardening.sh remediate
```

This applies configured changes after a baseline audit and then performs a
final audit. It can modify system files, services, firewall policy, kernel
settings, and account/security configuration.

### 4. Review the result

Check the terminal output and the run log/report paths printed at the end.
Distinguish baseline findings from failures shown in the final verification
audit. Investigate any remaining failures on the host before assuming the
configuration has taken effect.

### Help

```bash
./hardening.sh --help
```

The help text lists the supported actions and examples. The script still
requires root for `audit` and `remediate`.

## Logs, reports, and backups

The main controller creates timestamped run logs and audit reports under:

- `/var/log/cis-hardening/` — controller run logs.
- `/var/log/cis-hardening/reports/` — audit summary reports.

The shared library also maintains timestamped operation logs and backups
under:

- `/root/cis-logs/<timestamp>/` — section/common remediation logs.
- `/root/cis-backup/<timestamp>/` — backups created by shared backup helpers.

The controller additionally creates its pre-remediation backups before
applying the remediation sections. Use the paths printed by the actual run as
the authoritative locations for that host and execution.

## Deployment workflow

The GitHub Actions workflow in `.github/workflows/deploy.yml` runs on pushes
to `main`. It connects to an EC2 host using the repository's configured GitHub
Actions secrets and updates the checkout under `/home/ubuntu/cis-hardening`.
The workflow uses `git reset --hard origin/main` on the remote checkout.

Before enabling or relying on automated deployment:

1. Configure the host, username, and SSH key as repository Actions secrets.
2. Confirm the remote path and account are correct.
3. Understand that the hard reset discards uncommitted changes in the remote
   checkout.
4. Review workflow output and verify the deployed commit on the host.

The workflow deploys the repository; it does not itself run the hardening
commands.

## Operational safety notes

- Test remediation in a recoverable environment before production use.
- Keep a separate, verified recovery path when changing firewall or SSH
  settings.
- Confirm the SSH port and any other required inbound ports in
  `cis.conf` before UFW is enabled.
- Review all policy values and optional actions against the system's role.
- Treat audit `PASS`, `FAIL`, `WARNING`, and `SKIP/MANUAL` outcomes
  differently; some findings need an administrator's decision rather than
  automatic remediation.
- Runtime kernel settings can be changed by system services or other
  configuration sources. If an audit reports a live-value failure while
  persistence passes, inspect all sources that may load or override that
  kernel setting, including service-specific configuration such as UFW's
  sysctl file.
- Do not assume a successful remediation message means the host will remain
  compliant after a reboot, network-interface event, package update, or
  external configuration-management run. Verify again after relevant system
  lifecycle events.
