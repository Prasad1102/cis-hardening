# CIS Ubuntu 24.04 Test Cases

Run static checks with `bash tests/run_tests.sh`. Run live tests on a disposable Ubuntu 24.04 host as root. Remediation tests modify system configuration; take a VM snapshot first. Each case records the required objective, setup, command, and acceptance criteria.

## Filesystem and Boot

### FS-01

- **Control ID:** 1.1.2.1.1
- **Objective:** Verify `/tmp` is a separate persistent mount with nodev,nosuid,noexec.
- **Preconditions:** Root; `CONFIGURE_TMP_MOUNT=yes`; configured size is 1-99%.
- **Test Commands:** `sudo ./hardening.sh remediate`; `findmnt -no TARGET,FSTYPE,OPTIONS /tmp`; `grep -E '^[^#].*[[:space:]]/tmp[[:space:]]' /etc/fstab`; `sudo ./hardening.sh audit`.
- **Expected Result:** A distinct `/tmp` tmpfs mount and matching fstab entry.
- **Pass Criteria:** Live and fstab options contain nodev,nosuid,noexec; audit passes.
- **Fail Criteria:** No `/tmp` mount, options differ, or fstab entry is not persistent.

### FS-02

- **Control ID:** 1.1.2.2.4
- **Objective:** Verify `/dev/shm` mount restrictions.
- **Preconditions:** Root; `/dev/shm` exists.
- **Test Commands:** `findmnt -no OPTIONS /dev/shm`; inspect the `/dev/shm` line in `/etc/fstab`; audit.
- **Expected Result:** Runtime and persistent nodev,nosuid,noexec options.
- **Pass Criteria:** All three options exist in both places and audit passes.
- **Fail Criteria:** Any option is missing.

### BOOT-01

- **Control ID:** 1.4.1
- **Objective:** Verify GRUB password when enabled; otherwise explicitly report manual SKIP.
- **Preconditions:** To test PASS, set `GRUB_PASSWORD_ENABLED=yes` and provide a valid PBKDF2 hash.
- **Test Commands:** `sudo ./hardening.sh remediate`; `grep -E 'set superusers|password_pbkdf2' /boot/grub/grub.cfg`; `sudo ./hardening.sh audit`.
- **Expected Result:** Enabled configuration has the configured superuser/hash; disabled configuration is reported SKIP/MANUAL.
- **Pass Criteria:** Exact configured identity/hash is generated and audit passes, or intentional disabled policy reports SKIP.
- **Fail Criteria:** Enabled without a hash, generated identity/hash mismatches, or disabled control reports PASS.

### SYS-01

- **Control ID:** 1.5.4, 1.5.5, 1.5.9
- **Objective:** Verify core kernel sysctl settings.
- **Preconditions:** Root; sysctl keys supported.
- **Test Commands:** `sysctl fs.suid_dumpable kernel.dmesg_restrict kernel.randomize_va_space`; inspect `/etc/sysctl.d/99-cis-hardening.conf`; audit.
- **Expected Result:** Values match `cis.conf` both live and persistently.
- **Pass Criteria:** All keys match and audit passes.
- **Fail Criteria:** Any key is absent, overridden, or differs.

### AA-01

- **Control ID:** 1.3.1.4
- **Objective:** Verify AppArmor status and configured restriction.
- **Preconditions:** Ubuntu kernel and AppArmor package support.
- **Test Commands:** `systemctl is-enabled apparmor`; `systemctl is-active apparmor`; `sysctl kernel.apparmor_restrict_unprivileged_unconfined`; audit.
- **Expected Result:** AppArmor enabled/active and requested restriction active.
- **Pass Criteria:** All configured checks pass.
- **Fail Criteria:** Required service or setting is unavailable/disabled.

### ERR-01

- **Control ID:** 1.5.7
- **Objective:** Verify apport is disabled.
- **Preconditions:** Ubuntu host; package may be absent.
- **Test Commands:** `dpkg-query -W apport`; `grep -E '^enabled=0' /etc/default/apport`; audit.
- **Expected Result:** Package absent or configuration says `enabled=0`.
- **Pass Criteria:** Audit passes for either compliant state.
- **Fail Criteria:** Installed apport remains enabled or config is malformed.

### BANNER-01

- **Control ID:** 1.6.1, 1.6.3, 1.6.5, 1.6.6, 1.6.9
- **Objective:** Verify issue/issue.net text, effective SSH banner, MOTD permissions, and PAM MOTD.
- **Preconditions:** Root; OpenSSH and PAM installed.
- **Test Commands:** `cat /etc/issue /etc/issue.net`; `sudo sshd -T | grep '^banner '`; `stat -c '%U:%G %a' /etc/motd`; `grep pam_motd /etc/pam.d/common-session`; audit.
- **Expected Result:** Both section audits use the same effective banner path; files and PAM line match configuration.
- **Pass Criteria:** All five controls pass without banner mismatch.
- **Fail Criteria:** Effective path differs, file missing/empty, mode wrong, or PAM line absent.

### AIDE-01

- **Control ID:** AIDE integrity package/database/timer
- **Objective:** Verify AIDE package, active database, and scheduled check.
- **Preconditions:** Apt repositories reachable; systemd available.
- **Test Commands:** `dpkg-query -W aide`; `test -s /var/lib/aide/aide.db`; `systemctl list-unit-files --type=timer | grep -i aide`; audit.
- **Expected Result:** Package and active DB exist; discovered or generated timer is enabled and active.
- **Pass Criteria:** Audit passes all enabled AIDE checks.
- **Fail Criteria:** Package/DB missing or configured timer inactive.

## Services, Network, and Firewall

### PKG-01

- **Control ID:** 2.2.4
- **Objective:** Verify Telnet client is absent.
- **Preconditions:** dpkg available.
- **Test Commands:** `dpkg-query -W telnet`; audit.
- **Expected Result:** Telnet package absent.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Package installed.

### PKG-02

- **Control ID:** 2.2.6
- **Objective:** Verify FTP clients are absent.
- **Preconditions:** dpkg available.
- **Test Commands:** `dpkg-query -W ftp inetutils-ftp`; audit.
- **Expected Result:** Both packages absent.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Either package installed.

### MOD-01

- **Control ID:** 3.2.1, 3.2.2, 3.2.5, 3.2.6
- **Objective:** Verify ATM/CAN/SCTP/TIPC are unavailable or blocked.
- **Preconditions:** Root; inspect only modules present in the running kernel.
- **Test Commands:** `lsmod`; `grep -RHE '^(blacklist|install)' /etc/modprobe.d`; audit.
- **Expected Result:** Present configured modules are not loaded and cannot be loaded.
- **Pass Criteria:** Each enabled module passes or is absent from the kernel.
- **Fail Criteria:** A module is loaded or unblocked.

### IPV4-01

- **Control ID:** 3.3.1.4-.5, 3.3.1.8-.18
- **Objective:** Verify IPv4 redirect, route, rp_filter, martian, and SYN-cookie settings.
- **Preconditions:** Root; IPv4 enabled.
- **Test Commands:** `sysctl -a 2>/dev/null | grep -E 'net.ipv4.conf.(all|default).(send_redirects|accept_redirects|secure_redirects|rp_filter|accept_source_route|log_martians)|net.ipv4.tcp_syncookies'`; inspect sysctl config; audit.
- **Expected Result:** Live settings equal config and persistent settings cannot be overridden.
- **Pass Criteria:** All listed keys pass, including both `log_martians` values.
- **Fail Criteria:** Any value is absent, overridden, or mismatched.

### IPV6-01

- **Control ID:** 3.3.2.1-.8
- **Objective:** Verify IPv6 forwarding, redirect, source-route, and RA settings.
- **Preconditions:** `HARDEN_IPV6=yes`; IPv6 available.
- **Test Commands:** `sysctl -a 2>/dev/null | grep 'net.ipv6.conf'`; audit.
- **Expected Result:** Values match configuration.
- **Pass Criteria:** All enabled checks pass.
- **Fail Criteria:** Any mismatch; disabled policy must be SKIP, never PASS.

### UFW-01

- **Control ID:** 4.1.2
- **Objective:** Verify firewall is active.
- **Preconditions:** UFW installed.
- **Test Commands:** `sudo ufw status`; audit.
- **Expected Result:** `Status: active`.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** UFW inactive or missing.

### UFW-02

- **Control ID:** 4.1.3-.5
- **Objective:** Verify incoming, outgoing, and routed defaults.
- **Preconditions:** UFW installed.
- **Test Commands:** `sudo ufw status verbose`; audit.
- **Expected Result:** deny incoming, allow outgoing, deny routed.
- **Pass Criteria:** All three policies pass.
- **Fail Criteria:** Any policy differs.

### UFW-03

- **Control ID:** FIREWALL-SSH
- **Objective:** Verify active and configured SSH ports are allowed.
- **Preconditions:** OpenSSH and UFW installed.
- **Test Commands:** `sudo ufw status`; `sudo sshd -T | grep '^port '`; audit.
- **Expected Result:** Every effective/configured SSH TCP port has an allow rule.
- **Pass Criteria:** Audit passes for standard and verbose UFW output.
- **Fail Criteria:** Any needed SSH port is missing.

## SSH

### SSH-01

- **Control ID:** 5.1.1
- **Objective:** Verify sshd configuration owner and permissions.
- **Preconditions:** OpenSSH server installed.
- **Test Commands:** `stat -c '%U:%G %a' /etc/ssh/sshd_config`; audit.
- **Expected Result:** root:root, mode 600.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Owner, group, or mode differs.

### SSH-02

- **Control ID:** 5.1.4
- **Objective:** Verify effective access restrictions.
- **Preconditions:** Environment-specific allow/deny list configured.
- **Test Commands:** `sudo sshd -T | grep -E '^(allowusers|allowgroups|denyusers|denygroups) '`; audit.
- **Expected Result:** Effective restriction matches configuration.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** No intended restriction or unexpected effective values.

### SSH-03

- **Control ID:** 5.1.5
- **Objective:** Verify effective SSH banner.
- **Preconditions:** OpenSSH installed; banner file exists.
- **Test Commands:** `sudo sshd -T | grep '^banner '`; audit Sections 01 and 03.
- **Expected Result:** Both audits read the same effective value as `SSH_BANNER_FILE`.
- **Pass Criteria:** Both pass with identical path.
- **Fail Criteria:** Either section reports mismatch.

### SSH-04

- **Control ID:** 5.1.7
- **Objective:** Verify ClientAlive values.
- **Preconditions:** OpenSSH installed.
- **Test Commands:** `sudo sshd -T | grep -E '^clientalive(interval|countmax) '`; audit.
- **Expected Result:** Values equal config.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Either value differs.

### SSH-05

- **Control ID:** 5.1.11
- **Objective:** Verify IgnoreRhosts.
- **Preconditions:** OpenSSH installed.
- **Test Commands:** `sudo sshd -T | grep '^ignorerhosts '`; audit.
- **Expected Result:** Value equals config.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Value differs or audit reports unset while sshd reports a value.

### SSH-06

- **Control ID:** 5.1.14
- **Objective:** Verify LogLevel.
- **Preconditions:** OpenSSH installed.
- **Test Commands:** `sudo sshd -T | grep '^loglevel '`; audit.
- **Expected Result:** Value equals config.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Value differs or case mismatch causes false failure.

### SSH-07

- **Control ID:** 5.1.16-.18
- **Objective:** Verify MaxAuthTries, MaxStartups, MaxSessions.
- **Preconditions:** OpenSSH installed.
- **Test Commands:** `sudo sshd -T | grep -E '^(maxauthtries|maxstartups|maxsessions) '`; audit.
- **Expected Result:** Values meet configured thresholds.
- **Pass Criteria:** All pass.
- **Fail Criteria:** Any differs or exceeds threshold.

### SSH-08

- **Control ID:** 5.1.20-.21
- **Objective:** Verify root login and user-environment settings.
- **Preconditions:** OpenSSH installed.
- **Test Commands:** `sudo sshd -T | grep -E '^(permitrootlogin|permituserenvironment) '`; audit.
- **Expected Result:** Values equal config.
- **Pass Criteria:** Both pass.
- **Fail Criteria:** Either differs.

### SSH-09

- **Control ID:** SSH-HARDEN
- **Objective:** Verify empty-password, TCP/agent forwarding, and X11 settings.
- **Preconditions:** OpenSSH installed.
- **Test Commands:** `sudo sshd -T | grep -E '^(permitemptypasswords|allowtcpforwarding|allowagentforwarding|x11forwarding) '`; audit.
- **Expected Result:** Values equal config.
- **Pass Criteria:** All pass.
- **Fail Criteria:** Any differs or is falsely reported unset.

### SSH-10

- **Control ID:** 5.1.23
- **Objective:** Verify supported hybrid key exchange configuration.
- **Preconditions:** OpenSSH build exposes a supported algorithm.
- **Test Commands:** `ssh -Q kex`; `sudo sshd -T | grep '^kexalgorithms '`; audit.
- **Expected Result:** Supported algorithm is configured.
- **Pass Criteria:** Available algorithm is effective.
- **Fail Criteria:** Available algorithm omitted; unsupported build is manual/warning.

## PAM and Accounts

### PAM-01

- **Control ID:** 5.3.2.2
- **Objective:** Verify faillock preauth/authfail/authsucc/account rules.
- **Preconditions:** Root; PAM files exist.
- **Test Commands:** `grep -n pam_faillock /etc/pam.d/common-auth /etc/pam.d/common-account`; audit.
- **Expected Result:** Rules are present in required order.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Rule missing or misordered.

### PAM-02

- **Control ID:** 5.3.3.1.1-.3
- **Objective:** Verify deny, unlock time, and failure interval.
- **Preconditions:** faillock.conf exists.
- **Test Commands:** `grep -E '^(deny|unlock_time|fail_interval)' /etc/security/faillock.conf`; audit.
- **Expected Result:** Values equal config.
- **Pass Criteria:** All pass.
- **Fail Criteria:** Missing/mismatched value.

### PAM-03

- **Control ID:** 5.3.3.2.1-.6
- **Objective:** Verify pwquality package, active PAM module, and policy.
- **Preconditions:** Root; apt repositories reachable.
- **Test Commands:** `dpkg-query -W libpam-pwquality`; `grep -nE 'pam_pwquality|pam_unix' /etc/pam.d/common-password`; inspect pwquality.conf; audit.
- **Expected Result:** Module precedes pam_unix and configured values match.
- **Pass Criteria:** Package/module/order/policy all pass.
- **Fail Criteria:** Module absent, after pam_unix, or values differ.

### PAM-04

- **Control ID:** 5.3.3.2.8
- **Objective:** Verify root password quality policy.
- **Preconditions:** Root account exists.
- **Test Commands:** `getent shadow root`; inspect pwquality settings; audit.
- **Expected Result:** Locked root is accepted; otherwise global policy applies.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Unlocked root lacks quality policy.

### PAM-05

- **Control ID:** 5.3.3.3.2
- **Objective:** Verify root password history.
- **Preconditions:** PAM password stack exists.
- **Test Commands:** `grep pam_pwhistory /etc/pam.d/common-password`; audit.
- **Expected Result:** remember matches and enforce_for_root exists.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Either option missing/mismatched.

### PAM-06

- **Control ID:** 5.3.3.4.1
- **Objective:** Verify pam_unix nullok is absent.
- **Preconditions:** PAM files exist.
- **Test Commands:** `grep -nE 'pam_unix.*nullok' /etc/pam.d/common-*`; audit.
- **Expected Result:** No active nullok option.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Active nullok found.

### PASS-01

- **Control ID:** 5.4.1.1-.3
- **Objective:** Verify password age defaults and existing accounts.
- **Preconditions:** At least one interactive account.
- **Test Commands:** Inspect PASS_MAX_DAYS/PASS_MIN_DAYS/PASS_WARN_AGE; `chage -l USER`; audit.
- **Expected Result:** Defaults and existing account aging match policy.
- **Pass Criteria:** All pass.
- **Fail Criteria:** Missing/mismatched value.

### PASS-02

- **Control ID:** 5.4.1.5
- **Objective:** Verify inactive lock for existing accounts and new accounts.
- **Preconditions:** Root; useradd/getent available.
- **Test Commands:** `useradd -D`; `getent shadow ubuntu | cut -d: -f7`; audit.
- **Expected Result:** INACTIVE default and account shadow field 7 equal configured days.
- **Pass Criteria:** Both values equal policy.
- **Fail Criteria:** Default unset/wrong or eligible account field 7 differs; do not compare against chage's formatted date.

### PASS-03

- **Control ID:** 5.4.2.5
- **Objective:** Verify root PATH including symlinks.
- **Preconditions:** Root PATH includes standard directories.
- **Test Commands:** `printf '%s\n' "$PATH"`; `readlink -f /bin /sbin`; audit.
- **Expected Result:** Resolved directories root-owned and not group/other writable.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Empty/relative/unsafe resolved component.

### PASS-04

- **Control ID:** 5.4.3.3
- **Objective:** Verify configured default umask.
- **Preconditions:** Login files exist.
- **Test Commands:** Inspect UMASK in login.defs and system profile; audit.
- **Expected Result:** Effective value matches config without conflicting settings.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Missing/conflicting setting.

### ACCT-01

- **Control ID:** ACCOUNT-EMPTY-PASSWORD, ACCOUNT-UID0
- **Objective:** Verify no empty password hash and only root UID 0.
- **Preconditions:** Root.
- **Test Commands:** Inspect `/etc/shadow` empty hashes and `/etc/passwd` UID 0 entries; audit.
- **Expected Result:** No empty hashes; root is sole UID 0.
- **Pass Criteria:** Both pass.
- **Fail Criteria:** Empty hash or extra UID 0.

## Logging, Audit, and Permissions

### LOG-01

- **Control ID:** 6.1.2.4
- **Objective:** Verify rsyslog service and facilities.
- **Preconditions:** Rsyslog enabled in config.
- **Test Commands:** `systemctl is-enabled rsyslog`; `systemctl is-active rsyslog`; `rsyslogd -N1`; audit.
- **Expected Result:** Service healthy and configured facility destinations exist.
- **Pass Criteria:** All checks pass.
- **Fail Criteria:** Service/config/facility failure.

### LOG-02

- **Control ID:** 6.1.2.5
- **Objective:** Verify remote syslog destination.
- **Preconditions:** Remote logging enabled and host configured.
- **Test Commands:** Inspect `/etc/rsyslog.d/99-cis-hardening.conf`; `rsyslogd -N1`; audit.
- **Expected Result:** Exact protocol/host/port rule present.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Missing/wrong rule or parser failure.

### LOG-03

- **Control ID:** 6.1.3.1
- **Objective:** Verify log file/directory ownership and write bits.
- **Preconditions:** Logging services installed.
- **Test Commands:** `find /var/log -maxdepth 2 -type f -exec stat -c '%U:%G %a %n' {} +`; audit.
- **Expected Result:** Root-owned; no group/other write.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Unsafe owner or write bits.

### AUDIT-01

- **Control ID:** 6.2-AUDITD
- **Objective:** Verify auditd installation and service.
- **Preconditions:** Auditd enabled; Ubuntu kernel supports it.
- **Test Commands:** `dpkg-query -W auditd`; `systemctl is-enabled auditd`; `systemctl is-active auditd`; audit.
- **Expected Result:** Installed, enabled, active.
- **Pass Criteria:** Audit passes.
- **Fail Criteria:** Package or service state incorrect.

### AUDIT-02

- **Control ID:** 6.2-RULES
- **Objective:** Verify applicable audit rules and loading.
- **Preconditions:** auditd and rules.d available; watched paths exist.
- **Test Commands:** `grep -R -F -x --include='*.rules' -- '-w /etc/passwd -p wa -k identity' /etc/audit/rules.d`; `sudo augenrules --check`; audit.
- **Expected Result:** Rules for existing paths are present and loadable; absent paths are SKIP.
- **Pass Criteria:** All applicable checks pass.
- **Fail Criteria:** Existing-path rule missing or rules fail to load.

### AUDIT-03

- **Control ID:** 6.2-AUDITD-CONFIG
- **Objective:** Verify audit retention and disk actions.
- **Preconditions:** auditd.conf exists.
- **Test Commands:** Inspect max_log_file_action, space_left_action, admin_space_left_action; audit.
- **Expected Result:** keep_logs/email/halt policy configured.
- **Pass Criteria:** All required keys pass.
- **Fail Criteria:** Key missing or invalid.

### PERM-01

- **Control ID:** 7.1.1-.8
- **Objective:** Verify account database file permissions.
- **Preconditions:** Ubuntu shadow group exists.
- **Test Commands:** `stat -c '%U:%G %a %n' /etc/passwd /etc/group /etc/shadow /etc/gshadow`; audit.
- **Expected Result:** passwd/group root:root 0644; shadow/gshadow root:shadow 0640.
- **Pass Criteria:** All existing files pass.
- **Fail Criteria:** Owner or mode mismatch.

### SUDO-01

- **Control ID:** Sudo permissions
- **Objective:** Verify sudoers ownership, modes, and syntax.
- **Preconditions:** visudo installed.
- **Test Commands:** `stat -c '%U:%G %a' /etc/sudoers /etc/sudoers.d`; `visudo -c`; audit.
- **Expected Result:** Files root:root 0440, directory root:root 0750, syntax valid.
- **Pass Criteria:** All checks pass.
- **Fail Criteria:** Unsafe permissions or syntax error.

### WW-01

- **Control ID:** 7.1.11
- **Objective:** Verify world-writable files and non-sticky directories.
- **Preconditions:** Root; mounted filesystems accessible.
- **Test Commands:** Run the project's `find_world_writable_files` and `find_world_writable_directories`; inspect report; audit.
- **Expected Result:** Findings reported across mounted filesystems; virtual trees pruned; sticky shared dirs excluded.
- **Pass Criteria:** No unapproved findings.
- **Fail Criteria:** Findings are missed or unauthorized objects remain.

### TMP-01

- **Control ID:** Temporary directory permissions
- **Objective:** Verify shared temp directory modes.
- **Preconditions:** Root.
- **Test Commands:** `stat -c '%a %n' /tmp /var/tmp /dev/shm`; audit.
- **Expected Result:** Existing directories mode 1777.
- **Pass Criteria:** All existing paths pass.
- **Fail Criteria:** Any existing path differs.

### CRON-01

- **Control ID:** Cron permissions
- **Objective:** Verify cron object owners and write bits.
- **Preconditions:** Cron paths may be absent.
- **Test Commands:** Inspect `/etc/crontab` and `/etc/cron.*` ownership/modes; audit.
- **Expected Result:** Existing objects root-owned and not group/other writable.
- **Pass Criteria:** All existing objects pass.
- **Fail Criteria:** Unsafe existing object.

### SSH-PERM-01

- **Control ID:** SSH directory permissions
- **Objective:** Verify SSH config directories/files.
- **Preconditions:** OpenSSH installed.
- **Test Commands:** `find /etc/ssh/sshd_config.d -type f -exec stat -c '%U:%G %a %n' {} +`; audit.
- **Expected Result:** Root-owned and not group/other writable.
- **Pass Criteria:** All checks pass.
- **Fail Criteria:** Unsafe ownership/mode.

### FLOW-01

- **Control ID:** All configured controls
- **Objective:** Verify backup, remediation, validation, final audit, report, and idempotency.
- **Preconditions:** Disposable Ubuntu 24.04 VM; root; rollback snapshot.
- **Test Commands:** Run `sudo ./hardening.sh remediate` twice, then `sudo ./hardening.sh audit`; inspect report and backup directory.
- **Expected Result:** All sections execute; repeated remediation is stable; final audit/report produced.
- **Pass Criteria:** Accurate counters and report exist.
- **Fail Criteria:** Silent section skip, hidden error, duplicate config, or missing report.

### TEST-01

- **Control ID:** Test suite
- **Objective:** Verify automated checks and saved evidence.
- **Preconditions:** Bash available.
- **Test Commands:** `sudo bash tests/run_tests.sh`.
- **Expected Result:** PASS/FAIL/SKIP output and `tests/test_report.txt`.
- **Pass Criteria:** Report contains summary totals.
- **Fail Criteria:** Report missing, checks hidden, or summary absent.
