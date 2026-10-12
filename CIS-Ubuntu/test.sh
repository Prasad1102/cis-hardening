#!/usr/bin/env bash
# ============================================================
# CIS Ubuntu 24.04 LTS - Comprehensive Local Test Runner
#
# Place this file in the project root, beside hardening.sh.
#
# Usage:
#   chmod +x test.sh
#   ./test.sh                 # static + live read-only checks
#   sudo ./test.sh --audit    # also runs hardening.sh audit
#
# SAFETY:
# - Never runs remediation.
# - Never changes system settings.
# - Tests the local host only.
# - Ubuntu-specific controls are tested here; checks for other
#   OSs/benchmarks in the multi-server Nessus PDF are not treated
#   as Ubuntu controls.
# - Manual/site-specific controls are reported as SKIP.
# ============================================================

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HARDENING="$ROOT/hardening.sh"
CONFIG="$ROOT/cis.conf"
COMMON="$ROOT/lib/common.sh"
SECTIONS="$ROOT/sections"
SYSCTL_DROPIN="/etc/sysctl.d/99-cis-hardening.conf"
RUN_AUDIT=no

PASS=0
FAIL=0
SKIP=0
TOTAL=0

for arg in "$@"; do
    case "$arg" in
        --audit) RUN_AUDIT=yes ;;
        --help|-h)
            cat <<'HELP'
Usage:
  ./test.sh
  sudo ./test.sh --audit

This script runs read-only tests and does not run remediation.
--audit additionally invokes ./hardening.sh audit.
HELP
            exit 0
            ;;
        *)
            printf '[ERROR] Unknown option: %s\n' "$arg" >&2
            exit 2
            ;;
    esac
done

section() {
    printf '\n============================================================\n%s\n============================================================\n' "$1"
}

test_owner_root_shadow() {
    local path="$1" label="$2" owner
    if [[ ! -e "$path" ]]; then
        bad "$label (path missing)"
        return
    fi
    owner="$(stat -c '%U:%G' "$path" 2>/dev/null || true)"
    if [[ "$owner" == "root:shadow" ]]; then
        ok "$label owner=root:shadow"
    else
        bad "$label owner='${owner:-unknown}', expected root:shadow"
    fi
}

ok()   { printf '[PASS] %s\n' "$1"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
bad()  { printf '[FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }
skip() { printf '[SKIP] %s\n' "$1"; SKIP=$((SKIP+1)); TOTAL=$((TOTAL+1)); }

test_file() {
    local path="$1" desc="$2"
    [[ -f "$path" ]] && ok "$desc" || bad "$desc"
}

test_dir() {
    local path="$1" desc="$2"
    [[ -d "$path" ]] && ok "$desc" || bad "$desc"
}

test_pattern() {
    local path="$1" pattern="$2" desc="$3"
    if [[ -f "$path" ]] && grep -Eq -- "$pattern" "$path"; then
        ok "$desc"
    else
        bad "$desc"
    fi
}

test_function() {
    local path="$1" fn="$2"
    if [[ -f "$path" ]] && grep -Eq "^[[:space:]]*${fn}[[:space:]]*\\(\\)[[:space:]]*\\{" "$path"; then
        ok "Function $fn exists"
    else
        bad "Function $fn exists in ${path#"$ROOT"/}"
    fi
}

test_syntax() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        bad "Shell syntax: ${path#"$ROOT"/} (file missing)"
    elif bash -n "$path"; then
        ok "Shell syntax: ${path#"$ROOT"/}"
    else
        bad "Shell syntax: ${path#"$ROOT"/}"
    fi
}

test_sysctl() {
    local key="$1" expected="$2" label="${3:-$1}" actual
    if ! command -v sysctl >/dev/null 2>&1; then
        skip "$label (sysctl unavailable)"
        return
    fi
    actual="$(sysctl -n "$key" 2>/dev/null || true)"
    if [[ "$actual" == "$expected" ]]; then
        ok "$label runtime value=$expected"
    else
        bad "$label runtime value='${actual:-unavailable}', expected=$expected"
    fi
}

test_sysctl_persisted() {
    local key="$1" expected="$2" label="${3:-$1}" actual=""
    local f
    # sysctl settings may be in the CIS drop-in or another sysctl file.
    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf; do
        [[ -f "$f" ]] || continue
        local line
        line="$(awk -v k="$key" '
            /^[[:space:]]*#/ {next}
            {
              key=$1
              gsub(/[[:space:]]*=[[:space:]]*/, " ", $0)
              if ($1 == k) value=$2
            }
            END {if (value != "") print value}
        ' "$f" 2>/dev/null)"
        [[ -n "$line" ]] && actual="$line"
    done
    if [[ "$actual" == "$expected" ]]; then
        ok "$label persisted value=$expected"
    else
        bad "$label persisted value='${actual:-unset}', expected=$expected"
    fi
}

test_package_absent() {
    local pkg="$1"
    if ! command -v dpkg-query >/dev/null 2>&1; then
        skip "Package absence check: $pkg (dpkg-query unavailable)"
        return
    fi
    local status
    status="$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)"
    if [[ "$status" == "install ok installed" ]]; then
        bad "Package should be absent: $pkg"
    else
        ok "Package absent: $pkg"
    fi
}

test_service_enabled() {
    local svc="$1"
    if ! command -v systemctl >/dev/null 2>&1; then
        skip "Service check: $svc (systemctl unavailable)"
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        ok "Service enabled: $svc"
    else
        bad "Service enabled: $svc"
    fi
}

test_service_active() {
    local svc="$1"
    if ! command -v systemctl >/dev/null 2>&1; then
        skip "Service check: $svc (systemctl unavailable)"
    elif systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "Service active: $svc"
    else
        bad "Service active: $svc"
    fi
}

test_mode() {
    local path="$1" expected="$2" label="$3" actual
    if [[ ! -e "$path" ]]; then
        bad "$label (path missing: $path)"
        return
    fi
    actual="$(stat -c '%a' "$path" 2>/dev/null || true)"
    if [[ "$actual" == "$expected" ]]; then
        ok "$label mode=$expected"
    else
        bad "$label mode='${actual:-unknown}', expected=$expected"
    fi
}

test_owner_root() {
    local path="$1" label="$2" owner
    if [[ ! -e "$path" ]]; then
        bad "$label (path missing)"
        return
    fi
    owner="$(stat -c '%U:%G' "$path" 2>/dev/null || true)"
    if [[ "$owner" == "root:root" ]]; then
        ok "$label owner=root:root"
    else
        bad "$label owner='${owner:-unknown}', expected root:root"
    fi
}

# ============================================================
# GROUP 1: PROJECT STRUCTURE (12+ individual cases)
# ============================================================
section "GROUP 1 - PROJECT STRUCTURE"

test_file "$HARDENING" "Root hardening.sh exists"
test_file "$CONFIG" "Root cis.conf exists"
test_file "$ROOT/README.md" "Root README.md exists"
test_file "$ROOT/test.sh" "Root test.sh exists"
test_dir "$ROOT/lib" "lib directory exists"
test_file "$COMMON" "lib/common.sh exists"
test_dir "$SECTIONS" "sections directory exists"
test_file "$SECTIONS/01_filesystem_boot.sh" "Section 01 exists"
test_file "$SECTIONS/02_services_network.sh" "Section 02 exists"
test_file "$SECTIONS/03_firewall_ssh.sh" "Section 03 exists"
test_file "$SECTIONS/04_pam_accounts.sh" "Section 04 exists"
test_file "$SECTIONS/05_logging_audit.sh" "Section 05 exists"
test_file "$SECTIONS/06_permissions.sh" "Section 06 exists"

# ============================================================
# GROUP 2: SHELL SYNTAX (9 individual cases)
# ============================================================
section "GROUP 2 - SHELL SYNTAX"

test_syntax "$HARDENING"
test_syntax "$COMMON"
test_syntax "$CONFIG"
test_syntax "$SECTIONS/01_filesystem_boot.sh"
test_syntax "$SECTIONS/02_services_network.sh"
test_syntax "$SECTIONS/03_firewall_ssh.sh"
test_syntax "$SECTIONS/04_pam_accounts.sh"
test_syntax "$SECTIONS/05_logging_audit.sh"
test_syntax "$SECTIONS/06_permissions.sh"
test_syntax "$ROOT/test.sh"

# ============================================================
# GROUP 3: CORE FUNCTION COVERAGE (24 individual cases)
# ============================================================
section "GROUP 3 - CORE FUNCTION COVERAGE"

for fn in audit_pass audit_fail audit_warning audit_skip start_section end_section require_root command_exists install_package remove_package backup_file set_file_permissions set_sysctl_value get_sysctl_value get_mount_options package_installed validate_sshd; do
    test_function "$COMMON" "$fn"
done

test_pattern "$HARDENING" 'audit' "Main script contains audit mode"
test_pattern "$HARDENING" 'remediate' "Main script contains remediation mode"
test_pattern "$HARDENING" 'verify' "Main script contains verification mode"
test_pattern "$HARDENING" 'load_configuration' "Main script loads configuration"
test_pattern "$HARDENING" 'check_section_syntax' "Main script checks section syntax"
test_pattern "$HARDENING" 'preflight_checks' "Main script has preflight checks"
test_pattern "$HARDENING" 'run_audit' "Main script has audit runner"
test_pattern "$HARDENING" 'run_remediation' "Main script has remediation runner"

# ============================================================
# GROUP 4: SECTION ENTRY POINTS (18 individual cases)
# ============================================================
section "GROUP 4 - SECTION ENTRY POINTS"

test_function "$SECTIONS/01_filesystem_boot.sh" "section_01_filesystem_boot"
test_function "$SECTIONS/01_filesystem_boot.sh" "audit_01_filesystem_boot"
test_function "$SECTIONS/01_filesystem_boot.sh" "remediate_01_filesystem_boot"
test_function "$SECTIONS/02_services_network.sh" "section_02_services_network"
test_function "$SECTIONS/02_services_network.sh" "audit_02_services_network"
test_function "$SECTIONS/02_services_network.sh" "remediate_02_services_network"
test_function "$SECTIONS/02_services_network.sh" "audit_ipv4_settings"
test_function "$SECTIONS/02_services_network.sh" "remediate_ipv4_settings"
test_function "$SECTIONS/02_services_network.sh" "audit_ipv6_settings"
test_function "$SECTIONS/02_services_network.sh" "remediate_ipv6_settings"
test_function "$SECTIONS/03_firewall_ssh.sh" "section_03_firewall_ssh"
test_function "$SECTIONS/03_firewall_ssh.sh" "section_03_audit"
test_function "$SECTIONS/03_firewall_ssh.sh" "section_03_remediate"
test_function "$SECTIONS/04_pam_accounts.sh" "section_04_pam_accounts"
test_function "$SECTIONS/04_pam_accounts.sh" "section_04_audit"
test_function "$SECTIONS/04_pam_accounts.sh" "section_04_remediate"
test_function "$SECTIONS/05_logging_audit.sh" "section_05_logging_audit"
test_function "$SECTIONS/06_permissions.sh" "audit_section_06"

# ============================================================
# GROUP 5: OS / EXECUTION PREREQUISITES
# ============================================================
section "GROUP 5 - OS AND PREREQUISITES"

if [[ -r /etc/os-release ]]; then
    # The project targets Ubuntu 24.04 specifically.
    . /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] && ok "Host OS is Ubuntu" || bad "Host OS is Ubuntu (found ${ID:-unknown})"
    [[ "${VERSION_ID:-}" == "24.04" ]] && ok "Host version is Ubuntu 24.04" || bad "Host version is Ubuntu 24.04 (found ${VERSION_ID:-unknown})"
else
    bad "/etc/os-release is readable"
fi

for cmd in bash grep awk sed stat sysctl; do
    command -v "$cmd" >/dev/null 2>&1 && ok "Required command available: $cmd" || bad "Required command available: $cmd"
done

if [[ $EUID -eq 0 ]]; then
    ok "Tests are running as root"
else
    skip "Not root: read-only tests continue; some permission/service results may be restricted"
fi

# ============================================================
# GROUP 6: CONFIGURATION VALUE TESTS
# ============================================================
section "GROUP 6 - CONFIGURATION VALUES"

test_pattern "$CONFIG" '^[[:space:]]*NET_IPV4_ALL_LOG_MARTIANS[[:space:]]*=[[:space:]]*["]?1["]?([[:space:]]|$|#)' "Config sets all.log_martians=1"
test_pattern "$CONFIG" '^[[:space:]]*NET_IPV4_DEFAULT_LOG_MARTIANS[[:space:]]*=[[:space:]]*["]?1["]?([[:space:]]|$|#)' "Config sets default.log_martians=1"
test_pattern "$CONFIG" '^[[:space:]]*SSH_MAX_AUTH_TRIES[[:space:]]*=' "Config defines SSH_MAX_AUTH_TRIES"
test_pattern "$CONFIG" '^[[:space:]]*SSH_MAX_SESSIONS[[:space:]]*=' "Config defines SSH_MAX_SESSIONS"
test_pattern "$CONFIG" '^[[:space:]]*SSH_MAX_STARTUPS[[:space:]]*=' "Config defines SSH_MAX_STARTUPS"
test_pattern "$CONFIG" '^[[:space:]]*SSH_CLIENT_ALIVE_INTERVAL[[:space:]]*=' "Config defines SSH_CLIENT_ALIVE_INTERVAL"
test_pattern "$CONFIG" '^[[:space:]]*SSH_CLIENT_ALIVE_COUNT_MAX[[:space:]]*=' "Config defines SSH_CLIENT_ALIVE_COUNT_MAX"
test_pattern "$CONFIG" '^[[:space:]]*SSH_PERMIT_ROOT_LOGIN[[:space:]]*=' "Config defines SSH_PERMIT_ROOT_LOGIN"
test_pattern "$CONFIG" '^[[:space:]]*SSH_PERMIT_EMPTY_PASSWORDS[[:space:]]*=' "Config defines SSH_PERMIT_EMPTY_PASSWORDS"
test_pattern "$CONFIG" '^[[:space:]]*SSH_PERMIT_USER_ENVIRONMENT[[:space:]]*=' "Config defines SSH_PERMIT_USER_ENVIRONMENT"
test_pattern "$CONFIG" '^[[:space:]]*PASSWORD_MAX_DAYS[[:space:]]*=' "Config defines password maximum age"
test_pattern "$CONFIG" '^[[:space:]]*PASSWORD_MIN_LENGTH[[:space:]]*=' "Config defines minimum password length"
test_pattern "$CONFIG" '^[[:space:]]*FAILLOCK_DENY[[:space:]]*=' "Config defines failed-login deny threshold"
test_pattern "$CONFIG" '^[[:space:]]*DEFAULT_UMASK[[:space:]]*=' "Config defines default umask"
test_pattern "$CONFIG" '^[[:space:]]*UFW_ALLOWED_TCP_PORTS[[:space:]]*=' "Config defines allowed UFW TCP ports"
test_pattern "$CONFIG" '^[[:space:]]*REMOTE_SYSLOG_ENABLED[[:space:]]*=' "Config defines remote syslog policy"
test_pattern "$CONFIG" '^[[:space:]]*GRUB_SUPERUSER[[:space:]]*=' "Config defines GRUB superuser"
test_pattern "$CONFIG" '^[[:space:]]*GRUB_PASSWORD_HASH[[:space:]]*=' "Config defines GRUB password hash setting"

# ============================================================
# GROUP 7: IPV4 NETWORK CONTROLS - RUNTIME (13 cases)
# ============================================================
section "GROUP 7 - IPV4 NETWORK RUNTIME"

test_sysctl net.ipv4.conf.all.send_redirects 0 "3.3.1.4 all.send_redirects"
test_sysctl net.ipv4.conf.default.send_redirects 0 "3.3.1.5 default.send_redirects"
test_sysctl net.ipv4.conf.all.accept_redirects 0 "3.3.1.8 all.accept_redirects"
test_sysctl net.ipv4.conf.default.accept_redirects 0 "3.3.1.9 default.accept_redirects"
test_sysctl net.ipv4.conf.all.secure_redirects 0 "3.3.1.10 all.secure_redirects"
test_sysctl net.ipv4.conf.default.secure_redirects 0 "3.3.1.11 default.secure_redirects"
test_sysctl net.ipv4.conf.all.rp_filter 1 "3.3.1.12 all.rp_filter"
test_sysctl net.ipv4.conf.default.rp_filter 1 "3.3.1.13 default.rp_filter"
test_sysctl net.ipv4.conf.all.accept_source_route 0 "3.3.1.14 all.accept_source_route"
test_sysctl net.ipv4.conf.default.accept_source_route 0 "3.3.1.15 default.accept_source_route"
test_sysctl net.ipv4.conf.all.log_martians 1 "3.3.1.16 all.log_martians"
test_sysctl net.ipv4.conf.default.log_martians 1 "3.3.1.17 default.log_martians"
test_sysctl net.ipv4.tcp_syncookies 1 "3.3.1.18 tcp_syncookies"

# ============================================================
# GROUP 8: IPV4 NETWORK PERSISTENCE (13 cases)
# ============================================================
section "GROUP 8 - IPV4 NETWORK PERSISTENCE"

test_sysctl_persisted net.ipv4.conf.all.send_redirects 0 "3.3.1.4 all.send_redirects"
test_sysctl_persisted net.ipv4.conf.default.send_redirects 0 "3.3.1.5 default.send_redirects"
test_sysctl_persisted net.ipv4.conf.all.accept_redirects 0 "3.3.1.8 all.accept_redirects"
test_sysctl_persisted net.ipv4.conf.default.accept_redirects 0 "3.3.1.9 default.accept_redirects"
test_sysctl_persisted net.ipv4.conf.all.secure_redirects 0 "3.3.1.10 all.secure_redirects"
test_sysctl_persisted net.ipv4.conf.default.secure_redirects 0 "3.3.1.11 default.secure_redirects"
test_sysctl_persisted net.ipv4.conf.all.rp_filter 1 "3.3.1.12 all.rp_filter"
test_sysctl_persisted net.ipv4.conf.default.rp_filter 1 "3.3.1.13 default.rp_filter"
test_sysctl_persisted net.ipv4.conf.all.accept_source_route 0 "3.3.1.14 all.accept_source_route"
test_sysctl_persisted net.ipv4.conf.default.accept_source_route 0 "3.3.1.15 default.accept_source_route"
test_sysctl_persisted net.ipv4.conf.all.log_martians 1 "3.3.1.16 all.log_martians"
test_sysctl_persisted net.ipv4.conf.default.log_martians 1 "3.3.1.17 default.log_martians"
test_sysctl_persisted net.ipv4.tcp_syncookies 1 "3.3.1.18 tcp_syncookies"

# ============================================================
# GROUP 9: IPV6 NETWORK CONTROLS (8 runtime + 8 persistence)
# ============================================================
section "GROUP 9 - IPV6 NETWORK CONTROLS"

test_sysctl net.ipv6.conf.all.forwarding 0 "3.3.2.1 IPv6 all.forwarding"
test_sysctl net.ipv6.conf.default.forwarding 0 "3.3.2.2 IPv6 default.forwarding"
test_sysctl net.ipv6.conf.all.accept_redirects 0 "3.3.2.3 IPv6 all.accept_redirects"
test_sysctl net.ipv6.conf.default.accept_redirects 0 "3.3.2.4 IPv6 default.accept_redirects"
test_sysctl net.ipv6.conf.all.accept_source_route 0 "3.3.2.5 IPv6 all.accept_source_route"
test_sysctl net.ipv6.conf.default.accept_source_route 0 "3.3.2.6 IPv6 default.accept_source_route"
test_sysctl net.ipv6.conf.all.accept_ra 0 "3.3.2.7 IPv6 all.accept_ra"
test_sysctl net.ipv6.conf.default.accept_ra 0 "3.3.2.8 IPv6 default.accept_ra"

test_sysctl_persisted net.ipv6.conf.all.forwarding 0 "3.3.2.1 IPv6 all.forwarding"
test_sysctl_persisted net.ipv6.conf.default.forwarding 0 "3.3.2.2 IPv6 default.forwarding"
test_sysctl_persisted net.ipv6.conf.all.accept_redirects 0 "3.3.2.3 IPv6 all.accept_redirects"
test_sysctl_persisted net.ipv6.conf.default.accept_redirects 0 "3.3.2.4 IPv6 default.accept_redirects"
test_sysctl_persisted net.ipv6.conf.all.accept_source_route 0 "3.3.2.5 IPv6 all.accept_source_route"
test_sysctl_persisted net.ipv6.conf.default.accept_source_route 0 "3.3.2.6 IPv6 default.accept_source_route"
test_sysctl_persisted net.ipv6.conf.all.accept_ra 0 "3.3.2.7 IPv6 all.accept_ra"
test_sysctl_persisted net.ipv6.conf.default.accept_ra 0 "3.3.2.8 IPv6 default.accept_ra"

# ============================================================
# GROUP 10: UNNECESSARY CLIENTS / MODULES
# ============================================================
section "GROUP 10 - CLIENT PACKAGES AND MODULES"

test_package_absent telnet
test_package_absent ftp
test_package_absent inetutils-ftp

for mod in atm can sctp tipc; do
    if ! command -v modinfo >/dev/null 2>&1; then
        skip "Kernel module $mod availability (modinfo unavailable)"
    elif ! modinfo "$mod" >/dev/null 2>&1; then
        ok "Kernel module not available: $mod"
    elif grep -RqsE "^[[:space:]]*(blacklist|install)[[:space:]]+$mod([[:space:]]|$)" /etc/modprobe.d/ 2>/dev/null; then
        if lsmod | awk '{print $1}' | grep -qx "$mod"; then
            bad "Kernel module $mod is blacklisted but still loaded"
        else
            ok "Kernel module $mod is restricted and not loaded"
        fi
    else
        bad "Kernel module $mod exists but has no blacklist/install restriction"
    fi
done

# ============================================================
# GROUP 11: SSH EFFECTIVE CONFIGURATION (15 cases)
# ============================================================
section "GROUP 11 - SSH EFFECTIVE CONFIGURATION"

if command -v sshd >/dev/null 2>&1; then
    SSHD="$(sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null || true)"
    ssh_value() { printf '%s\n' "$SSHD" | awk -v k="$1" '$1==k {print $2; exit}'; }

    [[ -n "$SSHD" ]] || { bad "sshd -T returns effective configuration"; SSHD=""; }

    [[ "$(ssh_value maxauthtries)" == "3" ]] && ok "5.1.16 MaxAuthTries=3" || bad "5.1.16 MaxAuthTries expected 3, got $(ssh_value maxauthtries)"
    [[ "$(ssh_value maxsessions)" == "10" ]] && ok "5.1.18 MaxSessions=10" || bad "5.1.18 MaxSessions expected 10, got $(ssh_value maxsessions)"
    [[ "$(ssh_value maxstartups)" == "10:30:60" ]] && ok "5.1.17 MaxStartups=10:30:60" || bad "5.1.17 MaxStartups expected 10:30:60, got $(ssh_value maxstartups)"
    [[ "$(ssh_value clientaliveinterval)" == "15" ]] && ok "5.1.7 ClientAliveInterval=15" || bad "5.1.7 ClientAliveInterval expected 15, got $(ssh_value clientaliveinterval)"
    [[ "$(ssh_value clientalivecountmax)" == "3" ]] && ok "5.1.7 ClientAliveCountMax=3" || bad "5.1.7 ClientAliveCountMax expected 3, got $(ssh_value clientalivecountmax)"
    [[ "$(ssh_value permitrootlogin)" == "no" ]] && ok "5.1.20 PermitRootLogin=no" || bad "5.1.20 PermitRootLogin expected no, got $(ssh_value permitrootlogin)"
    [[ "$(ssh_value permitemptypasswords)" == "no" ]] && ok "PermitEmptyPasswords=no" || bad "PermitEmptyPasswords expected no, got $(ssh_value permitemptypasswords)"
    [[ "$(ssh_value permituserenvironment)" == "no" ]] && ok "5.1.21 PermitUserEnvironment=no" || bad "5.1.21 PermitUserEnvironment expected no, got $(ssh_value permituserenvironment)"
    [[ "$(ssh_value ignorerhosts)" == "yes" ]] && ok "5.1.11 IgnoreRhosts=yes" || bad "5.1.11 IgnoreRhosts expected yes, got $(ssh_value ignorerhosts)"
    [[ "$(ssh_value loglevel)" == "VERBOSE" ]] && ok "5.1.14 LogLevel=VERBOSE" || bad "5.1.14 LogLevel expected VERBOSE, got $(ssh_value loglevel)"
    [[ "$(ssh_value banner)" == "/etc/issue.net" ]] && ok "5.1.5 Banner=/etc/issue.net" || bad "5.1.5 Banner expected /etc/issue.net, got $(ssh_value banner)"
    [[ "$(ssh_value x11forwarding)" == "no" ]] && ok "SSH X11 forwarding disabled" || bad "SSH X11 forwarding expected no, got $(ssh_value x11forwarding)"
    [[ "$(ssh_value allowtcpforwarding)" == "no" ]] && ok "SSH TCP forwarding disabled" || bad "SSH TCP forwarding expected no, got $(ssh_value allowtcpforwarding)"
    [[ "$(ssh_value allowagentforwarding)" == "no" ]] && ok "SSH agent forwarding disabled" || bad "SSH agent forwarding expected no, got $(ssh_value allowagentforwarding)"
    if sshd -t 2>/dev/null; then ok "sshd configuration syntax is valid"; else bad "sshd configuration syntax is valid"; fi
else
    for n in {1..15}; do skip "SSH effective configuration check $n (sshd unavailable)"; done
fi

# ============================================================
# GROUP 12: SSH CONFIG FILE SECURITY
# ============================================================
section "GROUP 12 - SSH FILE SECURITY"

test_file /etc/ssh/sshd_config "SSH server configuration exists"
test_owner_root /etc/ssh/sshd_config "SSH config ownership"
test_mode /etc/ssh/sshd_config 600 "SSH config mode 0600"
test_file "$SYSCTL_DROPIN" "CIS sysctl drop-in exists"
test_pattern "$SECTIONS/03_firewall_ssh.sh" 'sshd[[:space:]]+-t' "Section 03 validates sshd configuration"
test_pattern "$SECTIONS/03_firewall_ssh.sh" '00-cis-hardening\.conf' "Section 03 uses an SSH drop-in"

# ============================================================
# GROUP 13: FIREWALL CHECKS
# ============================================================
section "GROUP 13 - UFW FIREWALL"

if command -v ufw >/dev/null 2>&1; then
    ufw status 2>/dev/null | grep -q 'Status: active' && ok "4.1.2 UFW is active" || bad "4.1.2 UFW is active"
    ufw status verbose 2>/dev/null | grep -qi 'Default: deny (incoming)' && ok "4.1.3 UFW default incoming policy is deny" || bad "4.1.3 UFW default incoming policy is deny"
    if ufw status verbose 2>/dev/null | grep -Eqi 'routed.*deny|Default:.*routed.*deny' ||
       grep -Eq '^[[:space:]]*DEFAULT_FORWARD_POLICY=["'\'']?DROP["'\'']?[[:space:]]*$' /etc/default/ufw 2>/dev/null; then
        ok "4.1.5 UFW routed policy is deny"
    else
        bad "4.1.5 UFW routed policy is deny"
    fi
else
    bad "UFW command is installed"
fi

# ============================================================
# GROUP 14: PAM / PASSWORD POLICY
# ============================================================
section "GROUP 14 - PAM AND PASSWORD POLICY"

for f in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password; do
    test_file "$f" "PAM file exists: $f"
done

test_pattern /etc/pam.d/common-auth 'pam_faillock\.so.*preauth|pam_faillock\.so' "PAM auth includes pam_faillock"
test_pattern /etc/pam.d/common-auth 'pam_faillock\.so.*authfail|authfail.*pam_faillock\.so' "PAM auth includes faillock authfail"
test_pattern /etc/pam.d/common-account 'pam_faillock\.so' "PAM account includes pam_faillock"
test_pattern /etc/pam.d/common-password 'pam_pwquality\.so' "PAM password includes pwquality"
test_pattern /etc/pam.d/common-password 'pam_pwhistory\.so|remember=' "PAM password history is configured"
test_pattern /etc/pam.d/common-password 'pam_unix\.so' "PAM password includes pam_unix"
if grep -E '^[[:space:]]*password[[:space:]].*pam_unix\.so' /etc/pam.d/common-password 2>/dev/null | grep -qw nullok; then
    bad "PAM pam_unix does not allow nullok"
else
    ok "PAM pam_unix does not allow nullok"
fi
test_pattern /etc/security/pwquality.conf '^[[:space:]]*minlen[[:space:]]*=[[:space:]]*14' "Password minimum length is configured as 14"
test_pattern /etc/security/pwquality.conf '^[[:space:]]*difok[[:space:]]*=[[:space:]]*2' "Password difok is configured as 2"
test_pattern /etc/security/pwquality.conf '^[[:space:]]*maxrepeat[[:space:]]*=[[:space:]]*3' "Password maxrepeat is configured as 3"
test_pattern /etc/security/pwquality.conf '^[[:space:]]*maxsequence[[:space:]]*=[[:space:]]*3' "Password maxsequence is configured as 3"
test_pattern /etc/security/pwquality.conf '^[[:space:]]*enforce_for_root([[:space:]]|$)' "Password quality policy enforces root"
test_pattern /etc/login.defs '^[[:space:]]*PASS_MAX_DAYS[[:space:]]+365' "PASS_MAX_DAYS is 365"
test_pattern /etc/login.defs '^[[:space:]]*PASS_MIN_DAYS[[:space:]]+1' "PASS_MIN_DAYS is 1"
test_pattern /etc/login.defs '^[[:space:]]*PASS_WARN_AGE[[:space:]]+7' "PASS_WARN_AGE is 7"

if command -v chage >/dev/null 2>&1; then
    root_inactive="$(chage -l root 2>/dev/null | awk -F: '/Password inactive/ {sub(/^[[:space:]]+/,"",$2); print $2}')"
    if [[ "$root_inactive" == "30 days" || "$root_inactive" == "30" ]]; then
        ok "Root password inactivity is 30 days"
    else
        bad "Root password inactivity expected 30 days (got ${root_inactive:-unknown})"
    fi
else
    skip "Root password inactivity (chage unavailable)"
fi

# ============================================================
# GROUP 15: ACCOUNT LOCKOUT / SU / UMASK / ROOT PATH
# ============================================================
section "GROUP 15 - ACCOUNT SECURITY"

test_pattern /etc/security/faillock.conf '^[[:space:]]*deny[[:space:]]*=[[:space:]]*5([[:space:]]|$)' "Failed login lockout threshold 5 is configured"
test_pattern /etc/security/faillock.conf '^[[:space:]]*unlock_time[[:space:]]*=[[:space:]]*900([[:space:]]|$)' "PAM failed-login unlock policy is configured"
test_pattern /etc/pam.d/su 'pam_wheel\.so' "su restriction references pam_wheel"
test_pattern /etc/profile '^[[:space:]]*umask[[:space:]]+(027|077)([[:space:]]|$)' "Global profile sets restrictive umask"
test_pattern /etc/bash.bashrc '^[[:space:]]*umask[[:space:]]+(027|077)([[:space:]]|$)' "Global bashrc sets restrictive umask"

root_path="$(sudo -n -u root /usr/bin/env 2>/dev/null | awk -F= '$1=="PATH"{print $2}' || true)"
if [[ -z "$root_path" ]]; then
    root_path="$PATH"
    skip "Root PATH checked with current PATH fallback (sudo noninteractive unavailable)"
else
    ok "Root PATH can be inspected"
fi
if [[ ":$root_path:" != *":.:"* && "$root_path" != .* && "$root_path" != *":..:"* ]]; then
    ok "PATH does not include current or parent directory"
else
    bad "PATH contains current or parent directory"
fi

# ============================================================
# GROUP 16: LOGGING AND AUDIT
# ============================================================
section "GROUP 16 - LOGGING AND AUDIT"

test_file /etc/rsyslog.conf "rsyslog main configuration exists"
test_dir /etc/rsyslog.d "rsyslog drop-in directory exists"
test_file /etc/audit/auditd.conf "auditd configuration exists"
test_dir /etc/audit/rules.d "audit rules directory exists"
test_service_active rsyslog
test_service_enabled rsyslog
test_service_active auditd
test_service_enabled auditd

test_pattern "$SECTIONS/05_logging_audit.sh" 'REMOTE_SYSLOG_HOST' "Section 05 supports configured remote syslog host"
test_pattern "$SECTIONS/05_logging_audit.sh" 'auth\.log' "Section 05 references Ubuntu auth.log"
test_pattern "$SECTIONS/05_logging_audit.sh" 'auditctl|augenrules' "Section 05 handles audit rules"

if grep -RqsE '^[[:space:]]*\*\.\*[[:space:]]+@{1,2}[^[:space:]]+' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null; then
    ok "Remote syslog destination is configured"
else
    skip "6.1.2.5 remote syslog target not configured (site-specific; configure a real central log host)"
fi

# ============================================================
# GROUP 17: LOG FILE PERMISSIONS
# ============================================================
section "GROUP 17 - LOG FILE PERMISSIONS"

for f in /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/dpkg.log /var/log/apt/history.log; do
    if [[ -e "$f" ]]; then
        mode="$(stat -c '%a' "$f" 2>/dev/null || true)"
        # A conservative ceiling: group/other must not have write access.
        if [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0022) == 0 )); then
            ok "Log file has no group/other write bits: $f ($mode)"
        else
            bad "Log file permissions too broad: $f (${mode:-unknown})"
        fi
    else
        skip "Optional log file absent: $f"
    fi
done

# ============================================================
# GROUP 18: FILESYSTEM / BANNERS / APPARMOR / AIDE
# ============================================================
section "GROUP 18 - FILESYSTEM AND BOOT SECURITY"

test_file /etc/issue "Local login banner file exists"
test_file /etc/issue.net "SSH warning banner file exists"
test_file /etc/motd "MOTD file exists"
effective_banner="$(sshd -T 2>/dev/null | awk '$1 == "banner" {print $2; exit}' || true)"
if [[ "$effective_banner" == "/etc/issue.net" ]] ||
   grep -Eq '^[[:space:]]*Banner[[:space:]]+/etc/issue\.net([[:space:]]|$)' /etc/ssh/sshd_config.d/00-cis-hardening.conf 2>/dev/null; then
    ok "SSH banner is configured in SSH config or effective drop-in"
else
    bad "SSH banner is configured in SSH config or effective drop-in"
fi
test_pattern "$SECTIONS/01_filesystem_boot.sh" 'GRUB_PASSWORD_HASH' "Section 01 supports GRUB password hash"
test_pattern "$SECTIONS/01_filesystem_boot.sh" 'fs\.suid_dumpable' "Section 01 handles fs.suid_dumpable"
test_pattern "$SECTIONS/01_filesystem_boot.sh" 'kernel\.dmesg_restrict' "Section 01 handles kernel.dmesg_restrict"
test_pattern "$SECTIONS/01_filesystem_boot.sh" 'kernel\.randomize_va_space' "Section 01 handles kernel.randomize_va_space"
test_pattern "$SECTIONS/01_filesystem_boot.sh" 'apparmor' "Section 01 handles AppArmor"
test_pattern "$SECTIONS/01_filesystem_boot.sh" 'apport' "Section 01 handles apport"
test_pattern "$SECTIONS/01_filesystem_boot.sh" 'aide' "Section 01 handles AIDE"

test_sysctl fs.suid_dumpable 0 "1.5.4 fs.suid_dumpable"
test_sysctl kernel.dmesg_restrict 1 "1.5.5 kernel.dmesg_restrict"
test_sysctl kernel.randomize_va_space 2 "1.5.9 kernel.randomize_va_space"

if command -v aa-status >/dev/null 2>&1; then
    aa-status --enabled >/dev/null 2>&1 && ok "AppArmor is enabled" || bad "AppArmor is enabled"
else
    skip "AppArmor status (aa-status unavailable)"
fi

if command -v aide >/dev/null 2>&1; then
    ok "AIDE command installed"
else
    bad "AIDE command installed"
fi

# /dev/shm mount options
if findmnt -n -o OPTIONS /dev/shm >/dev/null 2>&1; then
    shm_opts="$(findmnt -n -o OPTIONS /dev/shm 2>/dev/null || true)"
    [[ ",$shm_opts," == *",noexec,"* ]] && ok "1.1.2.2.4 /dev/shm has noexec" || bad "1.1.2.2.4 /dev/shm has noexec"
else
    bad "/dev/shm mount can be inspected"
fi

# /tmp separation is environment-dependent and cannot safely be created by a test.
if findmnt -n /tmp >/dev/null 2>&1; then
    ok "/tmp mount entry exists (review whether separate/tmpfs matches policy)"
else
    skip "1.1.2.1.1 /tmp separate mount is not configured; test runner will not repartition"
fi

# GRUB credential must be real, never invented.
if grep -Eq '^[[:space:]]*GRUB_PASSWORD_HASH[[:space:]]*=[[:space:]]*["'\'']?grub\.pbkdf2\.' "$CONFIG"; then
    ok "GRUB PBKDF2 hash is configured"
else
    skip "1.4.1 GRUB password hash is site-specific; configure a real hash before testing compliance"
fi

# ============================================================
# GROUP 19: CRON ACCESS CONTROLS
# ============================================================
section "GROUP 19 - CRON ACCESS AND PERMISSIONS"

test_mode /etc/crontab 600 "2.4.1.2 /etc/crontab"
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly /etc/cron.d; do
    if [[ -d "$d" ]]; then
        mode="$(stat -c '%a' "$d" 2>/dev/null || true)"
        if [[ "$mode" == "700" || "$mode" == "750" || "$mode" == "755" ]]; then
            ok "Cron directory has expected restrictive mode: $d ($mode)"
        else
            bad "Cron directory mode requires review: $d ($mode)"
        fi
    else
        skip "Cron directory not present: $d"
    fi
done

if [[ -e /etc/cron.allow ]]; then
    test_owner_root /etc/cron.allow "cron.allow ownership"
    test_mode /etc/cron.allow 600 "cron.allow mode"
else
    skip "cron.allow is absent; verify cron.deny/cron policy for this host"
fi

if [[ -e /etc/at.allow ]]; then
    test_owner_root /etc/at.allow "at.allow ownership"
    test_mode /etc/at.allow 600 "at.allow mode"
else
    skip "at.allow is absent; verify at access policy for this host"
fi

# ============================================================
# GROUP 20: SENSITIVE FILES / PERMISSIONS
# ============================================================
section "GROUP 20 - SENSITIVE FILE PERMISSIONS"

test_owner_root /etc/passwd "/etc/passwd owner"
test_mode /etc/passwd 644 "/etc/passwd mode"
test_owner_root /etc/group "/etc/group owner"
test_mode /etc/group 644 "/etc/group mode"
test_owner_root_shadow /etc/shadow "/etc/shadow owner"
test_mode /etc/shadow 640 "/etc/shadow mode"
test_owner_root_shadow /etc/gshadow "/etc/gshadow owner"
test_mode /etc/gshadow 640 "/etc/gshadow mode"
test_owner_root /etc/sudoers "/etc/sudoers owner"
test_mode /etc/sudoers 440 "/etc/sudoers mode"

if [[ -d /etc/sudoers.d ]]; then
    test_owner_root /etc/sudoers.d "/etc/sudoers.d owner"
    mode="$(stat -c '%a' /etc/sudoers.d 2>/dev/null || true)"
    [[ "$mode" == "750" || "$mode" == "755" ]] && ok "/etc/sudoers.d mode is restrictive ($mode)" || bad "/etc/sudoers.d mode is restrictive (got $mode)"
else
    skip "/etc/sudoers.d directory absent"
fi

test_pattern "$SECTIONS/06_permissions.sh" 'world.writable|world_writable|world writable' "Section 06 audits world-writable files/directories"
test_pattern "$SECTIONS/06_permissions.sh" 'cron' "Section 06 audits cron permissions"
test_pattern "$SECTIONS/06_permissions.sh" 'sshd_config|/etc/ssh' "Section 06 audits SSH file permissions"

# Check for world-writable regular files without changing anything.
if command -v find >/dev/null 2>&1; then
    ww="$(find / -xdev -type f -perm -0002 -print 2>/dev/null | head -n 1)"
    if [[ -z "$ww" ]]; then
        ok "No world-writable regular files found on root filesystem"
    else
        bad "World-writable regular file found (first: $ww); review all findings"
    fi
else
    skip "World-writable file scan (find unavailable)"
fi

# ============================================================
# GROUP 21: UPDATE / REMEDIATION IMPLEMENTATION COVERAGE
# ============================================================
section "GROUP 21 - CONTROL IMPLEMENTATION COVERAGE"

test_pattern "$SECTIONS/01_filesystem_boot.sh" 'apt-get update|apt-get upgrade' "Section 01 includes package/security update handling"
test_pattern "$SECTIONS/02_services_network.sh" 'persist_sysctl_value' "Section 02 persists sysctl settings"
test_pattern "$SECTIONS/02_services_network.sh" 'sysctl --system|sysctl -w|set_sysctl_value' "Section 02 applies runtime sysctl settings"
test_pattern "$SECTIONS/03_firewall_ssh.sh" 'ufw default deny incoming' "Section 03 configures UFW incoming default"
test_pattern "$SECTIONS/03_firewall_ssh.sh" 'ufw default deny routed' "Section 03 configures UFW routed default"
test_pattern "$SECTIONS/03_firewall_ssh.sh" 'PermitRootLogin' "Section 03 handles PermitRootLogin"
test_pattern "$SECTIONS/03_firewall_ssh.sh" 'MaxAuthTries' "Section 03 handles MaxAuthTries"
test_pattern "$SECTIONS/03_firewall_ssh.sh" 'MaxStartups' "Section 03 handles MaxStartups"
test_pattern "$SECTIONS/04_pam_accounts.sh" 'pam_faillock' "Section 04 handles pam_faillock"
test_pattern "$SECTIONS/04_pam_accounts.sh" 'pam_pwquality' "Section 04 handles password quality"
test_pattern "$SECTIONS/04_pam_accounts.sh" 'pam_pwhistory|remember=' "Section 04 handles password history"
test_pattern "$SECTIONS/05_logging_audit.sh" 'rsyslog' "Section 05 handles rsyslog"
test_pattern "$SECTIONS/05_logging_audit.sh" 'auditd|auditctl|augenrules' "Section 05 handles auditd/rules"
test_pattern "$SECTIONS/06_permissions.sh" 'chmod|set_file_permissions|install -o' "Section 06 contains permission remediation"

# ============================================================
# GROUP 22: MANUAL / ENVIRONMENT-SPECIFIC CONTROLS
# ============================================================
section "GROUP 22 - MANUAL / ENVIRONMENT-SPECIFIC CONTROLS"

skip "Remote syslog compliance requires the organization's real central logging host and transport"
skip "GRUB password compliance requires a real approved GRUB username and PBKDF2 hash"
skip "SSH AllowUsers/AllowGroups requires approved administrator/service-account inventory"
skip "Separate /tmp, /var, /home, /var/tmp, /var/log, /var/log/audit mounts require approved storage layout"
skip "SSH post-quantum KEX compliance depends on the installed OpenSSH version and benchmark wording"
skip "Nessus checks for other hosts and other OS benchmarks cannot be validated by this local Ubuntu test run"
skip "Nessus plugin-level compliance must be confirmed by rerunning the same applicable Ubuntu 24.04 audit"

# ============================================================
# GROUP 23: OPTIONAL AUDIT INTEGRATION
# ============================================================
section "GROUP 23 - OPTIONAL AUDIT INTEGRATION"

if [[ "$RUN_AUDIT" == "yes" ]]; then
    if [[ -x "$HARDENING" ]]; then
        printf '[INFO] Running read-only audit mode; no remediation is invoked.\n'
        if "$HARDENING" audit; then
            ok "hardening.sh audit exits successfully"
        else
            bad "hardening.sh audit exits successfully (audit found failure or command error)"
        fi
    else
        bad "hardening.sh is executable for audit integration"
    fi
else
    skip "Full hardening.sh audit not requested; use sudo ./test.sh --audit"
fi

# ============================================================
# FINAL SUMMARY
# ============================================================
section "FINAL SUMMARY"
printf 'Total test cases : %d\n' "$TOTAL"
printf 'Passed           : %d\n' "$PASS"
printf 'Failed           : %d\n' "$FAIL"
printf 'Skipped          : %d\n' "$SKIP"

if (( FAIL > 0 )); then
    printf '\nRESULT: FAIL - review the failures above.\n'
    exit 1
fi

printf '\nRESULT: All executed checks passed; skipped checks still require review.\n'
exit 0
