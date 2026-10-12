#!/usr/bin/env bash

# ============================================================
# CIS Ubuntu 24.04 LTS - Test Runner
#
# File: test.sh
# Location: Project root, alongside hardening.sh
#
# Usage:
#   bash test.sh
#   bash test.sh --live-sysctl
#   sudo bash test.sh --audit
#
# Safety:
#   - Does not run remediation.
#   - Does not modify security settings.
#   - Static tests check project structure and source code.
#   - Optional live tests check current kernel settings.
#   - Optional audit runs hardening.sh in audit mode.
# ============================================================

set -uo pipefail

# ------------------------------------------------------------
# 1. Paths and test counters
# ------------------------------------------------------------

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

HARDENING="$SCRIPT_DIR/hardening.sh"
CONFIG="$SCRIPT_DIR/cis.conf"
COMMON="$SCRIPT_DIR/lib/common.sh"
SECTIONS="$SCRIPT_DIR/sections"

PASS=0
FAIL=0
SKIP=0

RUN_LIVE_SYSCTL=no
RUN_AUDIT=no

# ------------------------------------------------------------
# 2. Read command-line options
# ------------------------------------------------------------

for arg in "$@"; do
    case "$arg" in
        --live-sysctl)
            RUN_LIVE_SYSCTL=yes
            ;;
        --audit)
            RUN_AUDIT=yes
            ;;
        --help|-h)
            cat <<'HELP'
CIS Ubuntu 24.04 Test Runner

Usage:
  bash test.sh
      Run static tests only.

  bash test.sh --live-sysctl
      Run static tests and check live log_martians values.

  sudo bash test.sh --audit
      Run static tests and the hardening script in audit mode.

  sudo bash test.sh --live-sysctl --audit
      Run all of the above.

This test runner never runs remediation.
HELP
            exit 0
            ;;
        *)
            printf '[ERROR] Unknown option: %s\n' "$arg"
            printf 'Use: bash test.sh --help\n'
            exit 2
            ;;
    esac
done

# ------------------------------------------------------------
# 3. Test reporting functions
# ------------------------------------------------------------

pass() {
    printf '[PASS] %s\n' "$1"
    PASS=$((PASS + 1))
}

fail() {
    printf '[FAIL] %s\n' "$1"
    FAIL=$((FAIL + 1))
}

skip() {
    printf '[SKIP] %s\n' "$1"
    SKIP=$((SKIP + 1))
}

section() {
    printf '\n============================================================\n'
    printf '%s\n' "$1"
    printf '============================================================\n'
}

check_file() {
    local file="$1"

    if [[ -f "$file" ]]; then
        pass "File exists: ${file#"$SCRIPT_DIR"/}"
    else
        fail "Missing file: ${file#"$SCRIPT_DIR"/}"
    fi
}

check_function() {
    local file="$1"
    local function_name="$2"

    if [[ ! -f "$file" ]]; then
        fail "Cannot check function $function_name; file is missing"
        return
    fi

    if grep -Eq \
        "^[[:space:]]*${function_name}[[:space:]]*\\(\\)[[:space:]]*\\{" \
        "$file"; then
        pass "Function exists: ${function_name}"
    else
        fail "Function missing: ${function_name} in ${file#"$SCRIPT_DIR"/}"
    fi
}

check_pattern() {
    local file="$1"
    local pattern="$2"
    local description="$3"

    if [[ ! -f "$file" ]]; then
        fail "$description (source file missing)"
        return
    fi

    if grep -Eq -- "$pattern" "$file"; then
        pass "$description"
    else
        fail "$description"
    fi
}

# ------------------------------------------------------------
# 4. Project structure tests
# ------------------------------------------------------------

section "TEST GROUP 1: PROJECT FILES"

check_file "$HARDENING"
check_file "$CONFIG"
check_file "$COMMON"
check_file "$SCRIPT_DIR/README.md"

for file in \
    01_filesystem_boot.sh \
    02_services_network.sh \
    03_firewall_ssh.sh \
    04_pam_accounts.sh \
    05_logging_audit.sh \
    06_permissions.sh
do
    check_file "$SECTIONS/$file"
done

# ------------------------------------------------------------
# 5. Shell syntax tests
# ------------------------------------------------------------

section "TEST GROUP 2: SHELL SYNTAX"

if bash -n "$HARDENING"; then
    pass "hardening.sh syntax"
else
    fail "hardening.sh syntax"
fi

if bash -n "$COMMON"; then
    pass "lib/common.sh syntax"
else
    fail "lib/common.sh syntax"
fi

for file in "$SECTIONS"/*.sh; do
    [[ -f "$file" ]] || continue

    if bash -n "$file"; then
        pass "Syntax: ${file#"$SCRIPT_DIR"/}"
    else
        fail "Syntax: ${file#"$SCRIPT_DIR"/}"
    fi
done

if bash -n "$SCRIPT_DIR/test.sh"; then
    pass "test.sh syntax"
else
    fail "test.sh syntax"
fi

# ------------------------------------------------------------
# 6. Main script and common-library tests
# ------------------------------------------------------------

section "TEST GROUP 3: CORE FUNCTIONS"

check_pattern "$HARDENING" 'audit' \
    "Main script contains audit-mode handling"

check_pattern "$HARDENING" 'remediate' \
    "Main script contains remediation-mode handling"

check_pattern "$HARDENING" 'verify' \
    "Main script contains verify-mode handling"

check_pattern "$HARDENING" 'common\.sh' \
    "Main script references common.sh"

check_pattern "$HARDENING" 'cis\.conf' \
    "Main script references cis.conf"

check_function "$COMMON" "audit_pass"
check_function "$COMMON" "audit_fail"
check_function "$COMMON" "audit_warning"
check_function "$COMMON" "audit_skip"
check_function "$COMMON" "backup_file"
check_function "$COMMON" "set_sysctl_value"

# ------------------------------------------------------------
# 7. Section entry-point tests
# ------------------------------------------------------------

section "TEST GROUP 4: SECTION FUNCTIONS"

check_function "$SECTIONS/01_filesystem_boot.sh" \
    "section_01_filesystem_boot"

check_function "$SECTIONS/02_services_network.sh" \
    "section_02_services_network"

check_function "$SECTIONS/02_services_network.sh" \
    "audit_02_services_network"

check_function "$SECTIONS/02_services_network.sh" \
    "remediate_02_services_network"

check_function "$SECTIONS/02_services_network.sh" \
    "audit_ipv4_settings"

check_function "$SECTIONS/02_services_network.sh" \
    "remediate_ipv4_settings"

check_function "$SECTIONS/02_services_network.sh" \
    "audit_ipv6_settings"

check_function "$SECTIONS/02_services_network.sh" \
    "remediate_ipv6_settings"

check_function "$SECTIONS/03_firewall_ssh.sh" \
    "section_03_firewall_ssh"

check_function "$SECTIONS/04_pam_accounts.sh" \
    "section_04_pam_accounts"

check_function "$SECTIONS/05_logging_audit.sh" \
    "section_05_logging_audit"

check_function "$SECTIONS/06_permissions.sh" \
    "audit_section_06"

check_function "$SECTIONS/06_permissions.sh" \
    "remediate_section_06"

# ------------------------------------------------------------
# 8. Configuration tests
# ------------------------------------------------------------

section "TEST GROUP 5: CIS CONFIGURATION"

check_pattern "$CONFIG" \
    '^[[:space:]]*NET_IPV4_ALL_LOG_MARTIANS[[:space:]]*=[[:space:]]*1([[:space:]]|$|#)' \
    "IPv4 all.log_martians expected value is 1"

check_pattern "$CONFIG" \
    '^[[:space:]]*NET_IPV4_DEFAULT_LOG_MARTIANS[[:space:]]*=[[:space:]]*1([[:space:]]|$|#)' \
    "IPv4 default.log_martians expected value is 1"

check_pattern "$CONFIG" \
    '^[[:space:]]*SSH_MAX_AUTH_TRIES[[:space:]]*=' \
    "SSH MaxAuthTries is configurable"

check_pattern "$CONFIG" \
    '^[[:space:]]*SSH_MAX_SESSIONS[[:space:]]*=' \
    "SSH MaxSessions is configurable"

check_pattern "$CONFIG" \
    '^[[:space:]]*DISABLE_ATM_MODULE[[:space:]]*=' \
    "ATM module policy is configurable"

check_pattern "$CONFIG" \
    '^[[:space:]]*DISABLE_CAN_MODULE[[:space:]]*=' \
    "CAN module policy is configurable"

check_pattern "$CONFIG" \
    '^[[:space:]]*DISABLE_SCTP_MODULE[[:space:]]*=' \
    "SCTP module policy is configurable"

check_pattern "$CONFIG" \
    '^[[:space:]]*DISABLE_TIPC_MODULE[[:space:]]*=' \
    "TIPC module policy is configurable"

# ------------------------------------------------------------
# 9. IPv4 log_martians source-code tests
# ------------------------------------------------------------

SECTION_02="$SECTIONS/02_services_network.sh"

section "TEST GROUP 6: IPV4 LOG_MARTIANS CONTROLS"

check_pattern "$SECTION_02" \
    'net\.ipv4\.conf\.all\.log_martians' \
    "Section 02 handles all.log_martians"

check_pattern "$SECTION_02" \
    'net\.ipv4\.conf\.default\.log_martians' \
    "Section 02 handles default.log_martians"

check_pattern "$SECTION_02" \
    'NET_IPV4_ALL_LOG_MARTIANS' \
    "Section 02 uses configured all.log_martians value"

check_pattern "$SECTION_02" \
    'NET_IPV4_DEFAULT_LOG_MARTIANS' \
    "Section 02 uses configured default.log_martians value"

check_pattern "$SECTION_02" \
    'persist_sysctl_value' \
    "Section 02 contains persistent sysctl handling"

check_pattern "$SECTION_02" \
    'set_sysctl_value' \
    "Section 02 contains runtime sysctl handling"

check_pattern "$SECTION_02" \
    '99-cis-hardening\.conf' \
    "Section 02 uses the CIS sysctl drop-in file"

check_pattern "$SECTION_02" \
    '3\.3\.1\.16' \
    "Section 02 includes CIS control 3.3.1.16"

check_pattern "$SECTION_02" \
    '3\.3\.1\.17' \
    "Section 02 includes CIS control 3.3.1.17"

# ------------------------------------------------------------
# 10. Other network-control source tests
# ------------------------------------------------------------

section "TEST GROUP 7: NETWORK CONTROL COVERAGE"

for control in \
    3.3.1.4 \
    3.3.1.5 \
    3.3.1.8 \
    3.3.1.9 \
    3.3.1.10 \
    3.3.1.11 \
    3.3.1.12 \
    3.3.1.13 \
    3.3.1.14 \
    3.3.1.15 \
    3.3.1.18 \
    3.3.2.1 \
    3.3.2.2 \
    3.3.2.3 \
    3.3.2.4 \
    3.3.2.5 \
    3.3.2.6 \
    3.3.2.7 \
    3.3.2.8
do
    check_pattern "$SECTION_02" "$control" \
        "Section 02 references network control $control"
done

check_pattern "$SECTION_02" 'audit_kernel_modules' \
    "Section 02 audits unnecessary kernel modules"

check_pattern "$SECTION_02" 'remediate_kernel_modules' \
    "Section 02 contains kernel module remediation"

check_pattern "$SECTION_02" 'audit_telnet_client' \
    "Section 02 audits Telnet client"

check_pattern "$SECTION_02" 'audit_ftp_client' \
    "Section 02 audits FTP client"

# ------------------------------------------------------------
# 11. Optional live kernel tests
# ------------------------------------------------------------

section "TEST GROUP 8: LIVE KERNEL VALUES"

if [[ "$RUN_LIVE_SYSCTL" == "yes" ]]; then

    if ! command -v sysctl >/dev/null 2>&1; then
        fail "sysctl command is unavailable"
    else
        actual_all="$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null || true)"
        actual_default="$(sysctl -n net.ipv4.conf.default.log_martians 2>/dev/null || true)"

        if [[ "$actual_all" == "1" ]]; then
            pass "Live all.log_martians is 1"
        else
            fail "Live all.log_martians is '${actual_all:-unavailable}', expected 1"
        fi

        if [[ "$actual_default" == "1" ]]; then
            pass "Live default.log_martians is 1"
        else
            fail "Live default.log_martians is '${actual_default:-unavailable}', expected 1"
        fi
    fi

else
    skip "Live kernel checks not requested; use --live-sysctl"
fi

# ------------------------------------------------------------
# 12. Optional audit-mode integration test
# ------------------------------------------------------------

section "TEST GROUP 9: AUDIT-MODE INTEGRATION"

if [[ "$RUN_AUDIT" == "yes" ]]; then

    if [[ ! -x "$HARDENING" ]]; then
        skip "hardening.sh is not executable; run chmod +x hardening.sh"
    else
        printf '[INFO] Running hardening.sh audit. This may require root.\n'

        if "$HARDENING" audit; then
            pass "hardening.sh audit command exited successfully"
        else
            fail "hardening.sh audit command returned a non-zero exit code"
        fi
    fi

else
    skip "Audit integration not requested; use --audit"
fi

# ------------------------------------------------------------
# 13. Final summary
# ------------------------------------------------------------

section "TEST SUMMARY"

printf 'Passed : %d\n' "$PASS"
printf 'Failed : %d\n' "$FAIL"
printf 'Skipped: %d\n' "$SKIP"
printf 'Total  : %d\n' "$((PASS + FAIL + SKIP))"

if [[ "$FAIL" -gt 0 ]]; then
    printf '\nRESULT: TESTS FAILED\n'
    exit 1
fi

printf '\nRESULT: ALL EXECUTED TESTS PASSED\n'
exit 0
