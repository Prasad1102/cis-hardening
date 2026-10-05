#!/usr/bin/env bash

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$TEST_DIR/.." && pwd)"
BASH_BIN="${BASH_BIN:-bash}"
TEST_REPORT="${TEST_REPORT:-${TMPDIR:-/tmp}/cis-hardening-tests-$(date '+%Y%m%d_%H%M%S').txt}"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

mkdir -p "$(dirname "$TEST_REPORT")" || exit 2
: > "$TEST_REPORT" || exit 2

record_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf 'PASS: %s\n' "$1" | tee -a "$TEST_REPORT"
}

record_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf 'FAIL: %s\n' "$1" | tee -a "$TEST_REPORT"
}

record_skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    printf 'SKIP: %s\n' "$1" | tee -a "$TEST_REPORT"
}

run_check() {
    local name="$1"
    shift

    if "$@"; then
        record_pass "$name"
    else
        record_fail "$name"
    fi
}

syntax_check() {
    local file
    local failed=0
    local files=(
        "$PROJECT_DIR/hardening.sh"
        "$PROJECT_DIR/cis.conf"
        "$PROJECT_DIR/lib/common.sh"
        "$PROJECT_DIR/sections/01_filesystem_boot.sh"
        "$PROJECT_DIR/sections/02_services_network.sh"
        "$PROJECT_DIR/sections/03_firewall_ssh.sh"
        "$PROJECT_DIR/sections/04_pam_accounts.sh"
        "$PROJECT_DIR/sections/05_logging_audit.sh"
        "$PROJECT_DIR/sections/06_permissions.sh"
    )

    for file in "${files[@]}"; do
        "$BASH_BIN" -n "$file" || failed=1
    done
    return "$failed"
}

config_check() {
    "$BASH_BIN" -c '
        source "$1" || exit 1
        [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || exit 1
        [[ "$ENABLE_REMEDIATION" == yes ]] || exit 1
        [[ "$UFW_ALLOWED_TCP_PORTS" == *22* ]] || exit 1
        [[ "$NET_IPV4_ALL_LOG_MARTIANS" == 1 ]] || exit 1
        [[ "$NET_IPV4_DEFAULT_LOG_MARTIANS" == 1 ]] || exit 1
        [[ "$CONFIGURE_TMP_MOUNT" == yes ]] || exit 1
        [[ "$TMPFS_TMP_SIZE" =~ ^[1-9][0-9]?%$ ]] || exit 1
    ' _ "$PROJECT_DIR/cis.conf"
}

section_source_check() {
    "$BASH_BIN" -c '
        set -e
        project="$1"
        for file in "$project"/sections/*.sh; do source "$file"; done
        for function in \
            section_01_filesystem_boot section_02_services_network \
            section_03_audit section_03_remediate \
            section_04_audit section_04_remediate \
            section_05_audit section_05_remediate \
            audit_section_06 remediate_section_06; do
            declare -F "$function" >/dev/null
        done
    ' _ "$PROJECT_DIR"
}

remediation_dispatch_check() {
    grep -Eq '^run_remediation\(\)[[:space:]]*\{' "$PROJECT_DIR/hardening.sh" &&
        ! grep -Eq '^run_remediation\(\)[[:space:]]*\{' "$PROJECT_DIR/lib/common.sh" &&
        grep -Eq '^run_remediation_command\(\)[[:space:]]*\{' "$PROJECT_DIR/lib/common.sh" &&
        grep -Fq 'MODE="$action"' "$PROJECT_DIR/hardening.sh"
}

audit_rule_grep_check() {
    local rule='-w /etc/passwd -p wa -k identity'
    local fixture
    fixture="$(mktemp -d)" || return 1
    printf '%s\n' "$rule" > "$fixture/10-test.rules"
    grep -RFx --include='*.rules' -- "$rule" "$fixture" >/dev/null
    local status=$?
    rm -rf "$fixture"
    return "$status"
}

ufw_status_parse_check() {
    local expression="^[[:space:]]*22/tcp([[:space:]]|\\().*ALLOW([[:space:]]+IN)?([[:space:]]|$)"
    printf '%s\n' '22/tcp                     ALLOW       Anywhere' | grep -Eq "$expression" &&
        printf '%s\n' '22/tcp (v6)                ALLOW IN    Anywhere (v6)' | grep -Eq "$expression"
}

package_install_check() {
    local common="$PROJECT_DIR/lib/common.sh"
    local update_line install_line

    update_line="$(grep -n -m1 'apt-get update' "$common" | cut -d: -f1)"
    install_line="$(grep -n -m1 'apt-get install -y' "$common" | cut -d: -f1)"

    [[ -n "$update_line" && -n "$install_line" ]] &&
        (( update_line < install_line )) &&
        grep -Fq 'export DEBIAN_FRONTEND=noninteractive' "$common"
}

tmp_fstab_check() {
    [[ "$(uname -s)" == "Linux" ]] || return 2

    local fixture
    fixture="$(mktemp)" || return 1
    printf '%s\n' \
        '# existing fstab entry' \
        'UUID=root / ext4 defaults 0 1' \
        'tmpfs /tmp tmpfs defaults,noauto 0 0' > "$fixture"

    if ! "$BASH_BIN" -c '
        source "$1"
        update_tmp_fstab "$2" 10% || exit 1
        update_tmp_fstab "$2" 10% || exit 1
        line_count="$(grep -Ec "^[^#[:space:]]+[[:space:]]+/tmp[[:space:]]" "$2" || true)"
        [[ "$line_count" == 1 ]] || exit 1
        entry="$(grep -E "^[^#[:space:]]+[[:space:]]+/tmp[[:space:]]" "$2")"
        set -- $entry
        mount_options="$4"
        for option in nodev nosuid noexec size=10% mode=1777; do
            case ",${mount_options}," in
                *",${option},"*) ;;
                *) exit 1 ;;
            esac
        done
        case ",${mount_options}," in *,noauto,*) exit 1 ;; esac
    ' _ "$PROJECT_DIR/sections/01_filesystem_boot.sh" "$fixture"; then
        rm -f "$fixture"
        return 1
    fi

    rm -f "$fixture"
    return 0
}

run_check "Bash syntax for all project files" syntax_check
run_check "cis.conf loads required remediation values" config_check
run_check "All section files source without dispatch side effects" section_source_check
run_check "Main remediation dispatcher is not shadowed by common.sh" remediation_dispatch_check
run_check "Audit rule grep accepts leading -w" audit_rule_grep_check
run_check "UFW SSH parser accepts standard and verbose output" ufw_status_parse_check
run_check "Package install refreshes apt and is noninteractive" package_install_check

if [[ "$(uname -s)" == "Linux" ]]; then
    run_check "tmpfs /tmp fstab update is persistent and idempotent" tmp_fstab_check
else
    record_skip "tmpfs /tmp fstab transformation needs a Linux chmod implementation"
fi

if command -v shellcheck >/dev/null 2>&1; then
    shell_files=(
        "$PROJECT_DIR/hardening.sh"
        "$PROJECT_DIR/lib/common.sh"
        "$PROJECT_DIR"/sections/*.sh
    )
    run_check "ShellCheck all shell scripts" shellcheck "${shell_files[@]}"
else
    record_skip "ShellCheck is not installed"
fi

if [[ "${RUN_LIVE_AUDIT:-yes}" == "yes" ]]; then
    if [[ "$EUID" -ne 0 ]]; then
        record_skip "Live CIS audit requires root"
    elif [[ ! -r /etc/os-release ]] || ! grep -q '^ID=ubuntu$' /etc/os-release || ! grep -q '^VERSION_ID="24.04"$' /etc/os-release; then
        record_skip "Live CIS audit requires Ubuntu 24.04"
    else
        live_log="${TEST_REPORT%.txt}.live-audit.log"
        if "$PROJECT_DIR/hardening.sh" audit > "$live_log" 2>&1; then
            record_pass "Live hardening.sh audit; output: $live_log"
        else
            record_fail "Live hardening.sh audit; review $live_log"
        fi
    fi
else
    record_skip "Live audit disabled by RUN_LIVE_AUDIT"
fi

{
    printf '\nSUMMARY\n'
    printf 'PASS=%s\nFAIL=%s\nSKIP=%s\n' "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
    printf 'REPORT=%s\n' "$TEST_REPORT"
} | tee -a "$TEST_REPORT"

[[ "$FAIL_COUNT" -eq 0 ]]
