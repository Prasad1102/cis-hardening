#!/usr/bin/env bash

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$TEST_DIR/.." && pwd)"
BASH_BIN="${BASH_BIN:-bash}"
TEST_REPORT="${TEST_REPORT:-$TEST_DIR/test_report.txt}"
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

ssh_effective_setting_check() {
    local fixture
    fixture="$(mktemp -d)" || return 1

    if ! "$BASH_BIN" -c '
        mkdir() { return 0; }
        touch() { return 0; }
        sshd() {
            printf "%s\n" \
                "port 22" \
                "banner /etc/issue.net" \
                "ignorerhosts yes" \
                "loglevel VERBOSE" \
                "permitrootlogin no" \
                "permituserenvironment no" \
                "permitemptypasswords no" \
                "allowtcpforwarding no" \
                "allowagentforwarding no" \
                "x11forwarding no"
        }
            audit_pass() { return 0; }
            audit_fail() { return 1; }
            source "$1/lib/common.sh"
        LOG_DIR="$2"
            source "$1/sections/01_filesystem_boot.sh"
            source "$1/sections/03_firewall_ssh.sh"
        [[ "$(ssh_effective_value Port)" == 22 ]] || exit 1
        [[ "$(ssh_effective_value IgnoreRhosts)" == yes ]] || exit 1
        [[ "$(ssh_effective_value LogLevel)" == VERBOSE ]] || exit 1
        [[ "$(ssh_effective_value PermitRootLogin)" == no ]] || exit 1
        [[ "$(ssh_effective_value PermitUserEnvironment)" == no ]] || exit 1
        [[ "$(ssh_effective_value PermitEmptyPasswords)" == no ]] || exit 1
        [[ "$(ssh_effective_value AllowTcpForwarding)" == no ]] || exit 1
        [[ "$(ssh_effective_value AllowAgentForwarding)" == no ]] || exit 1
        [[ "$(ssh_effective_value X11Forwarding)" == no ]] || exit 1
        audit_ssh_banner || exit 1
    ' _ "$PROJECT_DIR" "$fixture"; then
        rm -f "$fixture/sshd-validation.log"
        rmdir "$fixture"
        return 1
    fi

    rm -f "$fixture/sshd-validation.log"
    rmdir "$fixture"
    return 0
}

ssh_warning_semantics_check() {
    "$BASH_BIN" -c '
        sshd() { printf "%s\\n" "port 22"; }
        ssh() { return 0; }
        audit_warning() { return 0; }
        audit_pass() { return 0; }
        audit_fail() { return 1; }
        source "$1"
        audit_sshd_access_config || exit 1
        audit_sshd_pq_kex || exit 1
    ' _ "$PROJECT_DIR/sections/03_firewall_ssh.sh"
}

grub_manual_skip_check() {
    "$BASH_BIN" -c '
        source "$1"
        GRUB_PASSWORD_ENABLED=no
        GRUB_PASSWORD_HASH=""
        audit_skip() { [[ "$1" == "1.4.1" ]]; }
        audit_fail() { return 1; }
        audit_grub_password
    ' _ "$PROJECT_DIR/sections/01_filesystem_boot.sh"
}

pam_fixture_check() {
    local fixture
    fixture="$(mktemp)" || return 1
    printf '%s\n' \
        'password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt' > "$fixture"

    if ! "$BASH_BIN" -c '
        source "$1"
        PAM_PASSWORD="$2"
        package_installed() { [[ "$1" == libpam-pwquality ]]; }
        install_package() { return 0; }
        backup_file() { return 0; }
        chown() { return 0; }
        chmod() { return 0; }
        command_exists() { return 1; }
        audit_pass() { return 0; }
        audit_fail() { return 1; }
        remediate_pam_pwquality_module || exit 1
        remediate_pam_pwquality_module || exit 1
        [[ "$(grep -c pam_pwquality.so "$PAM_PASSWORD")" == 1 ]] || exit 1
        audit_pam_pwquality_module || exit 1
        getent() {
            [[ "$1" == shadow && "$2" == ubuntu ]] || return 1
            printf "ubuntu:$hash:20000:0:99999:7:30::\\n"
        }
        [[ "$(shadow_inactive_days ubuntu)" == 30 ]]
    ' _ "$PROJECT_DIR/sections/04_pam_accounts.sh" "$fixture"; then
        rm -f "$fixture"
        return 1
    fi

    rm -f "$fixture"
    return 0
}

martian_remediation_check() {
    local capture
    capture="$(mktemp)" || return 1

    if ! "$BASH_BIN" -c '
        source "$1/cis.conf"
        source "$1/sections/02_services_network.sh"
        backup_file() { return 0; }
        persist_sysctl_value() { printf "persist %s=%s\\n" "$1" "$2" >> "$MARTIAN_CAPTURE"; }
        set_sysctl_value() { printf "live %s=%s\\n" "$1" "$2" >> "$MARTIAN_CAPTURE"; }
        sysctl() { [[ "$1" == --system ]]; }
        log_error() { return 0; }
        log_success() { return 0; }
        MARTIAN_CAPTURE="$2"
        REMEDIATION_LOG="$MARTIAN_CAPTURE"
        remediate_ipv4_settings || exit 1
        grep -Fqx "persist net.ipv4.conf.all.log_martians=1" "$MARTIAN_CAPTURE" || exit 1
        grep -Fqx "persist net.ipv4.conf.default.log_martians=1" "$MARTIAN_CAPTURE" || exit 1
        grep -Fqx "live net.ipv4.conf.all.log_martians=1" "$MARTIAN_CAPTURE" || exit 1
        grep -Fqx "live net.ipv4.conf.default.log_martians=1" "$MARTIAN_CAPTURE" || exit 1
    ' _ "$PROJECT_DIR" "$capture"; then
        rm -f "$capture"
        return 1
    fi

    rm -f "$capture"
    return 0
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
run_check "SSH effective lookup handles sshd -T lowercase keys" ssh_effective_setting_check
run_check "SSH manual-policy warnings do not fail the audit" ssh_warning_semantics_check
run_check "Disabled GRUB password is classified as manual SKIP" grub_manual_skip_check
run_check "PAM quality ordering and shadow inactive field are validated" pam_fixture_check
run_check "Martian sysctls are persisted and applied at runtime" martian_remediation_check
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
