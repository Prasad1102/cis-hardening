#!/usr/bin/env bash
#
# CIS Ubuntu 24.04 LTS Level 1 Hardening
#
# Main controller
#
# Usage:
# sudo ./hardening.sh audit
# sudo ./hardening.sh remediate
#
# Project structure:
#
# cis-ubuntu-24.04/
# ├── hardening.sh
# ├── cis.conf
# ├── README.md
# ├── lib/
# │ └── common.sh
# └── sections/
# ├── 01_filesystem_boot.sh
# ├── 02_services_network.sh
# ├── 03_firewall_ssh.sh
# ├── 04_pam_accounts.sh
# ├── 05_logging_audit.sh
# └── 06_permissions.sh
#

set -o pipefail

###############################################################################
# Script paths
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONFIG_FILE="${SCRIPT_DIR}/cis.conf"
COMMON_LIB="${SCRIPT_DIR}/lib/common.sh"
SECTIONS_DIR="${SCRIPT_DIR}/sections"

###############################################################################
# Global runtime variables
###############################################################################

RUN_TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"

LOG_DIR="/var/log/cis-hardening"

RUN_LOG="${LOG_DIR}/hardening_${RUN_TIMESTAMP}.log"

REPORT_DIR="${LOG_DIR}/reports"

AUDIT_REPORT="${REPORT_DIR}/audit_${RUN_TIMESTAMP}.txt"

###############################################################################
# Section files
###############################################################################

SECTION_01="${SECTIONS_DIR}/01_filesystem_boot.sh"
SECTION_02="${SECTIONS_DIR}/02_services_network.sh"
SECTION_03="${SECTIONS_DIR}/03_firewall_ssh.sh"
SECTION_04="${SECTIONS_DIR}/04_pam_accounts.sh"
SECTION_05="${SECTIONS_DIR}/05_logging_audit.sh"
SECTION_06="${SECTIONS_DIR}/06_permissions.sh"

###############################################################################
# Colors
###############################################################################

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    RESET=''
fi

###############################################################################
# Main output helpers
###############################################################################

print_banner() {
    printf '\n'
    printf '%b\n' "${CYAN}============================================================${RESET}"
    printf '%b\n' "${CYAN} CIS Ubuntu 24.04 LTS Level 1 Hardening${RESET}"
    printf '%b\n' "${CYAN}============================================================${RESET}"
    printf '\n'
}

print_usage() {
    cat <<'EOF'

Usage:
  sudo ./hardening.sh audit
  sudo ./hardening.sh remediate

Commands:

  audit
      Audit the server against the configured CIS controls.
      No configuration changes are intentionally made.

  remediate
      Apply the configured hardening settings and then run
      a final audit to identify remaining failures/manual items.

Examples:

  sudo ./hardening.sh audit

  sudo ./hardening.sh remediate

EOF
}

###############################################################################
# Logging
###############################################################################

initialize_logging() {

    mkdir -p "$LOG_DIR"
    mkdir -p "$REPORT_DIR"

    touch "$RUN_LOG"
    touch "$AUDIT_REPORT"

    chmod 750 "$LOG_DIR"
    chmod 750 "$REPORT_DIR"
    chmod 640 "$RUN_LOG"
    chmod 640 "$AUDIT_REPORT"

    #
    # Send stdout/stderr to both terminal and log file.
    #
    exec > >(tee -a "$RUN_LOG") 2>&1

    printf '\n'
    printf '============================================================\n'
    printf 'CIS Ubuntu 24.04 LTS Hardening Run\n'
    printf 'Started : %s\n' "$(date)"
    printf 'Command : %s\n' "$0 $*"
    printf 'Host : %s\n' "$(hostname)"
    printf 'Kernel : %s\n' "$(uname -r)"
    printf '============================================================\n'
    printf '\n'
}

###############################################################################
# Basic validation
###############################################################################

check_root() {

    if [[ "${EUID}" -ne 0 ]]; then
        printf '%b\n' "${RED}ERROR: This script must be run as root.${RESET}"
        printf '%s\n' "Use:"
        printf '%s\n' " sudo ./hardening.sh audit"
        printf '%s\n' "or:"
        printf '%s\n' " sudo ./hardening.sh remediate"
        exit 1
    fi
}

check_os() {

    if [[ ! -f /etc/os-release ]]; then
        printf '%b\n' "${RED}ERROR: /etc/os-release was not found.${RESET}"
        exit 1
    fi

    #
    # shellcheck disable=SC1091
    #
    source /etc/os-release

    if [[ "${ID:-}" != "ubuntu" ]]; then
        printf '%b\n' "${RED}ERROR: This hardening project is intended for Ubuntu.${RESET}"
        printf 'Detected OS: %s\n' "${PRETTY_NAME:-unknown}"
        exit 1
    fi

    if [[ "${VERSION_ID:-}" != "24.04" ]]; then
        printf '%b\n' "${RED}ERROR: This script supports Ubuntu 24.04 LTS only.${RESET}"
        printf 'Detected version: %s\n' "${VERSION_ID:-unknown}"
        exit 1
    fi
}

###############################################################################
# File validation
###############################################################################

check_required_files() {

    local missing=0

    printf '%b\n' "${BLUE}Checking project files...${RESET}"

    local required_files=(
        "$CONFIG_FILE"
        "$COMMON_LIB"
        "$SECTION_01"
        "$SECTION_02"
        "$SECTION_03"
        "$SECTION_04"
        "$SECTION_05"
        "$SECTION_06"
    )

    local file

    for file in "${required_files[@]}"; do

        if [[ -f "$file" ]]; then
            printf '%b %s\n' "${GREEN}[OK]${RESET}" "$file"
        else
            printf '%b %s\n' "${RED}[MISSING]${RESET}" "$file"
            missing=1
        fi
    done

    if [[ "$missing" -ne 0 ]]; then
        printf '\n'
        printf '%b\n' "${RED}ERROR: One or more required project files are missing.${RESET}"
        exit 1
    fi

    printf '\n'
}

check_section_syntax() {

    printf '%b\n' "${BLUE}Checking shell syntax...${RESET}"

    local files=(
        "${SCRIPT_DIR}/hardening.sh"
        "$CONFIG_FILE"
        "$COMMON_LIB"
        "$SECTION_01"
        "$SECTION_02"
        "$SECTION_03"
        "$SECTION_04"
        "$SECTION_05"
        "$SECTION_06"
    )

    local file
    local failed=0

    for file in "${files[@]}"; do

        if bash -n "$file"; then
            printf '%b %s\n' "${GREEN}[OK]${RESET}" "$file"
        else
            printf '%b %s\n' "${RED}[FAIL]${RESET}" "$file"
            failed=1
        fi
    done

    if [[ "$failed" -ne 0 ]]; then
        printf '\n'
        printf '%b\n' "${RED}ERROR: Shell syntax validation failed.${RESET}"
        exit 1
    fi

    printf '\n'
}

###############################################################################
# Configuration validation
###############################################################################

load_configuration() {

    if [[ ! -f "$CONFIG_FILE" ]]; then
        printf '%b\n' "${RED}ERROR: Configuration file not found: $CONFIG_FILE${RESET}"
        exit 1
    fi

    #
    # shellcheck disable=SC1090
    #
    source "$CONFIG_FILE"
}

validate_configuration() {

    printf '%b\n' "${BLUE}Validating configuration...${RESET}"

    local config_errors=0

    #
    # Required numeric SSH values.
    #
    if [[ ! "${SSH_PORT:-}" =~ ^[0-9]+$ ]] ||
    (( 10#$SSH_PORT < 1 || 10#$SSH_PORT > 65535 )); then
        printf '%b SSH_PORT is invalid: %s\n' \
            "${RED}[FAIL]${RESET}" "${SSH_PORT:-empty}"
        config_errors=1
    else
        printf '%b SSH_PORT=%s\n' \
            "${GREEN}[OK]${RESET}" "$SSH_PORT"
    fi

    #
    # SSH MaxAuthTries.
    #
    if [[ "${SSH_MAX_AUTH_TRIES:-}" =~ ^[0-9]+$ ]]; then
        printf '%b SSH_MAX_AUTH_TRIES=%s\n' \
            "${GREEN}[OK]${RESET}" "$SSH_MAX_AUTH_TRIES"
    else
        printf '%b SSH_MAX_AUTH_TRIES is invalid.\n' \
            "${RED}[FAIL]${RESET}"
        config_errors=1
    fi

    #
    # SSH MaxSessions.
    #
    if [[ "${SSH_MAX_SESSIONS:-}" =~ ^[0-9]+$ ]]; then
        printf '%b SSH_MAX_SESSIONS=%s\n' \
            "${GREEN}[OK]${RESET}" "$SSH_MAX_SESSIONS"
    else
        printf '%b SSH_MAX_SESSIONS is invalid.\n' \
            "${RED}[FAIL]${RESET}"
        config_errors=1
    fi

    #
    # Password parameters.
    #
    local numeric_vars=(
        PASSWORD_MAX_DAYS
        PASSWORD_MIN_DAYS
        PASSWORD_WARN_DAYS
        PASSWORD_INACTIVE_DAYS
        PASSWORD_MIN_LENGTH
        PASSWORD_MIN_UPPER
        PASSWORD_MIN_LOWER
        PASSWORD_MIN_DIGITS
        PASSWORD_MIN_OTHER
        PASSWORD_MAX_REPEAT
        PASSWORD_MAX_SEQUENCE
        PASSWORD_MAX_CLASS_REPEAT
        PASSWORD_DIFOK
        PASSWORD_HISTORY
        FAILLOCK_DENY
        FAILLOCK_UNLOCK_TIME
        FAILLOCK_FAIL_INTERVAL
        KERNEL_SUID_DUMPABLE
        KERNEL_DMESG_RESTRICT
        KERNEL_RANDOMIZE_VA_SPACE
        NET_IPV4_ALL_SEND_REDIRECTS
        NET_IPV4_DEFAULT_SEND_REDIRECTS
        NET_IPV4_ALL_ACCEPT_REDIRECTS
        NET_IPV4_DEFAULT_ACCEPT_REDIRECTS
        NET_IPV4_ALL_SECURE_REDIRECTS
        NET_IPV4_DEFAULT_SECURE_REDIRECTS
        NET_IPV4_ALL_RP_FILTER
        NET_IPV4_DEFAULT_RP_FILTER
        NET_IPV4_ALL_ACCEPT_SOURCE_ROUTE
        NET_IPV4_DEFAULT_ACCEPT_SOURCE_ROUTE
        NET_IPV4_ALL_LOG_MARTIANS
        NET_IPV4_DEFAULT_LOG_MARTIANS
        NET_IPV4_TCP_SYNCOOKIES
        NET_IPV6_ALL_FORWARDING
        NET_IPV6_DEFAULT_FORWARDING
        NET_IPV6_ALL_ACCEPT_REDIRECTS
        NET_IPV6_DEFAULT_ACCEPT_REDIRECTS
        NET_IPV6_ALL_ACCEPT_SOURCE_ROUTE
        NET_IPV6_DEFAULT_ACCEPT_SOURCE_ROUTE
        NET_IPV6_ALL_ACCEPT_RA
        NET_IPV6_DEFAULT_ACCEPT_RA
    )

    local variable

    for variable in "${numeric_vars[@]}"; do

        if [[ "${!variable:-}" =~ ^[0-9]+$ ]]; then
            printf '%b %s=%s\n' \
                "${GREEN}[OK]${RESET}" \
                "$variable" \
                "${!variable}"
        else
            printf '%b %s is missing or invalid.\n' \
                "${RED}[FAIL]${RESET}" \
                "$variable"
            config_errors=1
        fi
    done

    local boolean_vars=(
        ENABLE_REMEDIATION
        CONFIGURE_TMP_MOUNT
        ENABLE_APPARMOR
        APPARMOR_RESTRICT_UNPRIVILEGED_UNCONFINED
        DISABLE_APPORT
        DEV_SHM_NOEXEC
        GRUB_PASSWORD_ENABLED
        HARDEN_IPV6
        INSTALL_AIDE
        ENABLE_AIDE_TIMER
        INSTALL_RSYSLOG
        ENABLE_RSYSLOG
        INSTALL_AUDITD
        ENABLE_AUDITD
        REQUIRE_SSH_UFW_RULE
        DISABLE_ATM_MODULE
        DISABLE_CAN_MODULE
        DISABLE_SCTP_MODULE
        DISABLE_TIPC_MODULE
        REMOVE_TELNET_CLIENT
        REMOVE_FTP_CLIENT
        REMOTE_SYSLOG_ENABLED
        ISSUE_ENABLED
        ISSUE_NET_ENABLED
        MOTD_ENABLED
        PAM_MOTD_ENABLED
    )

    for variable in "${boolean_vars[@]}"; do
        if [[ "${!variable:-}" == "yes" || "${!variable:-}" == "no" ]]; then
            printf '%b %s=%s\n' "${GREEN}[OK]${RESET}" "$variable" "${!variable}"
        else
            printf '%b %s must be yes or no.\n' "${RED}[FAIL]${RESET}" "$variable"
            config_errors=1
        fi
    done

    if [[ "${DEFAULT_UMASK:-}" =~ ^[0-7]{3,4}$ ]]; then
        printf '%b DEFAULT_UMASK=%s\n' "${GREEN}[OK]${RESET}" "$DEFAULT_UMASK"
    else
        printf '%b DEFAULT_UMASK is invalid.\n' "${RED}[FAIL]${RESET}"
        config_errors=1
    fi

        if [[ "${CONFIGURE_TMP_MOUNT:-}" == "yes" &&
                    ! "${TMPFS_TMP_SIZE:-}" =~ ^[1-9][0-9]?%$ ]]; then
                printf '%b TMPFS_TMP_SIZE must be between 1%% and 99%%.\n' "${RED}[FAIL]${RESET}"
                config_errors=1
        fi

    if [[ "${REMOTE_SYSLOG_ENABLED:-no}" == "yes" &&
          "${REMOTE_SYSLOG_PROTOCOL:-}" != "tcp" &&
          "${REMOTE_SYSLOG_PROTOCOL:-}" != "udp" ]]; then
        printf '%b REMOTE_SYSLOG_PROTOCOL must be tcp or udp.\n' "${RED}[FAIL]${RESET}"
        config_errors=1
    fi

    local port_variable port_list configured_ports port_value
    for port_variable in UFW_ALLOWED_TCP_PORTS UFW_ALLOWED_UDP_PORTS; do
        port_list="${!port_variable:-}"
        IFS=', ' read -ra configured_ports <<< "$port_list"
        for port_value in "${configured_ports[@]}"; do
            [[ -z "$port_value" ]] && continue
            if [[ ! "$port_value" =~ ^[0-9]+$ ]] ||
               (( 10#$port_value < 1 || 10#$port_value > 65535 )); then
                printf '%b Invalid port in %s: %s\n' \
                    "${RED}[FAIL]${RESET}" "$port_variable" "$port_value"
                config_errors=1
            fi
        done
    done

    #
    # UFW SSH protection.
    #
    if [[ "${REQUIRE_SSH_UFW_RULE:-}" == "yes" ||
          "${REQUIRE_SSH_UFW_RULE:-}" == "no" ]]; then
        printf '%b REQUIRE_SSH_UFW_RULE=%s\n' \
            "${GREEN}[OK]${RESET}" \
            "$REQUIRE_SSH_UFW_RULE"
    else
        printf '%b REQUIRE_SSH_UFW_RULE must be yes or no.\n' \
            "${RED}[FAIL]${RESET}"
        config_errors=1
    fi

    #
    # Remote logging.
    #
    if [[ "${REMOTE_SYSLOG_ENABLED:-no}" == "yes" ]]; then

        if [[ ! "${REMOTE_SYSLOG_HOST:-}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
            printf '%b REMOTE_SYSLOG_HOST is required when remote logging is enabled.\n' \
                "${RED}[FAIL]${RESET}"
            config_errors=1
        else
            printf '%b Remote syslog host=%s\n' \
                "${GREEN}[OK]${RESET}" \
                "$REMOTE_SYSLOG_HOST"
        fi

          if [[ ! "${REMOTE_SYSLOG_PORT:-}" =~ ^[0-9]+$ ]] ||
              (( 10#$REMOTE_SYSLOG_PORT < 1 || 10#$REMOTE_SYSLOG_PORT > 65535 )); then
            printf '%b REMOTE_SYSLOG_PORT is invalid.\n' \
                "${RED}[FAIL]${RESET}"
            config_errors=1
        fi
    fi

    #
    # GRUB password.
    #
    if [[ "${GRUB_PASSWORD_HASH:-}" == "" ]]; then
        printf '%b GRUB_PASSWORD_HASH is empty; GRUB password remediation will require manual configuration.\n' \
            "${YELLOW}[WARNING]${RESET}"
    else
        printf '%b GRUB_PASSWORD_HASH is configured.\n' \
            "${GREEN}[OK]${RESET}"
    fi

    if [[ "$config_errors" -ne 0 ]]; then
        printf '\n'
        printf '%b\n' "${RED}ERROR: Configuration validation failed.${RESET}"
        exit 1
    fi

    printf '\n'
}

###############################################################################
# Source common library
###############################################################################

load_common_library() {

    if [[ ! -f "$COMMON_LIB" ]]; then
        printf '%b\n' "${RED}ERROR: common.sh not found.${RESET}"
        exit 1
    fi

    #
    # shellcheck disable=SC1090
    #
    source "$COMMON_LIB"
}

###############################################################################
# Section execution
###############################################################################

run_section() {

    local section_name="$1"
    local section_file="$2"
    local action="$3"

    MODE="$action"
    export MODE

    printf '\n'
    printf '%b\n' "${CYAN}============================================================${RESET}"
    printf '%b\n' "${CYAN}${section_name}${RESET}"
    printf '%b\n' "${CYAN}============================================================${RESET}"
    printf '\n'

    if [[ ! -f "$section_file" ]]; then
        printf '%b %s\n' \
            "${RED}[ERROR]${RESET}" \
            "Section file missing: $section_file"

        return 1
    fi

    #
    # Source the section so it can use common.sh and cis.conf.
    #
    # shellcheck disable=SC1090
    source "$section_file"

    #
    # Section 01 and Section 02 use a MODE variable.
    #
    # Section 03, 04, 05 and 06 expose explicit audit/remediation
    # entry points.
    #
    case "$action" in

        audit)

            case "$section_file" in

                "$SECTION_01")
                    MODE="audit"
                    export MODE

                    if declare -F section_01_filesystem_boot >/dev/null 2>&1; then
                        section_01_filesystem_boot
                    else
                        printf '%b\n' \
                            "${RED}section_01_filesystem_boot() not found.${RESET}"
                        return 1
                    fi
                    ;;

                "$SECTION_02")
                    MODE="audit"
                    export MODE

                    if declare -F section_02_services_network >/dev/null 2>&1; then
                        section_02_services_network
                    else
                        printf '%b\n' \
                            "${RED}section_02_services_network() not found.${RESET}"
                        return 1
                    fi
                    ;;

                "$SECTION_03")
                    if declare -F section_03_audit >/dev/null 2>&1; then
                        section_03_audit
                    else
                        printf '%b\n' \
                            "${RED}section_03_audit() not found.${RESET}"
                        return 1
                    fi
                    ;;

                "$SECTION_04")
                    if declare -F section_04_audit >/dev/null 2>&1; then
                        section_04_audit
                    else
                        printf '%b\n' \
                            "${RED}section_04_audit() not found.${RESET}"
                        return 1
                    fi
                    ;;

                "$SECTION_05")
                    if declare -F section_05_audit >/dev/null 2>&1; then
                        section_05_audit
                    else
                        printf '%b\n' \
                            "${RED}section_05_audit() not found.${RESET}"
                        return 1
                    fi
                    ;;

                "$SECTION_06")
                    if declare -F audit_section_06 >/dev/null 2>&1; then
                        audit_section_06
                    else
                        printf '%b\n' \
                            "${RED}audit_section_06() not found.${RESET}"
                        return 1
                    fi
                    ;;

                *)
                    printf '%b\n' \
                        "${RED}Unknown section: $section_file${RESET}"
                    return 1
                    ;;
            esac
            ;;

        remediate)

            case "$section_file" in

                "$SECTION_01")
                    MODE="remediate"
                    export MODE

                    if declare -F section_01_filesystem_boot >/dev/null 2>&1; then
                        section_01_filesystem_boot
                    else
                        printf '%b\n' \
                            "${RED}section_01_filesystem_boot() not found.${RESET}"
                        return 1
                    fi
                    ;;

                "$SECTION_02")
                    MODE="remediate"
                    export MODE

                    if declare -F section_02_services_network >/dev/null 2>&1; then
                        section_02_services_network
                    else
                        printf '%b\n' \
                            "${RED}section_02_services_network() not found.${RESET}"
                        return 1
                    fi
                    ;;

                "$SECTION_03")
                    if declare -F section_03_remediate >/dev/null 2>&1; then
                        section_03_remediate
                    else
                        printf '%b\n' \
                            "${RED}section_03_remediate() not found.${RESET}"
                        return 1
                    fi
                    ;;

                "$SECTION_04")
                    if declare -F section_04_remediate >/dev/null 2>&1; then
                        section_04_remediate
                    else
                        printf '%b\n' \
                            "${RED}section_04_remediate() not found.${RESET}"
                        return 1
                    fi
                    ;;

                "$SECTION_05")
                    if declare -F section_05_remediate >/dev/null 2>&1; then
                        section_05_remediate
                    else
                        printf '%b\n' \
                            "${RED}section_05_remediate() not found.${RESET}"
                        return 1
                    fi
                    ;;

                "$SECTION_06")
                    if declare -F remediate_section_06 >/dev/null 2>&1; then
                        remediate_section_06
                    else
                        printf '%b\n' \
                            "${RED}remediate_section_06() not found.${RESET}"
                        return 1
                    fi
                    ;;

                *)
                    printf '%b\n' \
                        "${RED}Unknown section: $section_file${RESET}"
                    return 1
                    ;;
            esac
            ;;

        *)
            printf '%b\n' \
                "${RED}Invalid section action: $action${RESET}"
            return 1
            ;;
    esac

    return $?
}


###############################################################################
# Audit report
###############################################################################

create_audit_summary() {

    printf '\n'
    printf '%b\n' "${CYAN}============================================================${RESET}"
    printf '%b\n' "${CYAN}FINAL AUDIT SUMMARY${RESET}"
    printf '%b\n' "${CYAN}============================================================${RESET}"

    printf '\n'

    #
    # If common.sh maintains counters, display them.
    #
    if [[ -n "${AUDIT_PASS_COUNT+x}" ]]; then
        printf '%b %s\n' \
            "${GREEN}PASS:${RESET}" \
            "${AUDIT_PASS_COUNT}"
    fi

    if [[ -n "${AUDIT_FAIL_COUNT+x}" ]]; then
        printf '%b %s\n' \
            "${RED}FAIL:${RESET}" \
            "${AUDIT_FAIL_COUNT}"
    fi

    if [[ -n "${AUDIT_WARNING_COUNT+x}" ]]; then
        printf '%b %s\n' \
            "${YELLOW}WARNING:${RESET}" \
            "${AUDIT_WARNING_COUNT}"
    fi

    if [[ -n "${AUDIT_SKIP_COUNT+x}" ]]; then
        printf '%b %s\n' \
            "${YELLOW}SKIP/MANUAL:${RESET}" \
            "${AUDIT_SKIP_COUNT}"
    fi

    printf '\n'
    printf 'Run log : %s\n' "$RUN_LOG"
    printf 'Audit file : %s\n' "$AUDIT_REPORT"
    printf '\n'

    #
    # Create a compact summary report from the run log.
    #
    {
        echo "CIS Ubuntu 24.04 LTS Level 1 Hardening Audit"
        echo "================================================"
        echo
        echo "Host : $(hostname)"
        echo "Date : $(date)"
        echo
        echo "PASS : ${AUDIT_PASS_COUNT:-unknown}"
        echo "FAIL : ${AUDIT_FAIL_COUNT:-unknown}"
        echo "WARNING : ${AUDIT_WARNING_COUNT:-unknown}"
        echo "SKIP : ${AUDIT_SKIP_COUNT:-unknown}"
        echo "Remediation failed : ${REMEDIATION_FAILED:-not applicable}"
        echo "Validation failed : ${VALIDATION_FAILED:-not applicable}"
        echo "Final audit dispatch failed : ${FINAL_AUDIT_FAILED:-not applicable}"
        echo "Backup directory : ${BACKUP_DIR:-unknown}"
        echo
        echo "Run log : $RUN_LOG"
        echo
        echo "Detailed failures/warnings:"
        echo "------------------------------------------------"
        if [[ "${ACTION:-audit}" == "remediate" ]]; then
            awk '/Running final verification audit/{in_final=1} in_final' "$RUN_LOG" \
                | grep -E '\[FAIL\]|\[WARNING\]|\[SKIP\]' || true
        else
            grep -E '\[FAIL\]|\[WARNING\]|\[SKIP\]' "$RUN_LOG" 2>/dev/null || true
        fi
    } > "$AUDIT_REPORT"

    chmod 640 "$AUDIT_REPORT"

    #
    # Return failure when audit failures exist.
    #
    if [[ "${AUDIT_FAIL_COUNT:-0}" -gt 0 ]]; then
        return 1
    fi

    return 0
}

###############################################################################
# Pre-hardening safety checks
###############################################################################

preflight_checks() {

    printf '%b\n' "${BLUE}Running preflight checks...${RESET}"

    #
    # Confirm this is not an empty/uninitialized filesystem.
    #
    if [[ ! -d /etc ]]; then
        printf '%b\n' "${RED}ERROR: /etc is unavailable.${RESET}"
        exit 1
    fi

    #
    # Confirm basic networking commands.
    #
    local commands=(
        apt-get
        awk
        dpkg-query
        sed
        grep
        find
        readlink
        stat
        systemctl
        mount
        sysctl
    )

    local command_name
    local missing=0

    for command_name in "${commands[@]}"; do
        if command -v "$command_name" >/dev/null 2>&1; then
            printf '%b %s\n' \
                "${GREEN}[OK]${RESET}" \
                "$command_name"
        else
            printf '%b %s\n' \
                "${RED}[MISSING]${RESET}" \
                "$command_name"
            missing=1
        fi
    done

    if [[ "$missing" -ne 0 ]]; then
        log_error "Required system commands are missing."
        return 1
    fi

    #
    # Make sure /etc/ssh exists before SSH remediation.
    #
    if [[ -d /etc/ssh ]]; then
        printf '%b /etc/ssh exists\n' "${GREEN}[OK]${RESET}"
    else
        printf '%b /etc/ssh does not exist\n' "${RED}[FAIL]${RESET}"
        exit 1
    fi

    printf '\n'
}

###############################################################################
# Backup information
###############################################################################

show_backup_information() {

    if [[ -n "${BACKUP_DIR:-}" && -d "${BACKUP_DIR:-}" ]]; then
        printf 'Backup directory: %s\n' "$BACKUP_DIR"
    else
        printf 'Backup directory: managed by common.sh\n'
    fi
}

create_pre_remediation_backup() {

    printf '%b\n' "${BLUE}Creating pre-remediation backups...${RESET}"

    local files=(
        /etc/fstab
        /etc/default/grub
        /etc/grub.d/01_cis_security
        /etc/systemd/system/cis-aide-check.service
        /etc/systemd/system/cis-aide-check.timer
        /etc/sysctl.d/99-cis-hardening.conf
        /etc/modprobe.d/99-cis-hardening.conf
        /etc/default/apport
        /etc/issue
        /etc/issue.net
        /etc/motd
        /etc/ssh/sshd_config
        /etc/ssh/sshd_config.d
        /etc/pam.d/common-auth
        /etc/pam.d/common-account
        /etc/pam.d/common-password
        /etc/pam.d/common-session
        /etc/security/pwquality.conf
        /etc/security/faillock.conf
        /etc/login.defs
        /etc/profile.d/99-cis-umask.sh
        /etc/passwd
        /etc/group
        /etc/shadow
        /etc/gshadow
        /etc/default/ufw
        /etc/ufw
        /etc/rsyslog.conf
        /etc/rsyslog.d/99-cis-hardening.conf
        /etc/audit/auditd.conf
        /etc/audit/rules.d/99-cis-hardening.rules
        /etc/crontab
        /etc/cron.d
        /etc/cron.hourly
        /etc/cron.daily
        /etc/cron.weekly
        /etc/cron.monthly
        /etc/cron.yearly
        /etc/sudoers
        /etc/sudoers.d
    )

    local file
    local failed=0

    for file in "${files[@]}"; do
        backup_file "$file" || failed=1
    done

    if [[ "$failed" -ne 0 ]]; then
        log_error "Pre-remediation backup failed; remediation will not run."
        return 1
    fi

    show_backup_information
    return 0
}

validate_remediation_changes() {

    printf '%b\n' "${BLUE}Validating remediated configuration...${RESET}"

    local files=(
        "${SCRIPT_DIR}/hardening.sh"
        "$CONFIG_FILE"
        "$COMMON_LIB"
        "$SECTION_01"
        "$SECTION_02"
        "$SECTION_03"
        "$SECTION_04"
        "$SECTION_05"
        "$SECTION_06"
    )
    local file
    local failed=0

    for file in "${files[@]}"; do
        if bash -n "$file"; then
            printf '%b %s\n' "${GREEN}[OK]${RESET}" "$file"
        else
            printf '%b %s\n' "${RED}[FAIL]${RESET}" "$file"
            failed=1
        fi
    done

    if command -v sshd >/dev/null 2>&1 && ! sshd -t; then
        log_error "sshd configuration validation failed"
        failed=1
    fi

    if command -v rsyslogd >/dev/null 2>&1 &&
       ! rsyslogd -N1 >/dev/null 2>"$LOG_DIR/rsyslog-validation.log"; then
        log_error "rsyslog configuration validation failed"
        failed=1
    fi

    if command -v visudo >/dev/null 2>&1 &&
       ! visudo -c -f /etc/sudoers >/dev/null 2>&1; then
        log_error "sudo configuration validation failed"
        failed=1
    fi

    if [[ "$failed" -eq 0 ]]; then
        printf '%b\n' "${GREEN}Configuration validation passed.${RESET}"
        return 0
    fi

    log_error "One or more post-remediation validations failed."
    return 1
}

###############################################################################
# Final status
###############################################################################

print_final_status() {

    printf '\n'
    printf '%b\n' "${CYAN}============================================================${RESET}"
    printf '%b\n' "${CYAN}HARDENING RUN COMPLETE${RESET}"
    printf '%b\n' "${CYAN}============================================================${RESET}"

    printf '\n'
    printf 'Host : %s\n' "$(hostname)"
    printf 'Completed : %s\n' "$(date)"
    printf 'Log : %s\n' "$RUN_LOG"
    printf 'Report : %s\n' "$AUDIT_REPORT"

    if [[ "${AUDIT_FAIL_COUNT:-0}" -gt 0 || "${RUN_FAILED:-0}" -gt 0 ]]; then

        printf '\n'
        printf '%b\n' "${RED}Result: AUDIT OR EXECUTION FAILURES REMAIN${RESET}"
        printf '%s\n' "Review the audit report and rerun:"
        printf '%s\n' " sudo ./hardening.sh audit"

    elif [[ "${AUDIT_WARNING_COUNT:-0}" -gt 0 ]]; then

        printf '\n'
        printf '%b\n' "${YELLOW}Result: NO AUDIT FAILURES, BUT WARNINGS/MANUAL ITEMS REMAIN${RESET}"
        printf '%s\n' "Review the audit report before the Nessus scan."

    else

        printf '\n'
        printf '%b\n' "${GREEN}Result: AUDIT COMPLETED WITHOUT REPORTED FAILURES${RESET}"

    fi

    printf '\n'
}

###############################################################################
# Audit mode
###############################################################################

run_audit() {

    printf '%b\n' "${BLUE}Starting CIS audit...${RESET}"
    printf '\n'

    #
    # Reset counters when common.sh provides them.
    #
    AUDIT_PASS_COUNT=0
    AUDIT_FAIL_COUNT=0
    AUDIT_WARNING_COUNT=0
    AUDIT_SKIP_COUNT=0
    local dispatch_failed=0

    #
    # Run all six sections in CIS order.
    #
    run_section \
        "01 - Filesystem and Boot" \
        "$SECTION_01" \
        "audit" || dispatch_failed=1

    run_section \
        "02 - Services and Network" \
        "$SECTION_02" \
        "audit" || dispatch_failed=1

    run_section \
        "03 - Firewall and SSH" \
        "$SECTION_03" \
        "audit" || dispatch_failed=1

    run_section \
        "04 - PAM and Accounts" \
        "$SECTION_04" \
        "audit" || dispatch_failed=1

    run_section \
        "05 - Logging and Audit" \
        "$SECTION_05" \
        "audit" || dispatch_failed=1

    run_section \
        "06 - Permissions" \
        "$SECTION_06" \
        "audit" || dispatch_failed=1

    create_audit_summary

    local audit_status=$?

    if [[ "$dispatch_failed" -ne 0 ]]; then
        audit_status=1
        RUN_FAILED=1
    else
        RUN_FAILED=0
    fi

    print_final_status

    return "$audit_status"
}

###############################################################################
# Remediation mode
###############################################################################

run_remediation() {

    printf '%b\n' "${BLUE}Starting CIS remediation...${RESET}"
    printf '\n'

    #
    # Reset counters.
    #
    AUDIT_PASS_COUNT=0
    AUDIT_FAIL_COUNT=0
    AUDIT_WARNING_COUNT=0
    AUDIT_SKIP_COUNT=0
    local final_audit_failed=0

    ###########################################################################
    # Initial audit
    ###########################################################################

    printf '%b\n' "${CYAN}Running baseline audit before remediation...${RESET}"
    printf '\n'

    run_section \
        "01 - Filesystem and Boot - Baseline" \
        "$SECTION_01" \
        "audit"

    run_section \
        "02 - Services and Network - Baseline" \
        "$SECTION_02" \
        "audit"

    run_section \
        "03 - Firewall and SSH - Baseline" \
        "$SECTION_03" \
        "audit"

    run_section \
        "04 - PAM and Accounts - Baseline" \
        "$SECTION_04" \
        "audit"

    run_section \
        "05 - Logging and Audit - Baseline" \
        "$SECTION_05" \
        "audit"

    run_section \
        "06 - Permissions - Baseline" \
        "$SECTION_06" \
        "audit"

    ###########################################################################
    # Confirmation
    ###########################################################################

    printf '\n'
    printf '%b\n' "${YELLOW}The remediation mode will modify system configuration.${RESET}"
    printf '%s\n' "A pre-remediation backup will be created before any changes."
    printf '\n'

    if [[ "${ENABLE_REMEDIATION:-no}" != "yes" ]]; then
        log_error "Remediation is disabled by ENABLE_REMEDIATION in cis.conf."
        return 1
    fi

    ###########################################################################
    # Remediation
    ###########################################################################

    printf '%b\n' "${CYAN}Applying CIS remediation in section order...${RESET}"
    printf '\n'

    local remediation_failed=0

    if ! create_pre_remediation_backup; then
        remediation_failed=1
    else
        run_section \
            "01 - Filesystem and Boot - Remediation" \
            "$SECTION_01" \
            "remediate" || remediation_failed=1

    run_section \
        "02 - Services and Network - Remediation" \
        "$SECTION_02" \
        "remediate" || remediation_failed=1

    run_section \
        "03 - Firewall and SSH - Remediation" \
        "$SECTION_03" \
        "remediate" || remediation_failed=1

    run_section \
        "04 - PAM and Accounts - Remediation" \
        "$SECTION_04" \
        "remediate" || remediation_failed=1

    run_section \
        "05 - Logging and Audit - Remediation" \
        "$SECTION_05" \
        "remediate" || remediation_failed=1

    run_section \
        "06 - Permissions - Remediation" \
        "$SECTION_06" \
        "remediate" || remediation_failed=1
    fi

    local validation_failed=0
    validate_remediation_changes || validation_failed=1

    ###########################################################################
    # Final audit
    ###########################################################################

    printf '\n'
    printf '%b\n' "${CYAN}============================================================${RESET}"
    printf '%b\n' "${CYAN}Running final verification audit...${RESET}"
    printf '%b\n' "${CYAN}============================================================${RESET}"
    printf '\n'

    #
    # Reset counters for final verification.
    #
    AUDIT_PASS_COUNT=0
    AUDIT_FAIL_COUNT=0
    AUDIT_WARNING_COUNT=0
    AUDIT_SKIP_COUNT=0

    run_section \
        "01 - Filesystem and Boot - Final Audit" \
        "$SECTION_01" \
        "audit" || final_audit_failed=1

    run_section \
        "02 - Services and Network - Final Audit" \
        "$SECTION_02" \
        "audit" || final_audit_failed=1

    run_section \
        "03 - Firewall and SSH - Final Audit" \
        "$SECTION_03" \
        "audit" || final_audit_failed=1

    run_section \
        "04 - PAM and Accounts - Final Audit" \
        "$SECTION_04" \
        "audit" || final_audit_failed=1

    run_section \
        "05 - Logging and Audit - Final Audit" \
        "$SECTION_05" \
        "audit" || final_audit_failed=1

    run_section \
        "06 - Permissions - Final Audit" \
        "$SECTION_06" \
        "audit" || final_audit_failed=1

    ###########################################################################
    # Report
    ###########################################################################

    REMEDIATION_FAILED="$remediation_failed"
    VALIDATION_FAILED="$validation_failed"
    FINAL_AUDIT_FAILED="$final_audit_failed"

    create_audit_summary
    local final_status=$?

    if [[ "$remediation_failed" -ne 0 || "$validation_failed" -ne 0 || "$final_audit_failed" -ne 0 ]]; then
        final_status=1
    fi

    RUN_FAILED=0
    if [[ "$final_status" -ne 0 ]]; then
        RUN_FAILED=1
    fi

    print_final_status

    return "$final_status"
}

###############################################################################
# Main
###############################################################################

main() {

    local action="${1:-}"
    ACTION="$action"

    case "$action" in
        audit|remediate)
            ;;
        -h|--help|help)
            print_banner
            print_usage
            exit 0
            ;;
        "")
            print_banner
            print_usage
            exit 1
            ;;
        *)
            printf '%b\n' "${RED}ERROR: Unknown command: $action${RESET}"
            print_usage
            exit 1
            ;;
    esac

    #
    # Root check must happen before creating /var/log/cis-hardening.
    #
    check_root

    print_banner

    #
    # Verify OS before making any changes.
    #
    check_os

    #
    # Verify project files.
    #
    check_required_files

    #
    # Load configuration before validating configuration values.
    #
    load_configuration

    validate_configuration

    #
    # Load common functions.
    #
    load_common_library

    #
    # Syntax-check all section files.
    #
    check_section_syntax

    #
    # Create logging after the project structure has been validated.
    #
    initialize_logging "$@"

    #
    # Basic system checks.
    #
    preflight_checks || return 1

    printf '%b\n' "${BLUE}Action: $action${RESET}"
    printf '\n'

    case "$action" in

        audit)
            run_audit
            return $?
            ;;

        remediate)
            run_remediation
            return $?
            ;;

    esac
}

main "$@"
exit $?
