#!/usr/bin/env bash
#
# CIS Ubuntu 24.04 LTS Level 1 Hardening
#
# Unified CIS controller, common helpers, and all hardening sections
#
# Usage:
# sudo ./hardening.sh audit
# sudo ./hardening.sh remediate
# sudo ./hardening.sh verify
# ./test.sh
#
# Configuration is embedded below. Tests are run separately with ./test.sh.

set -o pipefail

###############################################################################
# Script paths
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Embedded CIS configuration
# ============================================================
# CIS Ubuntu 24.04 LTS v2.0.0 - Level 1
# Environment Configuration
# ============================================================

# ------------------------------------------------------------
# GENERAL
# ------------------------------------------------------------

HOSTNAME_EXPECTED=""

# Set to yes only when this machine is intentionally being
# hardened and tested.
ENABLE_REMEDIATION="yes"

# Package upgrades can restart services or change application behavior.
# Enable only when maintenance-window upgrades are approved.
APPLY_PACKAGE_UPDATES="no"


# ------------------------------------------------------------
# SSH
# ------------------------------------------------------------

SSH_PORT="22"

SSH_MAX_AUTH_TRIES="3"
SSH_MAX_SESSIONS="10"
SSH_MAX_STARTUPS="10:30:60"

SSH_CLIENT_ALIVE_INTERVAL="15"
SSH_CLIENT_ALIVE_COUNT_MAX="3"

SSH_LOG_LEVEL="VERBOSE"

SSH_PERMIT_ROOT_LOGIN="no"
SSH_PERMIT_EMPTY_PASSWORDS="no"
SSH_PERMIT_USER_ENVIRONMENT="no"

SSH_IGNORE_RHOSTS="yes"

SSH_ALLOW_TCP_FORWARDING="no"
SSH_ALLOW_AGENT_FORWARDING="no"
SSH_X11_FORWARDING="no"

# Leave empty unless your environment specifically requires
# AllowUsers / AllowGroups.
SSH_ALLOW_USERS=""
SSH_ALLOW_GROUPS=""


# ------------------------------------------------------------
# SSH BANNER
# ------------------------------------------------------------

SSH_BANNER_FILE="/etc/issue.net"

SSH_BANNER_TEXT="Authorized uses only. All activity may be monitored and reported."


# ------------------------------------------------------------
# PASSWORD POLICY
# ------------------------------------------------------------

PASSWORD_MAX_DAYS="365"
SSH_DENY_USERS=""
SSH_DENY_GROUPS=""
PASSWORD_MIN_DAYS="1"
PASSWORD_WARN_AGE="7"
PASSWORD_WARN_DAYS="7"
PASSWORD_INACTIVE_DAYS="30"

ISSUE_FILE="/etc/issue"
ISSUE_NET_FILE="/etc/issue.net"
MOTD_FILE="/etc/motd"
ISSUE_ENABLED="yes"
ISSUE_NET_ENABLED="yes"
MOTD_ENABLED="yes"
PAM_MOTD_ENABLED="yes"
BANNER_OWNER="root"
BANNER_GROUP="root"
BANNER_MODE="644"
PASSWORD_MIN_LENGTH="14"

PASSWORD_MIN_UPPER="1"
PASSWORD_MIN_LOWER="1"

DEV_SHM_NOEXEC="yes"
PASSWORD_MIN_DIGITS="1"
PASSWORD_MIN_OTHER="1"

PASSWORD_MAX_REPEAT="3"
PASSWORD_MAX_SEQUENCE="3"
GRUB_PASSWORD_ENABLED="no"
PASSWORD_MAX_CLASS_REPEAT="4"

PASSWORD_DIFOK="2"


# Kernel hardening
KERNEL_SUID_DUMPABLE="0"
KERNEL_DMESG_RESTRICT="1"
KERNEL_RANDOMIZE_VA_SPACE="2"

# IPv4 network hardening
NET_IPV4_ALL_SEND_REDIRECTS="0"
NET_IPV4_DEFAULT_SEND_REDIRECTS="0"
NET_IPV4_ALL_ACCEPT_REDIRECTS="0"
NET_IPV4_DEFAULT_ACCEPT_REDIRECTS="0"
NET_IPV4_ALL_SECURE_REDIRECTS="0"
NET_IPV4_DEFAULT_SECURE_REDIRECTS="0"
NET_IPV4_ALL_RP_FILTER="1"
NET_IPV4_DEFAULT_RP_FILTER="1"
NET_IPV4_ALL_ACCEPT_SOURCE_ROUTE="0"
NET_IPV4_DEFAULT_ACCEPT_SOURCE_ROUTE="0"
NET_IPV4_ALL_LOG_MARTIANS="1"
NET_IPV4_DEFAULT_LOG_MARTIANS="1"
NET_IPV4_TCP_SYNCOOKIES="1"

# IPv6 network hardening
NET_IPV6_ALL_FORWARDING="0"
NET_IPV6_DEFAULT_FORWARDING="0"
NET_IPV6_ALL_ACCEPT_REDIRECTS="0"
NET_IPV6_DEFAULT_ACCEPT_REDIRECTS="0"
NET_IPV6_ALL_ACCEPT_SOURCE_ROUTE="0"
NET_IPV6_DEFAULT_ACCEPT_SOURCE_ROUTE="0"
NET_IPV6_ALL_ACCEPT_RA="0"
NET_IPV6_DEFAULT_ACCEPT_RA="0"
PASSWORD_HISTORY="24"


# ------------------------------------------------------------
APPARMOR_RESTRICT_UNPRIVILEGED_UNCONFINED="yes"
# ACCOUNT LOCKOUT / FAILLOCK
# ------------------------------------------------------------

FAILLOCK_DENY="5"
ENABLE_AIDE_TIMER="yes"
FAILLOCK_UNLOCK_TIME="900"
FAILLOCK_FAIL_INTERVAL="900"


# ------------------------------------------------------------
# UMASK
# ------------------------------------------------------------

DEFAULT_UMASK="027"


REMOVE_TELNET_CLIENT="yes"
REMOVE_FTP_CLIENT="yes"

# ------------------------------------------------------------
# FIREWALL
# ------------------------------------------------------------

# IMPORTANT:
# Add every port that must remain reachable BEFORE enabling UFW.
#
# Example:
# UFW_ALLOWED_TCP_PORTS="22 80 443"
#
# For our basic EC2 test server SSH must remain allowed.

UFW_ALLOWED_TCP_PORTS="22"

UFW_ALLOWED_UDP_PORTS=""


# ------------------------------------------------------------
# REMOTE SYSLOG
# ------------------------------------------------------------

# Keep empty until the organization provides the actual
# remote logging server.

REMOTE_SYSLOG_ENABLED="no"

REMOTE_SYSLOG_HOST=""
REMOTE_SYSLOG_PORT="514"
REMOTE_SYSLOG_PROTOCOL="udp"


# ------------------------------------------------------------
# GRUB
# ------------------------------------------------------------

# DO NOT put a real password here.
#
# Generate the PBKDF2 hash separately with:
#
# grub-mkpasswd-pbkdf2
#
# Quote the completed hash with single quotes; GRUB hashes contain '$'.
# Example: GRUB_PASSWORD_HASH='grub.pbkdf2.sha512....'
#
# Then place the generated hash here on the test server.

GRUB_SUPERUSER="grubadmin"
GRUB_PASSWORD_HASH=""


# ------------------------------------------------------------
# FILESYSTEM
# ------------------------------------------------------------

# Do NOT automatically repartition an existing server.
#
# For EC2 testing, these remain disabled until the actual
# mount design has been confirmed.

CONFIGURE_TMP_MOUNT="yes"
TMPFS_TMP_SIZE="10%"
CONFIGURE_VAR_MOUNT="no"
CONFIGURE_HOME_MOUNT="no"


# ------------------------------------------------------------
# KERNEL MODULES
# ------------------------------------------------------------

# Modules required by CIS controls.
#
# Do not enable these blindly on an application server.

DISABLE_ATM_MODULE="yes"
DISABLE_CAN_MODULE="yes"
DISABLE_SCTP_MODULE="yes"
DISABLE_TIPC_MODULE="yes"


# ------------------------------------------------------------
# IPV6
# ------------------------------------------------------------

# yes = configure IPv6 CIS settings
# no = leave IPv6-related settings unchanged

HARDEN_IPV6="yes"


# ------------------------------------------------------------
# APPARMOR
# ------------------------------------------------------------

ENABLE_APPARMOR="yes"


# ------------------------------------------------------------
# AUTOMATIC ERROR REPORTING
# ------------------------------------------------------------

DISABLE_APPORT="yes"


# ------------------------------------------------------------
# AIDE
# ------------------------------------------------------------

INSTALL_AIDE="yes"


# ------------------------------------------------------------
# RSYSLOG
# ------------------------------------------------------------

INSTALL_RSYSLOG="yes"
ENABLE_RSYSLOG="yes"


# ------------------------------------------------------------
# AUDITD
# ------------------------------------------------------------

INSTALL_AUDITD="yes"
ENABLE_AUDITD="yes"


# ------------------------------------------------------------
# UFW SAFETY
# ------------------------------------------------------------

# NEVER enable UFW without first allowing SSH.

REQUIRE_SSH_UFW_RULE="yes"


# ------------------------------------------------------------
# REBOOT
# ------------------------------------------------------------

ALLOW_REBOOT="no"

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

SECTION_01="embedded:01"
SECTION_02="embedded:02"
SECTION_03="embedded:03"
SECTION_04="embedded:04"
SECTION_05="embedded:05"
SECTION_06="embedded:06"

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
  sudo ./hardening.sh verify
  sudo ./test.sh

Commands:

  audit
      Audit the server against the configured CIS controls.
      No configuration changes are intentionally made.

  remediate
      Apply the configured hardening settings and then run
      a final audit to identify remaining failures/manual items.

  verify
      Run the same read-only checks as audit.

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

    local required_files=("${SCRIPT_DIR}/hardening.sh")

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

    local files=("${SCRIPT_DIR}/hardening.sh")

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
    :
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
        APPLY_PACKAGE_UPDATES
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

    TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
    BACKUP_DIR="/root/cis-backup/$TIMESTAMP"
    LOG_DIR="/root/cis-logs/$TIMESTAMP"
    REMEDIATION_LOG="$LOG_DIR/remediation.log"
    CURRENT_SECTION=""
    APT_UPDATED="no"
    mkdir -p "$BACKUP_DIR" "$LOG_DIR"
    touch "$REMEDIATION_LOG"
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

    case "$section_file" in
        "$SECTION_01"|"$SECTION_02"|"$SECTION_03"|"$SECTION_04"|"$SECTION_05"|"$SECTION_06") ;;
        *) log_error "Unknown embedded section: $section_file"; return 1 ;;
    esac

    # Section functions are embedded in this script.

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

    local files=("${SCRIPT_DIR}/hardening.sh")
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
        log_error "Remediation is disabled by ENABLE_REMEDIATION in the embedded configuration."
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
# Embedded common library
###############################################################################
log() {
    local level="$1"
    shift

    local message="$*"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" \
        | tee -a "$LOG_DIR/hardening.log"
}


log_info() {
    log "INFO" "$*"
}


log_success() {
    log "PASS" "$*"
}


log_warning() {
    log "WARN" "$*"
}


log_error() {
    log "FAIL" "$*"
}


start_section() {
    CURRENT_SECTION="$1"

    echo ""
    echo "============================================================"
    echo "SECTION: $CURRENT_SECTION"
    echo "============================================================"

    log_info "Starting section: $CURRENT_SECTION"
}


# ------------------------------------------------------------
# ROOT CHECK
# ------------------------------------------------------------

require_root() {

    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] This script must be executed as root."
        echo "Use: sudo ./hardening.sh audit"
        exit 1
    fi
}


# ------------------------------------------------------------
# COMMAND CHECK
# ------------------------------------------------------------

command_exists() {
    command -v "$1" >/dev/null 2>&1
}


# ------------------------------------------------------------
# PACKAGE INSTALLATION
# ------------------------------------------------------------

install_package() {

    local package="$1"

    if dpkg-query -W -f='${Status}' "$package" 2>/dev/null \
        | grep -q "install ok installed"
    then
        log_success "Package already installed: $package"
        return 0
    fi

    if [ "$MODE" = "audit" ]; then
        log_warning "[AUDIT] Package required but not installed: $package"
        return 1
    fi

    export DEBIAN_FRONTEND=noninteractive

    if [ "$APT_UPDATED" != "yes" ]; then
        log_info "Refreshing apt package indexes"
        if ! apt-get update; then
            log_error "apt-get update failed"
            return 1
        fi
        APT_UPDATED="yes"
    fi

    log_info "Installing package: $package"

    if apt-get install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "$package"; then
        log_success "Installed: $package"
        return 0
    fi

    log_error "Failed to install: $package"
    return 1
}


remove_package() {

    local package="$1"

    if [ -z "$package" ]; then
        log_error "Package name is required for removal"
        return 1
    fi

    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null \
        | grep -q "install ok installed"
    then
        log_info "Package is not installed: $package"
        return 0
    fi

    log_info "Removing package: $package"

    export DEBIAN_FRONTEND=noninteractive
    if DEBIAN_FRONTEND=noninteractive apt-get remove -y "$package"; then
        log_success "Removed package: $package"
        return 0
    fi

    log_error "Failed to remove package: $package"
    return 1
}


# ------------------------------------------------------------
# COMMAND EXECUTION
# ------------------------------------------------------------

run_command() {

    local command="$1"
    local description="$2"

    log_info "$description"

    bash -c "$command" >> "$LOG_DIR/commands.log" 2>&1

    local rc=$?

    if [ $rc -eq 0 ]; then
        log_success "$description"
    else
        log_error "$description"
    fi

    return $rc
}


# ------------------------------------------------------------
# REMEDIATION
# ------------------------------------------------------------

run_remediation_command() {

    local command="$1"
    local description="$2"

    if [ "$MODE" = "audit" ]; then
        log_warning "[AUDIT ONLY] $description"
        return 0
    fi

    run_command "$command" "$description"
}


# ------------------------------------------------------------
# BACKUP FILE
# ------------------------------------------------------------

backup_file() {

    local file="$1"

    if [ ! -e "$file" ]; then
        return 0
    fi

    local destination="$BACKUP_DIR$file"
    local destination_dir
    destination_dir="$(dirname "$destination")"

    mkdir -p "$destination_dir" || return 1

    if [ -e "$destination" ] || [ -L "$destination" ]; then
        log_info "Original backup already exists: $file"
        return 0
    fi

    if ! cp -a "$file" "$destination"; then
        log_error "Failed to back up: $file"
        return 1
    fi

    log_info "Backed up: $file"
    return 0
}


# ------------------------------------------------------------
# VERIFY FILE PERMISSIONS
# ------------------------------------------------------------

# ------------------------------------------------------------
# SSH VALIDATION
# ------------------------------------------------------------

validate_sshd() {

    if ! command_exists sshd; then
        log_error "sshd command not found"
        return 1
    fi

    if sshd -t 2>>"$LOG_DIR/sshd-validation.log"; then
        log_success "sshd configuration syntax is valid"
        return 0
    fi

    log_error "sshd configuration syntax is INVALID"

    return 1
}


get_sshd_effective_value() {
    local key="${1:-}"
    local effective_config

    [[ -n "$key" ]] || return 1
    command_exists sshd || return 1
    effective_config="$(sshd -T 2>>"$LOG_DIR/sshd-validation.log")" || return 1

    awk -v search_key="${key,,}" '
        tolower($1) == search_key {
            print $2
            exit
        }
    ' <<< "$effective_config"
}

###############################################################################
# CIS SECTION HELPERS
###############################################################################

audit_pass() {

 AUDIT_PASS_COUNT=$(( ${AUDIT_PASS_COUNT:-0} + 1 ))

 printf '%b %s\n' \
 "${GREEN:-}[PASS]${RESET:-}" \
 "$*"

 return 0
}


audit_fail() {

 AUDIT_FAIL_COUNT=$(( ${AUDIT_FAIL_COUNT:-0} + 1 ))

 printf '%b %s\n' \
 "${RED:-}[FAIL]${RESET:-}" \
 "$*"

 return 1
}


audit_warning() {

 AUDIT_WARNING_COUNT=$(( ${AUDIT_WARNING_COUNT:-0} + 1 ))

 printf '%b %s\n' \
 "${YELLOW:-}[WARNING]${RESET:-}" \
 "$*"

 return 0
}


audit_skip() {

 AUDIT_SKIP_COUNT=$(( ${AUDIT_SKIP_COUNT:-0} + 1 ))

 printf '%b %s\n' \
 "${CYAN:-}[SKIP]${RESET:-}" \
 "$*"

 return 0
}


end_section() {

 printf '\n'
 printf '%b\n' \
 "${CYAN:-}============================================================${RESET:-}"

 return 0
}


get_mount_options() {

 local mount_point="${1:-}"

 if [[ -z "$mount_point" ]]; then
 return 1
 fi

 findmnt -no OPTIONS --target "$mount_point" 2>/dev/null || true
}


get_sysctl_value() {

 local key="${1:-}"

 if [[ -z "$key" ]]; then
 return 1
 fi

 sysctl -n "$key" 2>/dev/null || true
}


check_expected_value() {

 local control_id="$1"
 local setting="$2"
 local actual="${3:-}"
 local expected="${4:-}"

 if [[ "$actual" == "$expected" ]]; then
     audit_pass "$control_id" "$setting=$actual"
     return 0
 fi

 audit_fail "$control_id" "$setting=$actual; expected $expected"
 return 1
}


package_installed() {

 local package="${1:-}"

 if [[ -z "$package" ]]; then
 return 1
 fi

 dpkg-query \
 -W \
 -f='${Status}' \
 "$package" 2>/dev/null |
 grep -q '^install ok installed$'
}


###############################################################################
# Additional remediation helpers
###############################################################################

set_file_permissions() {

 local file="${1:-}"
 local owner="${2:-}"
 local group="${3:-}"
 local mode="${4:-}"

 if [[ -z "$file" || -z "$owner" || -z "$group" || -z "$mode" ]]; then
 return 1
 fi

 chown "$owner:$group" "$file" && chmod "$mode" "$file"
}


verify_file_permissions() {

 local file="${1:-}"
 local expected_owner="${2:-}"
 local expected_group="${3:-}"
 local expected_mode="${4:-}"

 if [[ ! -e "$file" || -z "$expected_owner" || -z "$expected_group" || -z "$expected_mode" ]]; then
 return 1
 fi

 local actual_owner
 actual_owner="$(stat -c '%U' "$file" 2>/dev/null)" || return 1

 local actual_group
 actual_group="$(stat -c '%G' "$file" 2>/dev/null)" || return 1

 local actual_mode
 actual_mode="$(stat -c '%a' "$file" 2>/dev/null)" || return 1

 [[ "$actual_owner" == "$expected_owner" &&
    "$actual_group" == "$expected_group" &&
    "$actual_mode" == "$expected_mode" ]]
}


set_sysctl_value() {

 local key="${1:-}"
 local value="${2:-}"

 if [[ -z "$key" || -z "$value" ]]; then
 return 1
 fi

 sysctl -w "${key}=${value}" >> "$REMEDIATION_LOG" 2>&1
}


persist_sysctl_value() {

 local key="${1:-}"
 local value="${2:-}"
 local config_file="${3:-/etc/sysctl.d/99-cis-hardening.conf}"

 if [[ -z "$key" || -z "$value" ]]; then
 return 1
 fi

 touch "$config_file" || return 1

 if grep -qE "^[[:space:]]*${key//./\\.}[[:space:]]*=" "$config_file"; then
 sed -i \
 "s|^[[:space:]]*${key//./\\.}[[:space:]]*=.*|${key} = ${value}|" \
 "$config_file"
 else
 printf '%s = %s\n' "$key" "$value" >> "$config_file"
 fi

 sysctl -w "${key}=${value}" >/dev/null
}


safe_reload_sshd() {

 if ! command_exists sshd; then
 return 1
 fi

 if ! sshd -t; then
 return 1
 fi

 if systemctl reload ssh 2>/dev/null; then
 return 0
 fi

 if systemctl reload sshd 2>/dev/null; then
 return 0
 fi

 return 1
}

#!/bin/bash

# ============================================================
# CIS Ubuntu 24.04 LTS
# Section 01 - Filesystem / Boot / Kernel / AppArmor
#
# File:
# sections/01_filesystem_boot.sh
#
# Controls covered in this section include:
#
# 1.1.2.1.1 /tmp filesystem
# 1.1.2.2.4 /dev/shm noexec
# 1.5.4 fs.suid_dumpable
# 1.5.5 kernel.dmesg_restrict
# 1.5.7 Automatic Error Reporting
# 1.3.1.4 AppArmor restriction
# 1.6.1 /etc/motd
# 1.6.3 /etc/issue.net
# 1.6.5 SSH warning banner
# 1.6.6 /etc/motd access
# 1.6.9 pam_motd access
#
# AIDE-related checks are also prepared here because they are
# filesystem-integrity controls.
#
# IMPORTANT:
# - Do not automatically repartition /tmp.
# - Do not generate a GRUB password automatically.
# - GRUB password hash must be supplied through the embedded configuration.
# ============================================================


# ============================================================
# 1. SECTION INITIALIZATION
# ============================================================

section_01_filesystem_boot() {
    start_section "01 - FILESYSTEM / BOOT / KERNEL / APPARMOR"

    local status=0

    case "${MODE:-audit}" in

        audit)
            audit_01_filesystem_boot || status=$?
            ;;

        remediate)
            remediate_01_filesystem_boot || status=$?
            ;;

        verify)
            audit_01_filesystem_boot || status=$?
            ;;

        *)
            log_error \
                "Unknown mode for Section 01: ${MODE:-unknown}"

            return 1
            ;;
    esac

    end_section
    return "$status"
}


# ============================================================
# 2. AUDIT ENTRY POINT
# ============================================================

audit_01_filesystem_boot() {

    log_info "Starting filesystem and boot audit."

    audit_tmp_filesystem
    audit_dev_shm
    audit_grub_password
    audit_kernel_settings
    audit_apparmor
    audit_apport
    audit_banners
    audit_pam_motd
    audit_aide

    log_info "Filesystem and boot audit completed."
}


# ============================================================
# 3. REMEDIATION ENTRY POINT
# ============================================================

remediate_01_filesystem_boot() {

    log_info "Starting filesystem and boot remediation."

    local failed=0

    remediate_package_updates || failed=1
    remediate_dev_shm || failed=1
    remediate_grub_password || failed=1
    remediate_kernel_settings || failed=1
    remediate_apparmor || failed=1
    remediate_apport || failed=1
    remediate_banners || failed=1
    remediate_pam_motd || failed=1
    remediate_aide || failed=1

    #
    # /tmp is deliberately not automatically repartitioned.
    #
    if [ "${CONFIGURE_TMP_MOUNT:-no}" = "yes" ]; then

        log_warning \
            "Automatic /tmp filesystem configuration is enabled."

        log_warning \
            "Review the /tmp filesystem requirement before continuing."

        remediate_tmp_filesystem || failed=1

    else

        log_info \
            "Automatic /tmp filesystem configuration is disabled."

        log_info \
            "The /tmp filesystem control will be audited only."
    fi

    log_info "Filesystem and boot remediation completed."
    return "$failed"
}


remediate_package_updates() {
    if [[ "${APPLY_PACKAGE_UPDATES:-no}" != "yes" ]]; then
        log_info "Package upgrades are disabled; enable APPLY_PACKAGE_UPDATES after approving a maintenance window."
        return 0
    fi

    command_exists apt-get || {
        log_error "apt-get is required for security package updates."
        return 1
    }

    apt-get update || {
        log_error "apt-get update failed."
        return 1
    }

    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --with-new-pkgs || {
        log_error "Installing package updates failed."
        return 1
    }
}


# ============================================================
# 4. /tmp FILESYSTEM
#
# CIS CONTROL:
# 1.1.2.1.1
#
# IMPORTANT:
# We do not repartition an existing EC2 instance automatically.
# ============================================================

audit_tmp_filesystem() {
    local control_id="1.1.2.1.1"
    local mount_target filesystem_type options persistent_options option

    mount_target="$(findmnt -n -o TARGET --target /tmp 2>/dev/null)"
    filesystem_type="$(findmnt -n -o FSTYPE --target /tmp 2>/dev/null)"
    options="$(get_mount_options /tmp)"
    persistent_options="$(awk '$1 !~ /^#/ && $2 == "/tmp" {print $4; exit}' /etc/fstab 2>/dev/null)"

    if [[ "$mount_target" != "/tmp" ]]; then
        audit_fail "$control_id" "/tmp is not a separate mount point"
        return 1
    fi

    if [[ -z "$persistent_options" ]]; then
        audit_fail "$control_id" "/tmp mount is not configured persistently in /etc/fstab"
        return 1
    fi

    for option in nodev nosuid noexec; do
        if ! grep -Eq "(^|,)${option}(,|$)" <<< "$options" ||
           ! grep -Eq "(^|,)${option}(,|$)" <<< "$persistent_options"; then
            audit_fail "$control_id" "/tmp is missing persistent or active $option"
            return 1
        fi
    done

    audit_pass "$control_id" "/tmp is a separate $filesystem_type mount with nodev,nosuid,noexec"
    return 0
}


update_tmp_fstab() {
    local fstab="${1:-/etc/fstab}"
    local tmp_size="${2:-10%}"
    local fstab_tmp

    [[ -f "$fstab" && "$tmp_size" =~ ^[1-9][0-9]?%$ ]] || return 1
    fstab_tmp="$(mktemp "${fstab}.XXXXXX")" || return 1

    if ! awk -v tmp_size="$tmp_size" '
        function has_option(options, wanted, fields, count, field_index) {
            count = split(options, fields, ",")
            for (field_index = 1; field_index <= count; field_index++) {
                if (wanted ~ /=$/ ? index(fields[field_index], wanted) == 1 : fields[field_index] == wanted) return 1
            }
            return 0
        }
        function add_option(options, wanted) {
            if (has_option(options, wanted)) return options
            return options == "" ? wanted : options "," wanted
        }
        function remove_option(options, unwanted, fields, count, field_index, result) {
            count = split(options, fields, ",")
            result = ""
            for (field_index = 1; field_index <= count; field_index++) {
                if (fields[field_index] != unwanted && fields[field_index] != "") {
                    result = result == "" ? fields[field_index] : result "," fields[field_index]
                }
            }
            return result
        }
        BEGIN { found = 0 }
        $1 !~ /^#/ && $2 == "/tmp" {
            if (!found) {
                if ($3 == "tmpfs") {
                    if (!has_option($4, "size=")) $4 = add_option($4, "size=" tmp_size)
                    if (!has_option($4, "mode=")) $4 = add_option($4, "mode=1777")
                }
                $4 = remove_option($4, "noauto")
                $4 = add_option($4, "nodev")
                $4 = add_option($4, "nosuid")
                $4 = add_option($4, "noexec")
                print
                found = 1
            }
            next
        }
        { print }
        END {
            if (!found) {
                print "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec,mode=1777,size=" tmp_size " 0 0"
            }
        }
    ' "$fstab" > "$fstab_tmp"; then
        rm -f "$fstab_tmp"
        return 1
    fi

    if ! chmod --reference="$fstab" "$fstab_tmp" || ! mv -f "$fstab_tmp" "$fstab"; then
        rm -f "$fstab_tmp"
        return 1
    fi
}


remediate_tmp_filesystem() {
    if [[ "${CONFIGURE_TMP_MOUNT:-no}" != "yes" ]]; then
        log_warning "Automatic /tmp configuration is disabled in the embedded configuration."
        return 0
    fi

    local fstab="/etc/fstab"
    backup_file "$fstab" || return 1
    update_tmp_fstab "$fstab" "${TMPFS_TMP_SIZE:-10%}" || return 1

    local mount_target
    mount_target="$(findmnt -n -o TARGET --target /tmp 2>/dev/null)"
    if [[ "$mount_target" == "/tmp" ]]; then
        mount -o remount,nodev,nosuid,noexec /tmp >> "$REMEDIATION_LOG" 2>&1 || return 1
    else
        mount /tmp >> "$REMEDIATION_LOG" 2>&1 || return 1
    fi

    chmod 1777 /tmp || return 1
    audit_tmp_filesystem
}


# ============================================================
# 5. /dev/shm
#
# CIS CONTROL:
# 1.1.2.2.4
#
# Required:
# noexec
# ============================================================

audit_dev_shm() {

    local control_id="1.1.2.2.4"

    if ! mountpoint -q /dev/shm; then
        audit_fail "$control_id" "/dev/shm is not a mount point"
        return 1
    fi

    local active_options
    active_options="$(get_mount_options /dev/shm)"

    local persistent_options
    persistent_options="$(awk '$1 !~ /^#/ && $2 == "/dev/shm" {print $4; exit}' /etc/fstab 2>/dev/null)"

    if printf '%s\n' "$active_options" | tr ',' '\n' | grep -qx "noexec" &&
       printf '%s\n' "$persistent_options" | tr ',' '\n' | grep -qx "noexec"; then
        audit_pass "$control_id" "/dev/shm has noexec at runtime and in /etc/fstab"
        return 0
    fi

    audit_fail "$control_id" "/dev/shm noexec is missing at runtime or in /etc/fstab"
    return 1
}


remediate_dev_shm() {

    if [ "${DEV_SHM_NOEXEC:-yes}" != "yes" ]; then
        log_info "DEV_SHM_NOEXEC is disabled."
        return 0
    fi

    local fstab="/etc/fstab"
    backup_file "$fstab" || return 1

    local fstab_tmp
    fstab_tmp="$(mktemp "${fstab}.XXXXXX")" || return 1

    if ! awk '
        BEGIN { found = 0 }
        $1 !~ /^#/ && $2 == "/dev/shm" {
            if (!found) {
                $4 = "defaults,nodev,nosuid,noexec"
                print
                found = 1
            }
            next
        }
        { print }
        END {
            if (!found) {
                print "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"
            }
        }
    ' "$fstab" > "$fstab_tmp"; then
        rm -f "$fstab_tmp"
        log_error "Could not prepare persistent /dev/shm mount options."
        return 1
    fi

    if ! chown --reference="$fstab" "$fstab_tmp" ||
       ! chmod --reference="$fstab" "$fstab_tmp" ||
       ! mv -f "$fstab_tmp" "$fstab"; then
        rm -f "$fstab_tmp"
        log_error "Could not update $fstab."
        return 1
    fi

    if mountpoint -q /dev/shm; then
        if mount -o remount,nodev,nosuid,noexec /dev/shm \
            >> "$REMEDIATION_LOG" 2>&1; then
            log_success "/dev/shm remounted with nodev,nosuid,noexec"
            return 0
        fi

        log_error "Unable to remount /dev/shm."
        return 1
    fi

    log_warning "/dev/shm is not currently mounted; reboot/mount is required."
    return 0
}


# ============================================================
# 6. GRUB BOOTLOADER PASSWORD
#
# CIS CONTROL:
# 1.4.1
#
# We require:
# set superusers=
# password_pbkdf2
#
# The password hash must come from the embedded configuration.
# ============================================================

audit_grub_password() {

    local control_id="1.4.1"

    if [[ "${GRUB_PASSWORD_ENABLED:-no}" != "yes" ||
          -z "${GRUB_PASSWORD_HASH:-}" ]]; then
        audit_skip \
            "$control_id" \
            "GRUB password is a manual control; enable it and configure a PBKDF2 hash to audit"
        return 0
    fi

    local grub_cfg="/boot/grub/grub.cfg"

    if [ ! -f "$grub_cfg" ]; then

        audit_fail \
            "$control_id" \
            "GRUB configuration file not found"

        return 1
    fi


    local superuser_present="no"
    local password_present="no"


    if grep -Fq -- "set superusers=\"${GRUB_SUPERUSER:-grubadmin}\"" "$grub_cfg"; then
        superuser_present="yes"
    fi

    if [[ -n "${GRUB_PASSWORD_HASH:-}" ]]; then
        if grep -Fq -- "password_pbkdf2 ${GRUB_SUPERUSER:-grubadmin} ${GRUB_PASSWORD_HASH}" "$grub_cfg"; then
            password_present="yes"
        fi
    elif grep -Eq '^[[:space:]]*password_pbkdf2[[:space:]]+' "$grub_cfg"; then
        password_present="yes"
    fi


    if [ "$superuser_present" = "yes" ] &&
       [ "$password_present" = "yes" ]
    then

        audit_pass \
            "$control_id" \
            "GRUB superuser and password_pbkdf2 configuration found"

        return 0
    fi


    audit_fail \
        "$control_id" \
        "GRUB bootloader password configuration is missing"

    return 1
}


remediate_grub_password() {

    if [ "${GRUB_PASSWORD_ENABLED:-no}" != "yes" ]; then

        log_warning \
            "GRUB_PASSWORD_ENABLED is not enabled."

        log_warning \
            "GRUB password remediation skipped."

        log_warning \
            "Generate a hash with: grub-mkpasswd-pbkdf2"

        return 0
    fi


    if [ -z "${GRUB_PASSWORD_HASH:-}" ]; then

        log_error \
            "GRUB_PASSWORD_HASH is empty."

        log_error \
            "Run: grub-mkpasswd-pbkdf2"

        log_error \
            "Then place the generated hash in the embedded configuration."

        return 1
    fi


    if ! command_exists update-grub; then

        log_error \
            "update-grub command not found."

        return 1
    fi


    local grub_custom="/etc/grub.d/01_cis_security"


    backup_file "$grub_custom"


    cat > "$grub_custom" <<EOF
#!/bin/sh
set -e

cat <<'GRUB_CIS'
set superusers="${GRUB_SUPERUSER}"
password_pbkdf2 ${GRUB_SUPERUSER} ${GRUB_PASSWORD_HASH}
GRUB_CIS
EOF


    chmod 700 "$grub_custom"

    if update-grub >> "$REMEDIATION_LOG" 2>&1; then
        log_success \
            "GRUB configuration regenerated."

        return 0
    fi


    log_error \
        "update-grub failed."

    return 1
}


# ============================================================
# 7. KERNEL SECURITY SETTINGS
#
# CIS:
# 1.5.4 fs.suid_dumpable
# 1.5.5 kernel.dmesg_restrict
# 1.5.9 kernel.randomize_va_space
# ============================================================

audit_kernel_settings() {

    local failed=0

    if ! check_expected_value \
        "1.5.4" \
        "fs.suid_dumpable" \
        "$(get_sysctl_value fs.suid_dumpable)" \
        "${KERNEL_SUID_DUMPABLE}"; then
        failed=1
    fi

    if ! check_expected_value \
        "1.5.5" \
        "kernel.dmesg_restrict" \
        "$(get_sysctl_value kernel.dmesg_restrict)" \
        "${KERNEL_DMESG_RESTRICT}"; then
        failed=1
    fi

    if ! check_expected_value \
        "1.5.9" \
        "kernel.randomize_va_space" \
        "$(get_sysctl_value kernel.randomize_va_space)" \
        "${KERNEL_RANDOMIZE_VA_SPACE}"; then
        failed=1
    fi

    return "$failed"
}


remediate_kernel_settings() {

    local sysctl_file="/etc/sysctl.d/99-cis-hardening.conf"

    backup_file "$sysctl_file"


    #
    # fs.suid_dumpable
    #

    persist_sysctl_value \
        "fs.suid_dumpable" \
        "${KERNEL_SUID_DUMPABLE}" \
        "$sysctl_file"

    set_sysctl_value \
        "fs.suid_dumpable" \
        "${KERNEL_SUID_DUMPABLE}"


    #
    # kernel.dmesg_restrict
    #

    persist_sysctl_value \
        "kernel.dmesg_restrict" \
        "${KERNEL_DMESG_RESTRICT}" \
        "$sysctl_file"

    set_sysctl_value \
        "kernel.dmesg_restrict" \
        "${KERNEL_DMESG_RESTRICT}"


    #
    # kernel.randomize_va_space
    #

    persist_sysctl_value \
        "kernel.randomize_va_space" \
        "${KERNEL_RANDOMIZE_VA_SPACE}" \
        "$sysctl_file"

    set_sysctl_value \
        "kernel.randomize_va_space" \
        "${KERNEL_RANDOMIZE_VA_SPACE}"


    #
    # Reload the complete sysctl configuration.
    #

    if sysctl --system \
        >> "$REMEDIATION_LOG" 2>&1
    then

        log_success \
            "Kernel sysctl configuration reloaded."

        return 0
    fi


    log_error \
        "sysctl --system failed."

    return 1
}


# ============================================================
# 8. APPARMOR
#
# CIS:
# 1.3.1.4
# ============================================================

audit_apparmor() {

    local control_id="1.3.1.4"


    if ! command_exists aa-status; then

        audit_fail \
            "$control_id" \
            "AppArmor aa-status command is not available"

        return 1
    fi


    if ! systemctl is-enabled apparmor >/dev/null 2>&1; then

        audit_fail \
            "$control_id" \
            "AppArmor service is not enabled"

        return 1
    fi


    if ! systemctl is-active apparmor >/dev/null 2>&1; then

        audit_fail \
            "$control_id" \
            "AppArmor service is not active"

        return 1
    fi


    if [ "${APPARMOR_RESTRICT_UNPRIVILEGED_UNCONFINED:-yes}" = "yes" ]; then

        local restriction

        restriction="$(sysctl -n kernel.apparmor_restrict_unprivileged_unconfined 2>/dev/null || true)"


        if [ "$restriction" != "1" ]; then

            audit_fail \
                "$control_id" \
                "AppArmor unprivileged unconfined restriction is not enabled"

            return 1
        fi
    fi


    audit_pass \
        "$control_id" \
        "AppArmor is enabled and required restriction is configured"

    return 0
}


remediate_apparmor() {

    if [ "${ENABLE_APPARMOR:-yes}" != "yes" ]; then

        log_warning \
            "AppArmor remediation disabled in the embedded configuration."

        return 0
    fi


    if ! command_exists apparmor_status; then

        if ! install_package apparmor; then
            return 1
        fi
    fi


    systemctl enable apparmor \
        >> "$REMEDIATION_LOG" 2>&1 || true


    systemctl start apparmor \
        >> "$REMEDIATION_LOG" 2>&1 || true


    #
    # Configure:
    #
    # kernel.apparmor_restrict_unprivileged_unconfined=1
    #

    if [ "${APPARMOR_RESTRICT_UNPRIVILEGED_UNCONFINED:-yes}" = "yes" ]; then

        local sysctl_file="/etc/sysctl.d/99-cis-hardening.conf"

        backup_file "$sysctl_file"

        persist_sysctl_value \
            "kernel.apparmor_restrict_unprivileged_unconfined" \
            "1" \
            "$sysctl_file"

        set_sysctl_value \
            "kernel.apparmor_restrict_unprivileged_unconfined" \
            "1"
    fi


    if systemctl is-active apparmor >/dev/null 2>&1; then

        log_success \
            "AppArmor is active."

        return 0
    fi


    log_error \
        "AppArmor could not be activated."

    return 1
}


# ============================================================
# 9. AUTOMATIC ERROR REPORTING
#
# CIS:
# 1.5.7
#
# Ubuntu uses apport.
# ============================================================

audit_apport() {

    local control_id="1.5.7"


    if [ "${DISABLE_APPORT:-yes}" != "yes" ]; then

        audit_warning \
            "$control_id" \
            "Automatic error reporting is not disabled in the embedded configuration"

        return 0
    fi


    if ! command_exists dpkg-query; then

        audit_warning \
            "$control_id" \
            "Unable to determine apport package state"

        return 0
    fi


    if package_installed apport; then

        local config_file="/etc/default/apport"


        if [ -f "$config_file" ] &&
           grep -Eq \
                '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*0' \
                "$config_file"
        then

            audit_pass \
                "$control_id" \
                "Apport is configured as disabled"

            return 0
        fi


        audit_fail \
            "$control_id" \
            "Apport is installed but not configured as disabled"

        return 1
    fi


    audit_pass \
        "$control_id" \
        "Apport package is not installed"

    return 0
}


remediate_apport() {

    if [ "${DISABLE_APPORT:-yes}" != "yes" ]; then

        log_info \
            "Automatic error reporting remediation disabled."

        return 0
    fi


    local config_file="/etc/default/apport"


    if [ -f "$config_file" ]; then

        backup_file "$config_file"

    else

        mkdir -p "$(dirname "$config_file")"
    fi


    #
    # Ubuntu apport configuration.
    #

    if grep -Eq \
        '^[[:space:]]*enabled[[:space:]]*=' \
        "$config_file" 2>/dev/null
    then

        sed -i \
            -E \
            's/^[[:space:]]*enabled[[:space:]]*=.*/enabled=0/' \
            "$config_file"

    else

        printf '%s\n' \
            "enabled=0" \
            >> "$config_file"
    fi


    log_success \
        "Automatic error reporting disabled in apport configuration."

    return 0
}


# ============================================================
# 10. /etc/issue
#
# CIS:
# 1.6.1
# ============================================================

audit_issue() {

    local control_id="1.6.1"

    local file="${ISSUE_FILE:-/etc/issue}"


    if [ ! -f "$file" ]; then

        audit_fail \
            "$control_id" \
            "$file does not exist"

        return 1
    fi


    if [ ! -s "$file" ]; then

        audit_fail \
            "$control_id" \
            "$file is empty"

        return 1
    fi


    audit_pass \
        "$control_id" \
        "$file exists and contains banner text"

    return 0
}


# ============================================================
# 11. /etc/issue.net
#
# CIS:
# 1.6.3
# ============================================================

audit_issue_net() {

    local control_id="1.6.3"

    local file="${ISSUE_NET_FILE:-/etc/issue.net}"


    if [ ! -f "$file" ]; then

        audit_fail \
            "$control_id" \
            "$file does not exist"

        return 1
    fi


    if [ ! -s "$file" ]; then

        audit_fail \
            "$control_id" \
            "$file is empty"

        return 1
    fi


    audit_pass \
        "$control_id" \
        "$file exists and contains banner text"

    return 0
}


# ============================================================
# 12. SSH WARNING BANNER
#
# CIS:
# 1.6.5
#
# sshd should use:
#
# Banner /etc/issue.net
# ============================================================

audit_ssh_banner() {

    local control_id="1.6.5"
    local expected_banner="${SSH_BANNER_FILE:-/etc/issue.net}"
    local effective_banner

    effective_banner="$(get_sshd_effective_value banner || true)"
    if [[ "$effective_banner" == "$expected_banner" ]]; then

        audit_pass \
            "$control_id" \
            "SSH Banner points to $expected_banner"

        return 0
    fi


    audit_fail \
        "$control_id" \
        "SSH Banner expected $expected_banner, found ${effective_banner:-unset}"

    return 1
}


# ============================================================
# 13. /etc/MOTD
#
# CIS:
# 1.6.6
# ============================================================

audit_motd() {

    local control_id="1.6.6"

    local file="${MOTD_FILE:-/etc/motd}"


    if [ ! -f "$file" ]; then

        audit_fail \
            "$control_id" \
            "$file does not exist"

        return 1
    fi


    #
    # Check ownership and permissions.
    #

    if verify_file_permissions \
        "$file" \
        "${BANNER_OWNER:-root}" \
        "${BANNER_GROUP:-root}" \
        "${BANNER_MODE:-644}"
    then

        audit_pass \
            "$control_id" \
            "$file ownership and permissions are correct"

        return 0
    fi


    audit_fail \
        "$control_id" \
        "$file ownership or permissions are incorrect"

    return 1
}


# ============================================================
# 14. BANNER AUDIT
# ============================================================

audit_banners() {

    local failed=0


    audit_issue || failed=1

    audit_issue_net || failed=1

    audit_ssh_banner || failed=1

    audit_motd || failed=1


    if [ "$failed" -eq 0 ]; then
        return 0
    fi

    return 1
}


# ============================================================
# 15. BANNER REMEDIATION
# ============================================================

remediate_banners() {

    local issue_file="${ISSUE_FILE:-/etc/issue}"
    local issue_net_file="${ISSUE_NET_FILE:-/etc/issue.net}"
    local motd_file="${MOTD_FILE:-/etc/motd}"


    #
    # /etc/issue
    #

    if [ "${ISSUE_ENABLED:-yes}" = "yes" ]; then

        backup_file "$issue_file"

        printf '%s\n' \
            "${SSH_BANNER_TEXT}" \
            > "$issue_file"

        set_file_permissions \
            "$issue_file" \
            "${BANNER_OWNER:-root}" \
            "${BANNER_GROUP:-root}" \
            "${BANNER_MODE:-644}"
    fi


    #
    # /etc/issue.net
    #

    if [ "${ISSUE_NET_ENABLED:-yes}" = "yes" ]; then

        backup_file "$issue_net_file"

        printf '%s\n' \
            "${SSH_BANNER_TEXT}" \
            > "$issue_net_file"

        set_file_permissions \
            "$issue_net_file" \
            "${BANNER_OWNER:-root}" \
            "${BANNER_GROUP:-root}" \
            "${BANNER_MODE:-644}"
    fi


    #
    # /etc/motd
    #

    if [ "${MOTD_ENABLED:-yes}" = "yes" ]; then

        backup_file "$motd_file"

        printf '%s\n' \
            "${SSH_BANNER_TEXT}" \
            > "$motd_file"

        set_file_permissions \
            "$motd_file" \
            "${BANNER_OWNER:-root}" \
            "${BANNER_GROUP:-root}" \
            "${BANNER_MODE:-644}"
    fi


    #
    # SSH Banner configuration.
    #

    local ssh_dropin="${SSH_CIS_CONFIG_FILE:-/etc/ssh/sshd_config.d/00-cis-hardening.conf}"


    mkdir -p "$(dirname "$ssh_dropin")"

    backup_file "$ssh_dropin"


    if grep -Eq \
        '^[[:space:]]*Banner[[:space:]]+' \
        "$ssh_dropin" 2>/dev/null
    then

        sed -i \
            -E \
            "s|^[[:space:]]*Banner[[:space:]]+.*|Banner ${SSH_BANNER_FILE:-/etc/issue.net}|" \
            "$ssh_dropin"

    else

        printf '%s\n' \
            "Banner ${SSH_BANNER_FILE:-/etc/issue.net}" \
            >> "$ssh_dropin"
    fi


    #
    # Validate before reload.
    #

    if validate_sshd; then

        safe_reload_sshd || return 1

    else

        log_error \
            "SSH banner remediation produced an invalid SSH configuration."

        return 1
    fi


    return 0
}


# ============================================================
# 16. PAM MOTD
#
# CIS:
# 1.6.9
# ============================================================

audit_pam_motd() {

    local control_id="1.6.9"

    local common_session="/etc/pam.d/common-session"


    if [ ! -f "$common_session" ]; then

        audit_fail \
            "$control_id" \
            "$common_session does not exist"

        return 1
    fi


    #
    # Ubuntu normally invokes pam_motd from PAM session
    # configuration.
    #

    if grep -Eq \
        '^[[:space:]]*session[[:space:]].*pam_motd\.so' \
        "$common_session"
    then

        audit_pass \
            "$control_id" \
            "pam_motd is configured in common-session"

        return 0
    fi


    audit_warning \
        "$control_id" \
        "pam_motd configuration was not found in common-session"

    return 1
}


remediate_pam_motd() {

    if [ "${PAM_MOTD_ENABLED:-yes}" != "yes" ]; then

        log_info \
            "PAM MOTD remediation disabled."

        return 0
    fi


    local common_session="/etc/pam.d/common-session"


    if [ ! -f "$common_session" ]; then

        log_warning \
            "$common_session does not exist."

        return 1
    fi


    #
    # Do not blindly add pam_motd if Ubuntu's PAM tooling already
    # manages it.
    #

    if grep -Eq \
        '^[[:space:]]*session[[:space:]].*pam_motd\.so' \
        "$common_session"
    then

        log_info \
            "pam_motd already configured."

        return 0
    fi


    backup_file "$common_session"


    printf '%s\n' \
        "session optional pam_motd.so" \
        >> "$common_session"


    log_success \
        "pam_motd added to common-session."

    return 0
}


# ============================================================
# 17. AIDE AUDIT
#
# The failed Nessus report included AIDE-related verification.
# We check package/configuration/timer state without assuming
# that a particular timer/service implementation is identical
# on every Ubuntu installation.
# ============================================================

aide_timer_unit() {
    command_exists systemctl || return 1

    systemctl list-unit-files --type=timer --no-legend 2>/dev/null \
        | awk 'tolower($1) ~ /aide.*\.timer$/ {print $1; exit}'
}

ensure_aide_timer() {
    local timer_unit aide_bin
    timer_unit="$(aide_timer_unit || true)"

    if [[ -z "$timer_unit" ]]; then
        aide_bin="$(command -v aide)" || return 1
        local service_file="/etc/systemd/system/cis-aide-check.service"
        local timer_file="/etc/systemd/system/cis-aide-check.timer"

        backup_file "$service_file" || return 1
        backup_file "$timer_file" || return 1

        cat > "$service_file" <<EOF
[Unit]
Description=CIS AIDE filesystem integrity check

[Service]
Type=oneshot
ExecStart=${aide_bin} --check
Nice=10
IOSchedulingClass=idle
EOF

        cat > "$timer_file" <<'EOF'
[Unit]
Description=Daily CIS AIDE filesystem integrity check

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
EOF

        chown root:root "$service_file" "$timer_file" || return 1
        chmod 644 "$service_file" "$timer_file" || return 1
        systemctl daemon-reload || return 1
        timer_unit="cis-aide-check.timer"
    fi

    systemctl enable --now "$timer_unit" >> "$REMEDIATION_LOG" 2>&1
}

audit_aide() {

    local control_id="AIDE"

    if ! command_exists aide; then

        audit_fail \
            "$control_id" \
            "AIDE command is not available"

        return 1
    fi


    #
    # AIDE database may not exist immediately after installation.
    # Do not create a potentially expensive database during audit.
    #

    local database_found="no"


    if [ -f /var/lib/aide/aide.db ]; then
        database_found="yes"
    fi


    if [ "$database_found" = "yes" ]; then

        audit_pass \
            "$control_id" \
            "AIDE package and database are present"

    else

        audit_fail \
            "$control_id" \
            "AIDE is installed but its active database /var/lib/aide/aide.db is missing"

        return 1

    fi


    #
    # Check timer only if configured.
    #

    if [ "${ENABLE_AIDE_TIMER:-yes}" = "yes" ]; then
        local timer_unit
        timer_unit="$(aide_timer_unit || true)"

        if [[ -n "$timer_unit" ]] &&
           systemctl is-enabled "$timer_unit" >/dev/null 2>&1 &&
           systemctl is-active "$timer_unit" >/dev/null 2>&1; then
            audit_pass "$control_id" "$timer_unit is enabled and active"
        else
            audit_fail "$control_id" "No enabled and active AIDE systemd timer was found"
            return 1
        fi
    fi


    return 0
}


# ============================================================
# 18. AIDE REMEDIATION
# ============================================================

remediate_aide() {

    if [ "${INSTALL_AIDE:-yes}" != "yes" ]; then

        log_info \
            "AIDE installation disabled."

        return 0
    fi


    #
    # Install AIDE.
    #

    if ! package_installed aide; then

        if ! install_package aide; then
            return 1
        fi
    fi

    if [ ! -f /var/lib/aide/aide.db ] &&
       [ -f /var/lib/aide/aide.db.new ]; then
        install -o root -g root -m 600 \
            /var/lib/aide/aide.db.new \
            /var/lib/aide/aide.db || return 1
    fi


    #
    # Create initial database only if none exists.
    #
    # This can take time, so do it only during remediation.
    #

    if [ ! -f /var/lib/aide/aide.db ] &&
       [ ! -f /var/lib/aide/aide.db.new ]
    then

        if command_exists aideinit; then

            log_info \
                "Initializing AIDE database."

            if aideinit >> "$REMEDIATION_LOG" 2>&1; then

                if [ -f /var/lib/aide/aide.db.new ]; then
                    install -o root -g root -m 600 \
                        /var/lib/aide/aide.db.new \
                        /var/lib/aide/aide.db || return 1
                fi

                log_success \
                    "AIDE database initialization completed."

            else

                log_warning \
                    "AIDE database initialization failed or requires manual review."
            fi

        elif command_exists aide; then

            log_warning \
                "aideinit command is unavailable."

            log_warning \
                "AIDE database initialization requires manual review."
        fi
    fi


    #
    # Enable timer if available.
    #

    if [ "${ENABLE_AIDE_TIMER:-yes}" = "yes" ]; then
        if ! ensure_aide_timer; then
            log_error "Could not enable or create an AIDE integrity timer."
            return 1
        fi
    fi


    return 0
}


# ============================================================
# 19. FULL SECTION STATUS
# ============================================================

section_01_status() {

    echo
    echo "Section 01 controls include:"
    echo
    echo " 1.1.2.1.1 /tmp filesystem"
    echo " 1.1.2.2.4 /dev/shm noexec"
    echo " 1.3.1.4 AppArmor restriction"
    echo " 1.4.1 GRUB bootloader password"
    echo " 1.5.4 fs.suid_dumpable"
    echo " 1.5.5 kernel.dmesg_restrict"
    echo " 1.5.7 Automatic Error Reporting"
    echo " 1.5.9 kernel.randomize_va_space"
    echo " 1.6.1 /etc/issue"
    echo " 1.6.3 /etc/issue.net"
    echo " 1.6.5 SSH warning banner"
    echo " 1.6.6 /etc/motd"
    echo " 1.6.9 pam_motd"
    echo " AIDE Filesystem integrity"
    echo
}


# ============================================================
# END OF SECTION 01
# ============================================================

#!/bin/bash

# ============================================================
# CIS Ubuntu 24.04 LTS
# Section 02 - Services / Network
#
# File:
#   sections/02_services_network.sh
#
# Purpose:
#   Audit and remediate:
#
#   - Unnecessary client packages
#   - Unnecessary kernel modules
#   - IPv4 network parameters
#   - IPv6 network parameters
#   - TCP SYN cookies
#   - Network forwarding
#
# Controls covered from the failed Nessus report:
#
#   2.2.4      Telnet client
#   2.2.6      FTP client
#
#   3.2.1      ATM module
#   3.2.2      CAN module
#   3.2.5      SCTP module
#   3.2.6      TIPC module
#
#   3.3.1.4    IPv4 all send_redirects
#   3.3.1.5    IPv4 default send_redirects
#   3.3.1.8    IPv4 all accept_redirects
#   3.3.1.9    IPv4 default accept_redirects
#   3.3.1.10   IPv4 all secure_redirects
#   3.3.1.11   IPv4 default secure_redirects
#   3.3.1.12   IPv4 all rp_filter
#   3.3.1.13   IPv4 default rp_filter
#   3.3.1.14   IPv4 all accept_source_route
#   3.3.1.15   IPv4 default accept_source_route
#   3.3.1.16   IPv4 all log_martians
#   3.3.1.17   IPv4 default log_martians
#   3.3.1.18   tcp_syncookies
#
#   3.3.2.1    IPv6 all forwarding
#   3.3.2.2    IPv6 default forwarding
#   3.3.2.3    IPv6 all accept_redirects
#   3.3.2.4    IPv6 default accept_redirects
#   3.3.2.5    IPv6 all accept_source_route
#   3.3.2.6    IPv6 default accept_source_route
#   3.3.2.7    IPv6 all accept_ra
#   3.3.2.8    IPv6 default accept_ra
#
# IMPORTANT:
#   Network settings can affect production connectivity.
#   Every setting is audited individually.
# ============================================================


# ============================================================
# 1. SECTION ENTRY POINT
# ============================================================

section_02_services_network() {

    start_section "02 - SERVICES / NETWORK"

    local status=0

    case "${MODE:-audit}" in

        audit)
            audit_02_services_network || status=$?
            ;;

        remediate)
            remediate_02_services_network || status=$?
            ;;

        verify)
            audit_02_services_network || status=$?
            ;;

        *)
            log_error \
                "Unknown mode for Section 02: ${MODE:-unknown}"

            return 1
            ;;
    esac

    end_section
    return "$status"
}


# ============================================================
# 2. AUDIT ENTRY POINT
# ============================================================

audit_02_services_network() {

    log_info "Starting services and network audit."

    audit_telnet_client
    audit_ftp_client

    audit_kernel_modules

    audit_ipv4_settings
    audit_ipv6_settings

    log_info "Services and network audit completed."
}


# ============================================================
# 3. REMEDIATION ENTRY POINT
# ============================================================

remediate_02_services_network() {

    log_info "Starting services and network remediation."

    local failed=0

    remediate_telnet_client || failed=1
    remediate_ftp_client || failed=1

    remediate_kernel_modules || failed=1

    remediate_ipv4_settings || failed=1
    remediate_ipv6_settings || failed=1
    set_sysctl_value \
        "net.ipv4.conf.all.log_martians" \
        "${NET_IPV4_ALL_LOG_MARTIANS}" || failed=1
    set_sysctl_value \
        "net.ipv4.conf.default.log_martians" \
        "${NET_IPV4_DEFAULT_LOG_MARTIANS}" || failed=1

    log_info "Services and network remediation completed."
    return "$failed"
}


# ============================================================
# 4. TELNET CLIENT
#
# CIS:
#   2.2.4
#
# Telnet client should not be installed unless specifically
# required.
# ============================================================

audit_telnet_client() {

    local control_id="2.2.4"


    if package_installed telnet; then

        audit_fail \
            "$control_id" \
            "Telnet client package is installed"

        return 1
    fi


    audit_pass \
        "$control_id" \
        "Telnet client package is not installed"

    return 0
}


remediate_telnet_client() {

    if [ "${REMOVE_TELNET_CLIENT:-yes}" != "yes" ]; then

        log_info \
            "Telnet client removal is disabled."

        return 0
    fi


    if package_installed telnet; then

        remove_package telnet

    else

        log_info \
            "Telnet client is not installed."
    fi
}


# ============================================================
# 5. FTP CLIENT
#
# CIS:
#   2.2.6
#
# FTP client should not be installed unless required.
# ============================================================

audit_ftp_client() {

    local control_id="2.2.6"


    #
    # Ubuntu may have different FTP client packages.
    #
    # Check the common package names rather than assuming only
    # one implementation.
    #

    local found="no"


    if package_installed ftp; then
        found="yes"
    fi


    if package_installed inetutils-ftp; then
        found="yes"
    fi


    if [ "$found" = "yes" ]; then

        audit_fail \
            "$control_id" \
            "FTP client package is installed"

        return 1
    fi


    audit_pass \
        "$control_id" \
        "FTP client package is not installed"

    return 0
}


remediate_ftp_client() {

    if [ "${REMOVE_FTP_CLIENT:-yes}" != "yes" ]; then

        log_info \
            "FTP client removal is disabled."

        return 0
    fi


    if package_installed ftp; then
        remove_package ftp
    fi


    if package_installed inetutils-ftp; then
        remove_package inetutils-ftp
    fi


    log_info \
        "FTP client package remediation completed."
}


# ============================================================
# 6. KERNEL MODULE AUDIT
#
# CIS:
#   3.2.1 ATM
#   3.2.2 CAN
#   3.2.5 SCTP
#   3.2.6 TIPC
#
# A module is considered compliant when:
#
#   - It is unavailable/blacklisted according to the policy,
#     and
#   - It is not currently loaded.
#
# Ubuntu kernels may not contain every module. If the module
# does not exist, that is treated as compliant.
# ============================================================


module_exists() {

    local module="$1"

    modinfo "$module" >/dev/null 2>&1
}


module_loaded() {

    local module="$1"

    lsmod 2>/dev/null \
        | awk '{print $1}' \
        | grep -qx "$module"
}


module_blacklisted() {

    local module="$1"

    grep -RqsE \
        "^[[:space:]]*(blacklist|install)[[:space:]]+${module}([[:space:]]|$)" \
        /etc/modprobe.d/ 2>/dev/null
}


audit_single_kernel_module() {

    local control_id="$1"
    local module="$2"
    local description="$3"


    #
    # If the kernel does not contain the module, it cannot be
    # loaded. This is compliant for the availability check.
    #

    if ! module_exists "$module"; then

        audit_pass \
            "$control_id" \
            "$description: module is not available"

        return 0
    fi


    #
    # Module exists.
    #

    if module_loaded "$module"; then

        audit_fail \
            "$control_id" \
            "$description: module is currently loaded"

        return 1
    fi


    #
    # If it exists but is not loaded, verify that loading is
    # prevented by modprobe configuration.
    #

    if module_blacklisted "$module"; then

        audit_pass \
            "$control_id" \
            "$description: module is unavailable/blacklisted"

        return 0
    fi


    audit_fail \
        "$control_id" \
        "$description: module exists and is not blacklisted"

    return 1
}


audit_kernel_modules() {

    local failed=0


    if [ "${DISABLE_ATM_MODULE:-yes}" = "yes" ]; then

        audit_single_kernel_module \
            "3.2.1" \
            "atm" \
            "ATM kernel module" || failed=1

    else

        audit_skip \
            "3.2.1" \
            "ATM module hardening disabled in the embedded configuration"
    fi


    if [ "${DISABLE_CAN_MODULE:-yes}" = "yes" ]; then

        audit_single_kernel_module \
            "3.2.2" \
            "can" \
            "CAN kernel module" || failed=1

    else

        audit_skip \
            "3.2.2" \
            "CAN module hardening disabled in the embedded configuration"
    fi


    if [ "${DISABLE_SCTP_MODULE:-yes}" = "yes" ]; then

        audit_single_kernel_module \
            "3.2.5" \
            "sctp" \
            "SCTP kernel module" || failed=1

    else

        audit_skip \
            "3.2.5" \
            "SCTP module hardening disabled in the embedded configuration"
    fi


    if [ "${DISABLE_TIPC_MODULE:-yes}" = "yes" ]; then

        audit_single_kernel_module \
            "3.2.6" \
            "tipc" \
            "TIPC kernel module" || failed=1

    else

        audit_skip \
            "3.2.6" \
            "TIPC module hardening disabled in the embedded configuration"
    fi


    if [ "$failed" -eq 0 ]; then
        return 0
    fi

    return 1
}


# ============================================================
# 7. KERNEL MODULE REMEDIATION
# ============================================================

remediate_single_kernel_module() {

    local module="$1"


    #
    # If the module is not available in this kernel, there is
    # nothing to change.
    #

    if ! module_exists "$module"; then

        log_info \
            "Kernel module not available: $module"

        return 0
    fi


    local config_file="/etc/modprobe.d/99-cis-hardening.conf"


    backup_file "$config_file"


    #
    # Prevent normal module loading.
    #

    if grep -Eq \
        "^[[:space:]]*blacklist[[:space:]]+${module}([[:space:]]|$)" \
        "$config_file" 2>/dev/null
    then

        :

    else

        printf '%s\n' \
            "blacklist $module" \
            >> "$config_file"
    fi


    #
    # Prevent explicit modprobe loading as well.
    #

    if grep -Eq \
        "^[[:space:]]*install[[:space:]]+${module}[[:space:]]+" \
        "$config_file" 2>/dev/null
    then

        :

    else

        printf '%s\n' \
            "install $module /bin/false" \
            >> "$config_file"
    fi


    #
    # If currently loaded, try to remove it.
    #

    if module_loaded "$module"; then

        if modprobe -r "$module" \
            >> "$REMEDIATION_LOG" 2>&1
        then

            log_success \
                "Unloaded kernel module: $module"

        else

            log_warning \
                "Could not unload kernel module currently loaded: $module"

            log_warning \
                "A reboot may be required."
        fi
    fi


    log_success \
        "Kernel module loading restricted: $module"

    return 0
}


remediate_kernel_modules() {

    if [ "${DISABLE_ATM_MODULE:-yes}" = "yes" ]; then
        remediate_single_kernel_module atm
    fi


    if [ "${DISABLE_CAN_MODULE:-yes}" = "yes" ]; then
        remediate_single_kernel_module can
    fi


    if [ "${DISABLE_SCTP_MODULE:-yes}" = "yes" ]; then
        remediate_single_kernel_module sctp
    fi


    if [ "${DISABLE_TIPC_MODULE:-yes}" = "yes" ]; then
        remediate_single_kernel_module tipc
    fi


    #
    # Rebuild initramfs so module restrictions are available
    # during boot where required.
    #

    if command_exists update-initramfs; then

        log_info \
            "Updating initramfs for kernel module restrictions."

        if update-initramfs -u \
            >> "$REMEDIATION_LOG" 2>&1
        then

            log_success \
                "initramfs updated."

        else

            log_warning \
                "initramfs update failed; review manually."
        fi
    fi
}


# ============================================================
# 8. IPv4 SETTINGS
#
# CIS controls:
#
#   3.3.1.4
#   3.3.1.5
#   3.3.1.8
#   3.3.1.9
#   3.3.1.10
#   3.3.1.11
#   3.3.1.12
#   3.3.1.13
#   3.3.1.14
#   3.3.1.15
#   3.3.1.16
#   3.3.1.17
#   3.3.1.18
# ============================================================

audit_persisted_sysctl_value() {
    local control_id="$1"
    local key="$2"
    local expected="$3"
    local config_file="${4:-/etc/sysctl.conf}"
    local actual=""

    if [[ -f "$config_file" ]]; then
        actual="$(awk -F '[[:space:]=]+' -v key="$key" \
            '$1 !~ /^#/ && $1 == key {value=$2} END {print value}' "$config_file")"
    fi

    if [[ "$actual" == "$expected" ]]; then
        audit_pass "$control_id" "$key persisted as $actual in $config_file"
        return 0
    fi

    audit_fail "$control_id" "$key persisted value is '${actual:-unset}', expected $expected in $config_file"
    return 1
}

audit_ipv4_settings() {

    local failed=0


    #
    # 3.3.1.4
    #

    check_expected_value \
        "3.3.1.4" \
        "net.ipv4.conf.all.send_redirects" \
        "$(get_sysctl_value net.ipv4.conf.all.send_redirects)" \
        "${NET_IPV4_ALL_SEND_REDIRECTS}" \
        || failed=1


    #
    # 3.3.1.5
    #

    check_expected_value \
        "3.3.1.5" \
        "net.ipv4.conf.default.send_redirects" \
        "$(get_sysctl_value net.ipv4.conf.default.send_redirects)" \
        "${NET_IPV4_DEFAULT_SEND_REDIRECTS}" \
        || failed=1


    #
    # 3.3.1.8
    #

    check_expected_value \
        "3.3.1.8" \
        "net.ipv4.conf.all.accept_redirects" \
        "$(get_sysctl_value net.ipv4.conf.all.accept_redirects)" \
        "${NET_IPV4_ALL_ACCEPT_REDIRECTS}" \
        || failed=1


    #
    # 3.3.1.9
    #

    check_expected_value \
        "3.3.1.9" \
        "net.ipv4.conf.default.accept_redirects" \
        "$(get_sysctl_value net.ipv4.conf.default.accept_redirects)" \
        "${NET_IPV4_DEFAULT_ACCEPT_REDIRECTS}" \
        || failed=1


    #
    # 3.3.1.10
    #

    check_expected_value \
        "3.3.1.10" \
        "net.ipv4.conf.all.secure_redirects" \
        "$(get_sysctl_value net.ipv4.conf.all.secure_redirects)" \
        "${NET_IPV4_ALL_SECURE_REDIRECTS}" \
        || failed=1


    #
    # 3.3.1.11
    #

    check_expected_value \
        "3.3.1.11" \
        "net.ipv4.conf.default.secure_redirects" \
        "$(get_sysctl_value net.ipv4.conf.default.secure_redirects)" \
        "${NET_IPV4_DEFAULT_SECURE_REDIRECTS}" \
        || failed=1


    #
    # 3.3.1.12
    #

    check_expected_value \
        "3.3.1.12" \
        "net.ipv4.conf.all.rp_filter" \
        "$(get_sysctl_value net.ipv4.conf.all.rp_filter)" \
        "${NET_IPV4_ALL_RP_FILTER}" \
        || failed=1


    #
    # 3.3.1.13
    #

    check_expected_value \
        "3.3.1.13" \
        "net.ipv4.conf.default.rp_filter" \
        "$(get_sysctl_value net.ipv4.conf.default.rp_filter)" \
        "${NET_IPV4_DEFAULT_RP_FILTER}" \
        || failed=1


    #
    # 3.3.1.14
    #

    check_expected_value \
        "3.3.1.14" \
        "net.ipv4.conf.all.accept_source_route" \
        "$(get_sysctl_value net.ipv4.conf.all.accept_source_route)" \
        "${NET_IPV4_ALL_ACCEPT_SOURCE_ROUTE}" \
        || failed=1


    #
    # 3.3.1.15
    #

    check_expected_value \
        "3.3.1.15" \
        "net.ipv4.conf.default.accept_source_route" \
        "$(get_sysctl_value net.ipv4.conf.default.accept_source_route)" \
        "${NET_IPV4_DEFAULT_ACCEPT_SOURCE_ROUTE}" \
        || failed=1


    #
    # 3.3.1.16
    #

    check_expected_value \
        "3.3.1.16" \
        "net.ipv4.conf.all.log_martians" \
        "$(get_sysctl_value net.ipv4.conf.all.log_martians)" \
        "${NET_IPV4_ALL_LOG_MARTIANS}" \
        || failed=1

    audit_persisted_sysctl_value \
        "3.3.1.16" \
        "net.ipv4.conf.all.log_martians" \
        "${NET_IPV4_ALL_LOG_MARTIANS}" \
        /etc/sysctl.d/99-cis-hardening.conf



    #
    # 3.3.1.17
    #

    check_expected_value \
        "3.3.1.17" \
        "net.ipv4.conf.default.log_martians" \
        "$(get_sysctl_value net.ipv4.conf.default.log_martians)" \
        "${NET_IPV4_DEFAULT_LOG_MARTIANS}" \
        || failed=1

    audit_persisted_sysctl_value \
        "3.3.1.17" \
        "net.ipv4.conf.default.log_martians" \
        "${NET_IPV4_DEFAULT_LOG_MARTIANS}" \
        /etc/sysctl.d/99-cis-hardening.conf

    #
    # 3.3.1.18
    #

    check_expected_value \
        "3.3.1.18" \
        "net.ipv4.tcp_syncookies" \
        "$(get_sysctl_value net.ipv4.tcp_syncookies)" \
        "${NET_IPV4_TCP_SYNCOOKIES}" \
        || failed=1


    if [ "$failed" -eq 0 ]; then
        return 0
    fi

    return 1
}


# ============================================================
# 9. IPv4 REMEDIATION
# ============================================================

remediate_ipv4_settings() {

    local sysctl_file="/etc/sysctl.d/99-cis-hardening.conf"

    backup_file "$sysctl_file"


    #
    # 3.3.1.4
    #

    persist_sysctl_value \
        "net.ipv4.conf.all.send_redirects" \
        "${NET_IPV4_ALL_SEND_REDIRECTS}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.conf.all.send_redirects" \
        "${NET_IPV4_ALL_SEND_REDIRECTS}"


    #
    # 3.3.1.5
    #

    persist_sysctl_value \
        "net.ipv4.conf.default.send_redirects" \
        "${NET_IPV4_DEFAULT_SEND_REDIRECTS}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.conf.default.send_redirects" \
        "${NET_IPV4_DEFAULT_SEND_REDIRECTS}"


    #
    # 3.3.1.8
    #

    persist_sysctl_value \
        "net.ipv4.conf.all.accept_redirects" \
        "${NET_IPV4_ALL_ACCEPT_REDIRECTS}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.conf.all.accept_redirects" \
        "${NET_IPV4_ALL_ACCEPT_REDIRECTS}"


    #
    # 3.3.1.9
    #

    persist_sysctl_value \
        "net.ipv4.conf.default.accept_redirects" \
        "${NET_IPV4_DEFAULT_ACCEPT_REDIRECTS}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.conf.default.accept_redirects" \
        "${NET_IPV4_DEFAULT_ACCEPT_REDIRECTS}"


    #
    # 3.3.1.10
    #

    persist_sysctl_value \
        "net.ipv4.conf.all.secure_redirects" \
        "${NET_IPV4_ALL_SECURE_REDIRECTS}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.conf.all.secure_redirects" \
        "${NET_IPV4_ALL_SECURE_REDIRECTS}"


    #
    # 3.3.1.11
    #

    persist_sysctl_value \
        "net.ipv4.conf.default.secure_redirects" \
        "${NET_IPV4_DEFAULT_SECURE_REDIRECTS}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.conf.default.secure_redirects" \
        "${NET_IPV4_DEFAULT_SECURE_REDIRECTS}"


    #
    # 3.3.1.12
    #

    persist_sysctl_value \
        "net.ipv4.conf.all.rp_filter" \
        "${NET_IPV4_ALL_RP_FILTER}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.conf.all.rp_filter" \
        "${NET_IPV4_ALL_RP_FILTER}"


    #
    # 3.3.1.13
    #

    persist_sysctl_value \
        "net.ipv4.conf.default.rp_filter" \
        "${NET_IPV4_DEFAULT_RP_FILTER}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.conf.default.rp_filter" \
        "${NET_IPV4_DEFAULT_RP_FILTER}"


    #
    # 3.3.1.14
    #

    persist_sysctl_value \
        "net.ipv4.conf.all.accept_source_route" \
        "${NET_IPV4_ALL_ACCEPT_SOURCE_ROUTE}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.conf.all.accept_source_route" \
        "${NET_IPV4_ALL_ACCEPT_SOURCE_ROUTE}"


    #
    # 3.3.1.15
    #

    persist_sysctl_value \
        "net.ipv4.conf.default.accept_source_route" \
        "${NET_IPV4_DEFAULT_ACCEPT_SOURCE_ROUTE}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.conf.default.accept_source_route" \
        "${NET_IPV4_DEFAULT_ACCEPT_SOURCE_ROUTE}"


    #
    # 3.3.1.16
    #

    persist_sysctl_value \
        "net.ipv4.conf.all.log_martians" \
        "${NET_IPV4_ALL_LOG_MARTIANS}" \
        "$sysctl_file"
# this is not working (Issue)
    set_sysctl_value \
        "net.ipv4.conf.all.log_martians" \
        "${NET_IPV4_ALL_LOG_MARTIANS}"


    #
    # 3.3.1.17
    #

    persist_sysctl_value \
        "net.ipv4.conf.default.log_martians" \
        "${NET_IPV4_DEFAULT_LOG_MARTIANS}" \
        "$sysctl_file"
# this is not working (Issue)
    set_sysctl_value \
        "net.ipv4.conf.default.log_martians" \
        "${NET_IPV4_DEFAULT_LOG_MARTIANS}"


    #
    # 3.3.1.18
    #

    persist_sysctl_value \
        "net.ipv4.tcp_syncookies" \
        "${NET_IPV4_TCP_SYNCOOKIES}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv4.tcp_syncookies" \
        "${NET_IPV4_TCP_SYNCOOKIES}"

    # /etc/sysctl.conf is loaded after sysctl.d; keep martian logging last.
    backup_file /etc/sysctl.conf || return 1
    persist_sysctl_value \
        "net.ipv4.conf.all.log_martians" \
        "${NET_IPV4_ALL_LOG_MARTIANS}" \
        /etc/sysctl.conf || return 1
    set_sysctl_value \
        "net.ipv4.conf.all.log_martians" \
        "${NET_IPV4_ALL_LOG_MARTIANS}" || return 1
    persist_sysctl_value \
        "net.ipv4.conf.default.log_martians" \
        "${NET_IPV4_DEFAULT_LOG_MARTIANS}" \
        /etc/sysctl.conf || return 1
    set_sysctl_value \
        "net.ipv4.conf.default.log_martians" \
        "${NET_IPV4_DEFAULT_LOG_MARTIANS}" || return 1

    if ! sysctl --system >> "$REMEDIATION_LOG" 2>&1; then
        log_error "Unable to apply the persisted IPv4 sysctl configuration."
        return 1
    fi

    local actual_all actual_default

    actual_all="$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null)"
    actual_default="$(sysctl -n net.ipv4.conf.default.log_martians 2>/dev/null)"

    if [[ "$actual_all" != "$NET_IPV4_ALL_LOG_MARTIANS" ]]; then
        log_error \
            "3.3.1.16 failed: net.ipv4.conf.all.log_martians=$actual_all"
        return 1
    fi

    if [[ "$actual_default" != "$NET_IPV4_DEFAULT_LOG_MARTIANS" ]]; then
        log_error \
            "3.3.1.17 failed: net.ipv4.conf.default.log_martians=$actual_default"
        return 1
    fi

    log_success \
        "3.3.1.16 net.ipv4.conf.all.log_martians=$actual_all"

    log_success \
        "3.3.1.17 net.ipv4.conf.default.log_martians=$actual_default"

    return 0
}


# ============================================================
# 10. IPv6 AUDIT
#
# Only run IPv6 controls when HARDEN_IPV6=yes.
#
# If IPv6 is deliberately not being hardened, we report SKIP
# rather than pretending that the control passed.
# ============================================================

audit_ipv6_settings() {

    if [ "${HARDEN_IPV6:-yes}" != "yes" ]; then

        audit_skip \
            "3.3.2" \
            "IPv6 network hardening disabled in the embedded configuration"

        return 0
    fi


    local failed=0


    #
    # 3.3.2.1
    #

    check_expected_value \
        "3.3.2.1" \
        "net.ipv6.conf.all.forwarding" \
        "$(get_sysctl_value net.ipv6.conf.all.forwarding)" \
        "${NET_IPV6_ALL_FORWARDING}" \
        || failed=1


    #
    # 3.3.2.2
    #

    check_expected_value \
        "3.3.2.2" \
        "net.ipv6.conf.default.forwarding" \
        "$(get_sysctl_value net.ipv6.conf.default.forwarding)" \
        "${NET_IPV6_DEFAULT_FORWARDING}" \
        || failed=1


    #
    # 3.3.2.3
    #

    check_expected_value \
        "3.3.2.3" \
        "net.ipv6.conf.all.accept_redirects" \
        "$(get_sysctl_value net.ipv6.conf.all.accept_redirects)" \
        "${NET_IPV6_ALL_ACCEPT_REDIRECTS}" \
        || failed=1


    #
    # 3.3.2.4
    #

    check_expected_value \
        "3.3.2.4" \
        "net.ipv6.conf.default.accept_redirects" \
        "$(get_sysctl_value net.ipv6.conf.default.accept_redirects)" \
        "${NET_IPV6_DEFAULT_ACCEPT_REDIRECTS}" \
        || failed=1


    #
    # 3.3.2.5
    #

    check_expected_value \
        "3.3.2.5" \
        "net.ipv6.conf.all.accept_source_route" \
        "$(get_sysctl_value net.ipv6.conf.all.accept_source_route)" \
        "${NET_IPV6_ALL_ACCEPT_SOURCE_ROUTE}" \
        || failed=1


    #
    # 3.3.2.6
    #

    check_expected_value \
        "3.3.2.6" \
        "net.ipv6.conf.default.accept_source_route" \
        "$(get_sysctl_value net.ipv6.conf.default.accept_source_route)" \
        "${NET_IPV6_DEFAULT_ACCEPT_SOURCE_ROUTE}" \
        || failed=1


    #
    # 3.3.2.7
    #

    check_expected_value \
        "3.3.2.7" \
        "net.ipv6.conf.all.accept_ra" \
        "$(get_sysctl_value net.ipv6.conf.all.accept_ra)" \
        "${NET_IPV6_ALL_ACCEPT_RA}" \
        || failed=1


    #
    # 3.3.2.8
    #

    check_expected_value \
        "3.3.2.8" \
        "net.ipv6.conf.default.accept_ra" \
        "$(get_sysctl_value net.ipv6.conf.default.accept_ra)" \
        "${NET_IPV6_DEFAULT_ACCEPT_RA}" \
        || failed=1


    if [ "$failed" -eq 0 ]; then
        return 0
    fi

    return 1
}


# ============================================================
# 11. IPv6 REMEDIATION
# ============================================================

remediate_ipv6_settings() {

    if [ "${HARDEN_IPV6:-yes}" != "yes" ]; then

        log_info \
            "IPv6 hardening disabled in the embedded configuration."

        return 0
    fi


    local sysctl_file="/etc/sysctl.d/99-cis-hardening.conf"

    backup_file "$sysctl_file"


    #
    # 3.3.2.1
    #

    persist_sysctl_value \
        "net.ipv6.conf.all.forwarding" \
        "${NET_IPV6_ALL_FORWARDING}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv6.conf.all.forwarding" \
        "${NET_IPV6_ALL_FORWARDING}"


    #
    # 3.3.2.2
    #

    persist_sysctl_value \
        "net.ipv6.conf.default.forwarding" \
        "${NET_IPV6_DEFAULT_FORWARDING}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv6.conf.default.forwarding" \
        "${NET_IPV6_DEFAULT_FORWARDING}"


    #
    # 3.3.2.3
    #

    persist_sysctl_value \
        "net.ipv6.conf.all.accept_redirects" \
        "${NET_IPV6_ALL_ACCEPT_REDIRECTS}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv6.conf.all.accept_redirects" \
        "${NET_IPV6_ALL_ACCEPT_REDIRECTS}"


    #
    # 3.3.2.4
    #

    persist_sysctl_value \
        "net.ipv6.conf.default.accept_redirects" \
        "${NET_IPV6_DEFAULT_ACCEPT_REDIRECTS}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv6.conf.default.accept_redirects" \
        "${NET_IPV6_DEFAULT_ACCEPT_REDIRECTS}"


    #
    # 3.3.2.5
    #

    persist_sysctl_value \
        "net.ipv6.conf.all.accept_source_route" \
        "${NET_IPV6_ALL_ACCEPT_SOURCE_ROUTE}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv6.conf.all.accept_source_route" \
        "${NET_IPV6_ALL_ACCEPT_SOURCE_ROUTE}"


    #
    # 3.3.2.6
    #

    persist_sysctl_value \
        "net.ipv6.conf.default.accept_source_route" \
        "${NET_IPV6_DEFAULT_ACCEPT_SOURCE_ROUTE}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv6.conf.default.accept_source_route" \
        "${NET_IPV6_DEFAULT_ACCEPT_SOURCE_ROUTE}"


    #
    # 3.3.2.7
    #

    persist_sysctl_value \
        "net.ipv6.conf.all.accept_ra" \
        "${NET_IPV6_ALL_ACCEPT_RA}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv6.conf.all.accept_ra" \
        "${NET_IPV6_ALL_ACCEPT_RA}"


    #
    # 3.3.2.8
    #

    persist_sysctl_value \
        "net.ipv6.conf.default.accept_ra" \
        "${NET_IPV6_DEFAULT_ACCEPT_RA}" \
        "$sysctl_file"

    set_sysctl_value \
        "net.ipv6.conf.default.accept_ra" \
        "${NET_IPV6_DEFAULT_ACCEPT_RA}"

    if ! sysctl --system >> "$REMEDIATION_LOG" 2>&1; then
        log_error "Unable to apply the persisted IPv6 sysctl configuration."
        return 1
    fi

    return 0
}


# ============================================================
# 12. NETWORK CONFIGURATION SUMMARY
# ============================================================

network_configuration_summary() {

    echo
    echo "============================================================"
    echo "NETWORK CONFIGURATION"
    echo "============================================================"

    echo
    echo "IPv4:"
    echo "  all.send_redirects          = ${NET_IPV4_ALL_SEND_REDIRECTS}"
    echo "  default.send_redirects      = ${NET_IPV4_DEFAULT_SEND_REDIRECTS}"
    echo "  all.accept_redirects        = ${NET_IPV4_ALL_ACCEPT_REDIRECTS}"
    echo "  default.accept_redirects    = ${NET_IPV4_DEFAULT_ACCEPT_REDIRECTS}"
    echo "  all.secure_redirects        = ${NET_IPV4_ALL_SECURE_REDIRECTS}"
    echo "  default.secure_redirects    = ${NET_IPV4_DEFAULT_SECURE_REDIRECTS}"
    echo "  all.rp_filter               = ${NET_IPV4_ALL_RP_FILTER}"
    echo "  default.rp_filter           = ${NET_IPV4_DEFAULT_RP_FILTER}"
    echo "  all.accept_source_route     = ${NET_IPV4_ALL_ACCEPT_SOURCE_ROUTE}"
    echo "  default.accept_source_route = ${NET_IPV4_DEFAULT_ACCEPT_SOURCE_ROUTE}"
    echo "  all.log_martians            = ${NET_IPV4_ALL_LOG_MARTIANS}"
    echo "  default.log_martians        = ${NET_IPV4_DEFAULT_LOG_MARTIANS}"
    echo "  tcp_syncookies              = ${NET_IPV4_TCP_SYNCOOKIES}"

    echo
    echo "IPv6:"
    echo "  Hardening                    = ${HARDEN_IPV6}"

    if [ "${HARDEN_IPV6:-yes}" = "yes" ]; then

        echo "  all.forwarding              = ${NET_IPV6_ALL_FORWARDING}"
        echo "  default.forwarding          = ${NET_IPV6_DEFAULT_FORWARDING}"
        echo "  all.accept_redirects        = ${NET_IPV6_ALL_ACCEPT_REDIRECTS}"
        echo "  default.accept_redirects    = ${NET_IPV6_DEFAULT_ACCEPT_REDIRECTS}"
        echo "  all.accept_source_route     = ${NET_IPV6_ALL_ACCEPT_SOURCE_ROUTE}"
        echo "  default.accept_source_route = ${NET_IPV6_DEFAULT_ACCEPT_SOURCE_ROUTE}"
        echo "  all.accept_ra               = ${NET_IPV6_ALL_ACCEPT_RA}"
        echo "  default.accept_ra           = ${NET_IPV6_DEFAULT_ACCEPT_RA}"

    fi

    echo
    echo "============================================================"
}


# ============================================================
# 13. SECTION STATUS
# ============================================================

section_02_status() {

    echo
    echo "Section 02 controls:"
    echo
    echo "  2.2.4      Telnet client"
    echo "  2.2.6      FTP client"
    echo
    echo "  3.2.1      ATM module"
    echo "  3.2.2      CAN module"
    echo "  3.2.5      SCTP module"
    echo "  3.2.6      TIPC module"
    echo
    echo "  3.3.1.4    IPv4 all send_redirects"
    echo "  3.3.1.5    IPv4 default send_redirects"
    echo "  3.3.1.8    IPv4 all accept_redirects"
    echo "  3.3.1.9    IPv4 default accept_redirects"
    echo "  3.3.1.10   IPv4 all secure_redirects"
    echo "  3.3.1.11   IPv4 default secure_redirects"
    echo "  3.3.1.12   IPv4 all rp_filter"
    echo "  3.3.1.13   IPv4 default rp_filter"
    echo "  3.3.1.14   IPv4 all accept_source_route"
    echo "  3.3.1.15   IPv4 default accept_source_route"
    echo "  3.3.1.16   IPv4 all log_martians"
    echo "  3.3.1.17   IPv4 default log_martians"
    echo "  3.3.1.18   IPv4 tcp_syncookies"
    echo
    echo "  3.3.2.1    IPv6 all forwarding"
    echo "  3.3.2.2    IPv6 default forwarding"
    echo "  3.3.2.3    IPv6 all accept_redirects"
    echo "  3.3.2.4    IPv6 default accept_redirects"
    echo "  3.3.2.5    IPv6 all accept_source_route"
    echo "  3.3.2.6    IPv6 default accept_source_route"
    echo "  3.3.2.7    IPv6 all accept_ra"
    echo "  3.3.2.8    IPv6 default accept_ra"
    echo
}


# ============================================================
# END OF SECTION 02
# ============================================================

#!/usr/bin/env bash

# ============================================================
# CIS Ubuntu 24.04 LTS Level 1
# Section 03 - Firewall and SSH Hardening
# ============================================================

# ------------------------------------------------------------
# UFW configuration
# ------------------------------------------------------------

audit_ufw_service() {
    local status

    if ! command_exists ufw; then
        audit_fail "4.1.2" "UFW firewall" "ufw package/command is not installed"
        return 1
    fi

    status="$(ufw status 2>/dev/null | head -n 1 || true)"

    if echo "$status" | grep -q "Status: active"; then
        audit_pass "4.1.2" "UFW firewall" "UFW is active"
        return 0
    fi

    audit_fail "4.1.2" "UFW firewall" "UFW is not active"
    return 1
}

audit_ufw_ssh_rule() {
    if [[ "${REQUIRE_SSH_UFW_RULE:-yes}" != "yes" ]]; then
        audit_skip "FIREWALL-SSH" "SSH UFW rule requirement is disabled in the embedded configuration"
        return 0
    fi

    if ! command_exists ufw || ! command_exists sshd; then
        audit_fail "FIREWALL-SSH" "Cannot verify the SSH UFW rule because ufw or sshd is unavailable"
        return 1
    fi

    local status active_ports port
    status="$(ufw status 2>/dev/null || true)"
    active_ports="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' || true)"
    active_ports="$(printf '%s\n' "$active_ports" "${SSH_PORT:-22}" | sort -un)"

    while IFS= read -r port; do
        [[ -z "$port" ]] && continue
        if ! grep -Eq "^[[:space:]]*${port}/tcp([[:space:]]|\\().*ALLOW([[:space:]]+IN)?([[:space:]]|$)" <<< "$status"; then
            audit_fail "FIREWALL-SSH" "UFW does not allow active/configured SSH port ${port}/tcp"
            return 1
        fi
    done <<< "$active_ports"

    audit_pass "FIREWALL-SSH" "UFW allows the active and configured SSH TCP ports"
    return 0
}

remediate_ufw_service() {
    log_info "Configuring UFW firewall"

    if ! command_exists ufw; then
        install_package "ufw" || return 1
    fi

    # Always allow SSH before enabling UFW.
    # This prevents the hardening script from locking out the
    # current SSH session.
    local ssh_port="${SSH_PORT:-22}"

    log_info "Allowing SSH TCP port ${ssh_port}"
    ufw allow "${ssh_port}/tcp" >/dev/null 2>&1 || {
        log_error "Failed to allow SSH port ${ssh_port} in UFW"
        return 1
    }

    # Configure default policies.
    ufw default deny incoming >/dev/null 2>&1 || return 1
    ufw default allow outgoing >/dev/null 2>&1 || return 1
    ufw default deny routed >/dev/null 2>&1 || return 1

    # Add configured additional TCP ports.
    if [[ -n "${UFW_ALLOWED_TCP_PORTS:-}" ]]; then
        local port

        IFS=', ' read -ra ports <<< "$UFW_ALLOWED_TCP_PORTS"

        for port in "${ports[@]}"; do
            port="$(echo "$port" | xargs)"

            if [[ -n "$port" ]]; then
                log_info "Allowing TCP port ${port}"
                ufw allow "${port}/tcp" >/dev/null 2>&1 || {
                    log_warning "Could not allow TCP port ${port}"
                }
            fi
        done
    fi

    # Add configured additional UDP ports.
    if [[ -n "${UFW_ALLOWED_UDP_PORTS:-}" ]]; then
        local port

        IFS=', ' read -ra ports <<< "$UFW_ALLOWED_UDP_PORTS"

        for port in "${ports[@]}"; do
            port="$(echo "$port" | xargs)"

            if [[ -n "$port" ]]; then
                log_info "Allowing UDP port ${port}"
                ufw allow "${port}/udp" >/dev/null 2>&1 || {
                    log_warning "Could not allow UDP port ${port}"
                }
            fi
        done
    fi

    # Enable firewall.
    if ufw --force enable >/dev/null 2>&1; then
        audit_pass "4.1.2" "UFW firewall" "UFW enabled successfully"
        return 0
    fi

    log_error "Failed to enable UFW"
    return 1
}

audit_ufw_defaults() {
    if ! command_exists ufw; then
        audit_fail "4.1.3" "UFW incoming default" "ufw is not installed"
        audit_fail "4.1.5" "UFW routed default" "ufw is not installed"
        return 1
    fi

    local status
    status="$(ufw status verbose 2>/dev/null || true)"

    # --------------------------------------------------------
    # 4.1.3 - Incoming traffic
    # --------------------------------------------------------
    if echo "$status" | grep -qi "Default: deny (incoming)"; then
        audit_pass \
            "4.1.3" \
            "UFW incoming default" \
            "Default incoming policy is deny"
    else
        audit_fail \
            "4.1.3" \
            "UFW incoming default" \
            "Default incoming policy is not deny"
    fi

    if echo "$status" | grep -qi "Default:.*allow (outgoing)"; then
        audit_pass \
            "4.1.4" \
            "UFW outgoing default" \
            "Default outgoing policy is allow"
    else
        audit_fail \
            "4.1.4" \
            "UFW outgoing default" \
            "Default outgoing policy is not allow"
    fi

    # --------------------------------------------------------
    # 4.1.5 - Routed traffic
    # --------------------------------------------------------
    if echo "$status" | grep -qiE "Default:.*deny \(routed\)"; then
        audit_pass \
            "4.1.5" \
            "UFW routed default" \
            "Default routed policy is deny"
    else
        # Some UFW versions display this information slightly
        # differently. Check the actual UFW config as fallback.
        if grep -qE 'DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw 2>/dev/null; then
            audit_pass \
                "4.1.5" \
                "UFW routed default" \
                "UFW forwarding policy is DROP"
        else
            audit_fail \
                "4.1.5" \
                "UFW routed default" \
                "Default routed policy is not deny"
        fi
    fi
}

remediate_ufw_defaults() {
    if ! command_exists ufw; then
        install_package "ufw" || return 1
    fi

    ufw default deny incoming >/dev/null 2>&1 || return 1
    ufw default allow outgoing >/dev/null 2>&1 || return 1
    ufw default deny routed >/dev/null 2>&1 || return 1

    # Also make sure the underlying UFW forwarding policy is DROP.
    if [[ -f /etc/default/ufw ]]; then
        backup_file "/etc/default/ufw"

        if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
            sed -i \
                's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="DROP"/' \
                /etc/default/ufw
        else
            printf '%s\n' 'DEFAULT_FORWARD_POLICY="DROP"' >> /etc/default/ufw
        fi
    fi

    audit_pass \
        "4.1.3" \
        "UFW incoming default" \
        "Default incoming policy configured as deny"

    audit_pass \
        "4.1.5" \
        "UFW routed default" \
        "Default routed policy configured as deny"

    return 0
}


# ------------------------------------------------------------
# SSH configuration helpers
# ------------------------------------------------------------

SSH_CIS_DROPIN="/etc/ssh/sshd_config.d/00-cis-hardening.conf"


ssh_effective_value() {
    local key="$1"

    get_sshd_effective_value "$key"
}


ssh_config_contains() {
    local key="$1"
    local expected="$2"

    local value
    value="$(ssh_effective_value "$key" || true)"

    [[ "${value,,}" == "${expected,,}" ]]
}


ssh_config_numeric_contains() {
    local key="$1"
    local expected="$2"

    local value
    value="$(ssh_effective_value "$key" || true)"

    [[ "$value" == "$expected" ]]
}


ssh_kex_list() {
    ssh -Q kex 2>/dev/null || true
}


get_pq_kex_algorithm() {
    local algorithm

    # Ubuntu 24.04/OpenSSH may expose one or more of these
    # hybrid post-quantum key exchange algorithms.
    while read -r algorithm; do
        case "$algorithm" in
            sntrup761x25519-sha512)
                echo "$algorithm"
                return 0
                ;;
            sntrup761x25519-sha512@openssh.com)
                echo "$algorithm"
                return 0
                ;;
            mlkem768x25519-sha256)
                echo "$algorithm"
                return 0
                ;;
        esac
    done < <(ssh_kex_list)

    return 1
}


ensure_ssh_dropin_directory() {
    if [[ ! -d /etc/ssh/sshd_config.d ]]; then
        mkdir -p /etc/ssh/sshd_config.d || {
            log_error "Could not create /etc/ssh/sshd_config.d"
            return 1
        }
    fi

    chown root:root /etc/ssh/sshd_config.d || return 1
    chmod 755 /etc/ssh/sshd_config.d || return 1

    return 0
}


write_ssh_setting() {
    local key="$1"
    local value="$2"

    printf '%s %s\n' "$key" "$value" >> "$SSH_CIS_DROPIN"
}


prepare_ssh_dropin() {
    ensure_ssh_dropin_directory || return 1

    if [[ -f "$SSH_CIS_DROPIN" ]]; then
        backup_file "$SSH_CIS_DROPIN"
    fi

    cat > "$SSH_CIS_DROPIN" <<'EOF'
# ============================================================
# CIS Ubuntu 24.04 LTS Level 1
# SSH hardening
#
# Managed by cis-ubuntu-24.04 hardening script.
# ============================================================

EOF

    chown root:root "$SSH_CIS_DROPIN"
    chmod 600 "$SSH_CIS_DROPIN"

    return 0
}


reload_ssh_safely() {
    if ! command_exists sshd; then
        log_error "sshd command not found"
        return 1
    fi

    if ! sshd -t 2>>"$LOG_DIR/sshd-validation.log"; then
        log_error "SSH configuration validation failed"
        log_error "SSH configuration was NOT reloaded"
        return 1
    fi

    if command_exists systemctl; then
        if systemctl reload ssh.service >/dev/null 2>&1; then
            log_success "SSH service reloaded successfully"
            return 0
        fi

        if systemctl reload sshd.service >/dev/null 2>&1; then
            log_success "sshd service reloaded successfully"
            return 0
        fi
    fi

    if command_exists service; then
        if service ssh reload >/dev/null 2>&1; then
            log_success "SSH service reloaded successfully"
            return 0
        fi
    fi

    log_error "Could not reload SSH service"
    return 1
}


# ------------------------------------------------------------
# SSH 5.1.1 - Permissions on sshd_config
# ------------------------------------------------------------

audit_sshd_config_permissions() {
    local file="/etc/ssh/sshd_config"

    if [[ ! -f "$file" ]]; then
        audit_fail \
            "5.1.1" \
            "sshd_config permissions" \
            "$file does not exist"
        return 1
    fi

    local owner group mode
    owner="$(stat -c '%U' "$file" 2>/dev/null || true)"
    group="$(stat -c '%G' "$file" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$file" 2>/dev/null || true)"

    if [[ "$owner" == "root" &&
          "$group" == "root" &&
          "$mode" == "600" ]]; then

        audit_pass \
            "5.1.1" \
            "sshd_config permissions" \
            "Owner root:root and mode 600"
        return 0
    fi

    audit_fail \
        "5.1.1" \
        "sshd_config permissions" \
        "Current owner=${owner}:${group}, mode=${mode}; expected root:root 600"

    return 1
}


remediate_sshd_config_permissions() {
    local file="/etc/ssh/sshd_config"

    if [[ ! -f "$file" ]]; then
        log_error "$file does not exist"
        return 1
    fi

    backup_file "$file"

    chown root:root "$file" || return 1
    chmod 600 "$file" || return 1

    audit_pass \
        "5.1.1" \
        "sshd_config permissions" \
        "Owner root:root and mode 600"

    return 0
}


# ------------------------------------------------------------
# SSH 5.1.4 - Access configuration
# ------------------------------------------------------------

audit_sshd_access_config() {
    local allow_users allow_groups deny_users deny_groups

    allow_users="$(sshd -T 2>/dev/null | awk '$1=="allowusers" {$1=""; sub(/^ /,""); print; exit}')"
    allow_groups="$(sshd -T 2>/dev/null | awk '$1=="allowgroups" {$1=""; sub(/^ /,""); print; exit}')"
    deny_users="$(sshd -T 2>/dev/null | awk '$1=="denyusers" {$1=""; sub(/^ /,""); print; exit}')"
    deny_groups="$(sshd -T 2>/dev/null | awk '$1=="denygroups" {$1=""; sub(/^ /,""); print; exit}')"

    if [[ -n "$allow_users" ||
          -n "$allow_groups" ||
          -n "$deny_users" ||
          -n "$deny_groups" ]]; then

        audit_pass \
            "5.1.4" \
            "sshd access configuration" \
            "SSH access restriction is configured"

        return 0
    fi

    audit_warning \
        "5.1.4" \
        "sshd access configuration" \
        "No AllowUsers/AllowGroups/DenyUsers/DenyGroups restriction configured; user-specific access policy is required"

    return 0
}


remediate_sshd_access_config() {
    local allow_users="${SSH_ALLOW_USERS:-}"
    local allow_groups="${SSH_ALLOW_GROUPS:-}"
    local deny_users="${SSH_DENY_USERS:-}"
    local deny_groups="${SSH_DENY_GROUPS:-}"

    if [[ -z "$allow_users" &&
          -z "$allow_groups" &&
          -z "$deny_users" &&
          -z "$deny_groups" ]]; then

        audit_warning \
            "5.1.4" \
            "sshd access configuration" \
            "No access list configured in the embedded configuration; refusing to invent allowed users"

        return 0
    fi

    prepare_ssh_dropin || return 1

    if [[ -n "$allow_users" ]]; then
        write_ssh_setting "AllowUsers" "$allow_users"
    fi

    if [[ -n "$allow_groups" ]]; then
        write_ssh_setting "AllowGroups" "$allow_groups"
    fi

    if [[ -n "$deny_users" ]]; then
        write_ssh_setting "DenyUsers" "$deny_users"
    fi

    if [[ -n "$deny_groups" ]]; then
        write_ssh_setting "DenyGroups" "$deny_groups"
    fi

    return 0
}


# ------------------------------------------------------------
# SSH 5.1.5 - Banner
# ------------------------------------------------------------

audit_sshd_banner() {
    local expected="${SSH_BANNER_FILE:-/etc/issue.net}"
    local value

    value="$(ssh_effective_value "banner" || true)"

    if [[ "$value" == "$expected" ]]; then
        audit_pass \
            "5.1.5" \
            "sshd Banner" \
            "SSH Banner is configured as $expected"
        return 0
    fi

    audit_fail \
        "5.1.5" \
        "sshd Banner" \
        "Expected Banner $expected, found ${value:-none}"

    return 1
}


remediate_sshd_banner() {
    local banner_path="${SSH_BANNER_FILE:-/etc/issue.net}"

    prepare_ssh_dropin || return 1

    write_ssh_setting "Banner" "$banner_path"

    audit_pass \
        "5.1.5" \
        "sshd Banner" \
        "SSH Banner configured as $banner_path"

    return 0
}


# ------------------------------------------------------------
# SSH 5.1.7 - ClientAlive
# ------------------------------------------------------------

audit_sshd_client_alive() {
    local interval count

    interval="$(ssh_effective_value "clientaliveinterval" || true)"
    count="$(ssh_effective_value "clientalivecountmax" || true)"

    if [[ "$interval" == "${SSH_CLIENT_ALIVE_INTERVAL:-15}" &&
          "$count" == "${SSH_CLIENT_ALIVE_COUNT_MAX:-3}" ]]; then

        audit_pass \
            "5.1.7" \
            "SSH ClientAlive settings" \
            "ClientAliveInterval=$interval ClientAliveCountMax=$count"

        return 0
    fi

    audit_fail \
        "5.1.7" \
        "SSH ClientAlive settings" \
        "Found ClientAliveInterval=$interval ClientAliveCountMax=$count"

    return 1
}


remediate_sshd_client_alive() {
    prepare_ssh_dropin || return 1

    write_ssh_setting \
        "ClientAliveInterval" \
        "${SSH_CLIENT_ALIVE_INTERVAL:-15}"

    write_ssh_setting \
        "ClientAliveCountMax" \
        "${SSH_CLIENT_ALIVE_COUNT_MAX:-3}"

    return 0
}


# ------------------------------------------------------------
# Generic SSH setting audit/remediation
# ------------------------------------------------------------

audit_sshd_setting() {
    local check_id="$1"
    local title="$2"
    local key="$3"
    local expected="$4"

    local actual
    actual="$(ssh_effective_value "$key" || true)"

    if [[ "${actual,,}" == "${expected,,}" ]]; then
        audit_pass \
            "$check_id" \
            "$title" \
            "$key=$actual"
        return 0
    fi

    audit_fail \
        "$check_id" \
        "$title" \
        "Expected $key=$expected, found ${actual:-unset}"

    return 1
}


remediate_sshd_setting() {
    local key="$1"
    local value="$2"

    prepare_ssh_dropin || return 1

    write_ssh_setting "$key" "$value"

    return 0
}


# ------------------------------------------------------------
# SSH 5.1.11 - IgnoreRhosts
# ------------------------------------------------------------

audit_sshd_ignore_rhosts() {
    audit_sshd_setting \
        "5.1.11" \
        "SSH IgnoreRhosts" \
        "IgnoreRhosts" \
        "${SSH_IGNORE_RHOSTS:-yes}"
}


remediate_sshd_ignore_rhosts() {
    remediate_sshd_setting \
        "IgnoreRhosts" \
        "${SSH_IGNORE_RHOSTS:-yes}"
}


# ------------------------------------------------------------
# SSH 5.1.14 - LogLevel
# ------------------------------------------------------------

audit_sshd_loglevel() {
    audit_sshd_setting \
        "5.1.14" \
        "SSH LogLevel" \
        "LogLevel" \
        "${SSH_LOG_LEVEL:-VERBOSE}"
}


remediate_sshd_loglevel() {
    remediate_sshd_setting \
        "LogLevel" \
        "${SSH_LOG_LEVEL:-VERBOSE}"
}


# ------------------------------------------------------------
# SSH 5.1.16 - MaxAuthTries
# ------------------------------------------------------------

audit_sshd_max_auth_tries() {
    local expected="${SSH_MAX_AUTH_TRIES:-3}"
    local actual

    actual="$(ssh_effective_value "maxauthtries" || true)"

    if [[ "$actual" =~ ^[0-9]+$ ]] &&
       (( actual <= expected )); then

        audit_pass \
            "5.1.16" \
            "SSH MaxAuthTries" \
            "MaxAuthTries=$actual"

        return 0
    fi

    audit_fail \
        "5.1.16" \
        "SSH MaxAuthTries" \
        "Expected MaxAuthTries <= $expected, found ${actual:-unset}"

    return 1
}


remediate_sshd_max_auth_tries() {
    remediate_sshd_setting \
        "MaxAuthTries" \
        "${SSH_MAX_AUTH_TRIES:-3}"
}


# ------------------------------------------------------------
# SSH 5.1.17 - MaxStartups
# ------------------------------------------------------------

audit_sshd_max_startups() {
    local expected="${SSH_MAX_STARTUPS:-10:30:60}"
    local actual

    actual="$(ssh_effective_value "maxstartups" || true)"

    if [[ "$actual" == "$expected" ]]; then
        audit_pass \
            "5.1.17" \
            "SSH MaxStartups" \
            "MaxStartups=$actual"
        return 0
    fi

    audit_fail \
        "5.1.17" \
        "SSH MaxStartups" \
        "Expected MaxStartups=$expected, found ${actual:-unset}"

    return 1
}


remediate_sshd_max_startups() {
    remediate_sshd_setting \
        "MaxStartups" \
        "${SSH_MAX_STARTUPS:-10:30:60}"
}


# ------------------------------------------------------------
# SSH 5.1.18 - MaxSessions
# ------------------------------------------------------------

audit_sshd_max_sessions() {
    local expected="${SSH_MAX_SESSIONS:-10}"
    local actual

    actual="$(ssh_effective_value "maxsessions" || true)"

    if [[ "$actual" =~ ^[0-9]+$ ]] &&
       (( actual <= expected )); then

        audit_pass \
            "5.1.18" \
            "SSH MaxSessions" \
            "MaxSessions=$actual"

        return 0
    fi

    audit_fail \
        "5.1.18" \
        "SSH MaxSessions" \
        "Expected MaxSessions <= $expected, found ${actual:-unset}"

    return 1
}


remediate_sshd_max_sessions() {
    remediate_sshd_setting \
        "MaxSessions" \
        "${SSH_MAX_SESSIONS:-10}"
}


# ------------------------------------------------------------
# SSH 5.1.20 - PermitRootLogin
# ------------------------------------------------------------

audit_sshd_root_login() {
    audit_sshd_setting \
        "5.1.20" \
        "SSH PermitRootLogin" \
        "PermitRootLogin" \
        "${SSH_PERMIT_ROOT_LOGIN:-no}"
}


remediate_sshd_root_login() {
    remediate_sshd_setting \
        "PermitRootLogin" \
        "${SSH_PERMIT_ROOT_LOGIN:-no}"
}


# ------------------------------------------------------------
# SSH 5.1.21 - PermitUserEnvironment
# ------------------------------------------------------------

audit_sshd_user_environment() {
    audit_sshd_setting \
        "5.1.21" \
        "SSH PermitUserEnvironment" \
        "PermitUserEnvironment" \
        "${SSH_PERMIT_USER_ENVIRONMENT:-no}"
}


remediate_sshd_user_environment() {
    remediate_sshd_setting \
        "PermitUserEnvironment" \
        "${SSH_PERMIT_USER_ENVIRONMENT:-no}"
}


# ------------------------------------------------------------
# Additional SSH hardening from the embedded configuration
# ------------------------------------------------------------

audit_additional_ssh_settings() {
    local failures=0

    audit_sshd_setting \
        "SSH-HARDEN" \
        "SSH PermitEmptyPasswords" \
        "PermitEmptyPasswords" \
        "${SSH_PERMIT_EMPTY_PASSWORDS:-no}" || failures=$((failures + 1))

    audit_sshd_setting \
        "SSH-HARDEN" \
        "SSH TCP forwarding" \
        "AllowTcpForwarding" \
        "${SSH_ALLOW_TCP_FORWARDING:-no}" || failures=$((failures + 1))

    audit_sshd_setting \
        "SSH-HARDEN" \
        "SSH agent forwarding" \
        "AllowAgentForwarding" \
        "${SSH_ALLOW_AGENT_FORWARDING:-no}" || failures=$((failures + 1))

    audit_sshd_setting \
        "SSH-HARDEN" \
        "SSH X11 forwarding" \
        "X11Forwarding" \
        "${SSH_X11_FORWARDING:-no}" || failures=$((failures + 1))

    return "$failures"
}


remediate_additional_ssh_settings() {
    prepare_ssh_dropin || return 1

    write_ssh_setting \
        "PermitEmptyPasswords" \
        "${SSH_PERMIT_EMPTY_PASSWORDS:-no}"

    write_ssh_setting \
        "AllowTcpForwarding" \
        "${SSH_ALLOW_TCP_FORWARDING:-no}"

    write_ssh_setting \
        "AllowAgentForwarding" \
        "${SSH_ALLOW_AGENT_FORWARDING:-no}"

    write_ssh_setting \
        "X11Forwarding" \
        "${SSH_X11_FORWARDING:-no}"

    return 0
}


# ------------------------------------------------------------
# SSH 5.1.23 - Post-quantum KEX
# ------------------------------------------------------------

audit_sshd_pq_kex() {
    local available configured expected

    available="$(get_pq_kex_algorithm || true)"

    if [[ -z "$available" ]]; then
        audit_warning \
            "5.1.23" \
            "SSH post-quantum KEX" \
            "No supported post-quantum/hybrid KEX algorithm is exposed by this OpenSSH build"

        return 0
    fi

    configured="$(ssh_effective_value "kexalgorithms" || true)"

    # The configured list may contain multiple algorithms.
    if echo "$configured" | tr ',' '\n' | grep -Fxq "$available"; then
        audit_pass \
            "5.1.23" \
            "SSH post-quantum KEX" \
            "Supported PQ/hybrid KEX algorithm is enabled: $available"

        return 0
    fi

    audit_fail \
        "5.1.23" \
        "SSH post-quantum KEX" \
        "Available PQ/hybrid algorithm $available is not configured"

    return 1
}


remediate_sshd_pq_kex() {
    local algorithm

    algorithm="$(get_pq_kex_algorithm || true)"

    if [[ -z "$algorithm" ]]; then
        audit_warning \
            "5.1.23" \
            "SSH post-quantum KEX" \
            "No supported PQ/hybrid algorithm found; no unsafe SSH configuration change was made"

        return 0
    fi

    prepare_ssh_dropin || return 1

    # Preserve the OpenSSH default algorithms and prepend the
    # available hybrid PQ algorithm.
    local current_kex

    current_kex="$(ssh -Q kex 2>/dev/null | paste -sd ',' - || true)"

    if [[ -z "$current_kex" ]]; then
        log_warning "Could not determine OpenSSH KEX algorithms"
        return 0
    fi

    # Build a list with the PQ algorithm first and remove the
    # duplicate occurrence if present.
    local kex_list
    kex_list="$algorithm"

    while read -r item; do
        [[ -z "$item" ]] && continue

        if [[ "$item" != "$algorithm" ]]; then
            kex_list="${kex_list},${item}"
        fi
    done < <(ssh -Q kex 2>/dev/null)

    write_ssh_setting "KexAlgorithms" "$kex_list"

    return 0
}


# ------------------------------------------------------------
# SSH configuration validation
# ------------------------------------------------------------

validate_ssh_configuration() {
    if ! command_exists sshd; then
        log_error "sshd command not found"
        return 1
    fi

    if sshd -t 2>>"$LOG_DIR/sshd-validation.log"; then
        audit_pass \
            "SSH-VALIDATION" \
            "SSH configuration syntax" \
            "sshd configuration is valid"
        return 0
    fi

    audit_fail \
        "SSH-VALIDATION" \
        "SSH configuration syntax" \
        "sshd configuration is invalid"

    log_error "Check $LOG_DIR/sshd-validation.log for details"

    return 1
}


# ------------------------------------------------------------
# Complete SSH remediation
# ------------------------------------------------------------

remediate_ssh() {
    log_info "Starting SSH hardening"

    if ! command_exists sshd; then
        log_error "OpenSSH server is not installed"
        return 1
    fi

    ensure_ssh_dropin_directory || return 1

    # Create one clean CIS drop-in.
    prepare_ssh_dropin || return 1

    write_ssh_setting \
        "Banner" \
        "${SSH_BANNER_FILE:-/etc/issue.net}"

    write_ssh_setting \
        "Port" \
        "${SSH_PORT:-22}"

    write_ssh_setting \
        "ClientAliveInterval" \
        "${SSH_CLIENT_ALIVE_INTERVAL:-15}"

    write_ssh_setting \
        "ClientAliveCountMax" \
        "${SSH_CLIENT_ALIVE_COUNT_MAX:-3}"

    write_ssh_setting \
        "IgnoreRhosts" \
        "${SSH_IGNORE_RHOSTS:-yes}"

    write_ssh_setting \
        "LogLevel" \
        "${SSH_LOG_LEVEL:-VERBOSE}"

    write_ssh_setting \
        "MaxAuthTries" \
        "${SSH_MAX_AUTH_TRIES:-3}"

    write_ssh_setting \
        "MaxStartups" \
        "${SSH_MAX_STARTUPS:-10:30:60}"

    write_ssh_setting \
        "MaxSessions" \
        "${SSH_MAX_SESSIONS:-10}"

    write_ssh_setting \
        "PermitRootLogin" \
        "${SSH_PERMIT_ROOT_LOGIN:-no}"

    write_ssh_setting \
        "PermitUserEnvironment" \
        "${SSH_PERMIT_USER_ENVIRONMENT:-no}"

    write_ssh_setting \
        "PermitEmptyPasswords" \
        "${SSH_PERMIT_EMPTY_PASSWORDS:-no}"

    write_ssh_setting \
        "AllowTcpForwarding" \
        "${SSH_ALLOW_TCP_FORWARDING:-no}"

    write_ssh_setting \
        "AllowAgentForwarding" \
        "${SSH_ALLOW_AGENT_FORWARDING:-no}"

    write_ssh_setting \
        "X11Forwarding" \
        "${SSH_X11_FORWARDING:-no}"

    # --------------------------------------------------------
    # Optional SSH access restrictions.
    # Do NOT invent users/groups.
    # --------------------------------------------------------

    if [[ -n "${SSH_ALLOW_USERS:-}" ]]; then
        write_ssh_setting "AllowUsers" "$SSH_ALLOW_USERS"
    fi

    if [[ -n "${SSH_ALLOW_GROUPS:-}" ]]; then
        write_ssh_setting "AllowGroups" "$SSH_ALLOW_GROUPS"
    fi

    if [[ -n "${SSH_DENY_USERS:-}" ]]; then
        write_ssh_setting "DenyUsers" "$SSH_DENY_USERS"
    fi

    if [[ -n "${SSH_DENY_GROUPS:-}" ]]; then
        write_ssh_setting "DenyGroups" "$SSH_DENY_GROUPS"
    fi

    # --------------------------------------------------------
    # Post-quantum KEX
    # --------------------------------------------------------

    local pq_algorithm
    pq_algorithm="$(get_pq_kex_algorithm || true)"

    if [[ -n "$pq_algorithm" ]]; then
        local kex_list="$pq_algorithm"

        while read -r item; do
            [[ -z "$item" ]] && continue

            if [[ "$item" != "$pq_algorithm" ]]; then
                kex_list="${kex_list},${item}"
            fi
        done < <(ssh -Q kex 2>/dev/null)

        write_ssh_setting "KexAlgorithms" "$kex_list"
    else
        log_warning \
            "No supported post-quantum/hybrid KEX algorithm found; leaving KexAlgorithms unchanged"
    fi

    chmod 600 "$SSH_CIS_DROPIN"
    chown root:root "$SSH_CIS_DROPIN"

    # Validate BEFORE touching the running SSH service.
    if ! sshd -t 2>>"$LOG_DIR/sshd-validation.log"; then
        log_error "New SSH configuration is invalid"
        log_error "Removing invalid CIS SSH drop-in"

        rm -f "$SSH_CIS_DROPIN"

        return 1
    fi

    log_success "SSH configuration syntax is valid"

    if ! reload_ssh_safely; then
        log_error "SSH service reload failed"
        return 1
    fi

    audit_pass \
        "SSH-REMEDIATION" \
        "SSH hardening" \
        "SSH hardening configuration applied successfully"

    return 0
}


# ------------------------------------------------------------
# Complete UFW remediation
# ------------------------------------------------------------

remediate_ufw() {
    log_info "Starting UFW hardening"

    if ! command_exists ufw; then
        install_package "ufw" || return 1
    fi

    local ssh_port="${SSH_PORT:-22}"

    if [[ "${REQUIRE_SSH_UFW_RULE:-yes}" == "yes" ]] &&
       ! command_exists sshd; then
        log_error "Refusing to enable UFW without an installed SSH server to protect"
        return 1
    fi

    # Permit both the currently active SSH port(s) and the configured target.
    local active_ssh_ports
    active_ssh_ports="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' || true)"
    active_ssh_ports="$(printf '%s\n' "$active_ssh_ports" "$ssh_port" | sort -un)"
    local port
    while IFS= read -r port; do
        [[ -z "$port" ]] && continue
        ufw allow "${port}/tcp" >/dev/null 2>&1 || {
            log_error "Unable to create UFW SSH rule for port ${port}"
            return 1
        }
    done <<< "$active_ssh_ports"

    local ports
    IFS=', ' read -ra ports <<< "${UFW_ALLOWED_TCP_PORTS:-}"
    for port in "${ports[@]}"; do
        [[ -z "$port" ]] && continue
        [[ "$port" =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )) || {
            log_error "Invalid configured UFW TCP port: $port"
            return 1
        }
        ufw allow "${port}/tcp" >/dev/null 2>&1 || return 1
    done

    IFS=', ' read -ra ports <<< "${UFW_ALLOWED_UDP_PORTS:-}"
    for port in "${ports[@]}"; do
        [[ -z "$port" ]] && continue
        [[ "$port" =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )) || {
            log_error "Invalid configured UFW UDP port: $port"
            return 1
        }
        ufw allow "${port}/udp" >/dev/null 2>&1 || return 1
    done

    ufw default deny incoming >/dev/null 2>&1 || return 1
    ufw default allow outgoing >/dev/null 2>&1 || return 1
    ufw default deny routed >/dev/null 2>&1 || return 1

    if [[ -f /etc/default/ufw ]]; then
        backup_file "/etc/default/ufw"

        if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
            sed -i \
                's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="DROP"/' \
                /etc/default/ufw
        else
            printf '%s\n' 'DEFAULT_FORWARD_POLICY="DROP"' >> /etc/default/ufw
        fi
    fi

    local ufw_sysctl_file="/etc/ufw/sysctl.conf"
    if [[ -f "$ufw_sysctl_file" ]]; then
        backup_file "$ufw_sysctl_file" || return 1
        sed -i \
            -e "s|^[[:space:]]*net/ipv4/conf/all/log_martians[[:space:]]*=.*|net/ipv4/conf/all/log_martians=${NET_IPV4_ALL_LOG_MARTIANS}|" \
            -e "s|^[[:space:]]*net/ipv4/conf/default/log_martians[[:space:]]*=.*|net/ipv4/conf/default/log_martians=${NET_IPV4_DEFAULT_LOG_MARTIANS}|" \
            "$ufw_sysctl_file" || return 1
    fi

    if ! ufw --force enable >/dev/null 2>&1; then
        log_error "Failed to enable UFW"
        return 1
    fi

    set_sysctl_value \
        "net.ipv4.conf.all.log_martians" \
        "${NET_IPV4_ALL_LOG_MARTIANS}" || return 1
    set_sysctl_value \
        "net.ipv4.conf.default.log_martians" \
        "${NET_IPV4_DEFAULT_LOG_MARTIANS}" || return 1

    audit_pass \
        "4.1.2" \
        "UFW firewall" \
        "UFW is enabled"

    audit_pass \
        "4.1.3" \
        "UFW incoming default" \
        "Incoming traffic defaults to deny"

    audit_pass \
        "4.1.5" \
        "UFW routed default" \
        "Routed traffic defaults to deny"

    return 0
}


# ------------------------------------------------------------
# Section 03 audit
# ------------------------------------------------------------

section_03_audit() {
    start_section "03 - Firewall and SSH Audit"

    local failures=0

    # --------------------------------------------------------
    # UFW
    # --------------------------------------------------------

    audit_ufw_service || failures=$((failures + 1))
    audit_ufw_ssh_rule || failures=$((failures + 1))
    audit_ufw_defaults

    # --------------------------------------------------------
    # SSH
    # --------------------------------------------------------

    if ! command_exists sshd; then
        audit_fail \
            "SSH" \
            "OpenSSH server" \
            "sshd is not installed"

        failures=$((failures + 1))
    else
        audit_sshd_config_permissions || failures=$((failures + 1))
        audit_sshd_access_config || failures=$((failures + 1))
        audit_sshd_setting \
            "SSH-PORT" \
            "SSH listening port" \
            "Port" \
            "${SSH_PORT:-22}" || failures=$((failures + 1))
        audit_sshd_banner || failures=$((failures + 1))
        audit_sshd_client_alive || failures=$((failures + 1))
        audit_sshd_ignore_rhosts || failures=$((failures + 1))
        audit_sshd_loglevel || failures=$((failures + 1))
        audit_sshd_max_auth_tries || failures=$((failures + 1))
        audit_sshd_max_startups || failures=$((failures + 1))
        audit_sshd_max_sessions || failures=$((failures + 1))
        audit_sshd_root_login || failures=$((failures + 1))
        audit_sshd_user_environment || failures=$((failures + 1))
        audit_sshd_pq_kex || failures=$((failures + 1))

        audit_additional_ssh_settings || failures=$((failures + 1))

        validate_ssh_configuration || failures=$((failures + 1))
    fi

    end_section "03 - Firewall and SSH Audit"

    return "$failures"
}


# ------------------------------------------------------------
# Section 03 remediation
# ------------------------------------------------------------

section_03_remediate() {
    start_section "03 - Firewall and SSH Remediation"

    local failures=0

    # --------------------------------------------------------
    # UFW
    # --------------------------------------------------------

    if ! remediate_ufw; then
        failures=$((failures + 1))
    fi

    # --------------------------------------------------------
    # SSH permissions
    # --------------------------------------------------------

    if ! remediate_sshd_config_permissions; then
        failures=$((failures + 1))
    fi

    # --------------------------------------------------------
    # SSH configuration
    # --------------------------------------------------------

    if ! remediate_ssh; then
        failures=$((failures + 1))
    fi

    end_section "03 - Firewall and SSH Remediation"

    return "$failures"
}


# ------------------------------------------------------------
# Section 03 dispatcher
# ------------------------------------------------------------

section_03_firewall_ssh() {
    local mode="${1:-audit}"

    case "$mode" in
        audit)
            section_03_audit
            ;;

        remediate|fix|apply)
            section_03_remediate
            ;;

        *)
            log_error "Unknown Section 03 mode: $mode"
            log_error "Valid modes: audit | remediate"
            return 1
            ;;
    esac
}


# ------------------------------------------------------------
# Section 03 status
# ------------------------------------------------------------

section_03_status() {
    echo
    echo "============================================================"
    echo " Section 03 - Firewall and SSH Status"
    echo "============================================================"

    echo
    echo "[UFW]"
    if command_exists ufw; then
        ufw status verbose 2>/dev/null || true
    else
        echo "ufw: NOT INSTALLED"
    fi

    echo
    echo "[SSH]"
    if command_exists sshd; then
        echo "SSH service:"
        systemctl is-active ssh 2>/dev/null || true

        echo
        echo "Effective SSH settings:"
        sshd -T 2>/dev/null | grep -E \
            '^(banner|clientaliveinterval|clientalivecountmax|ignorerhosts|loglevel|maxauthtries|maxstartups|maxsessions|permitrootlogin|permituserenvironment|permitemptypasswords|allowtcpforwarding|allowagentforwarding|x11forwarding|kexalgorithms) ' \
            || true

        echo
        echo "SSH configuration files:"
        ls -la /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null || true
    else
        echo "sshd: NOT INSTALLED"
    fi

    echo
    echo "============================================================"
}


# ------------------------------------------------------------
# If this file is executed directly
# ------------------------------------------------------------

#!/usr/bin/env bash

# ============================================================
# CIS Ubuntu 24.04 LTS Level 1
# Section 04 - PAM and Account Hardening
# ============================================================

# ------------------------------------------------------------
# File paths
# ------------------------------------------------------------

PAM_AUTH="/etc/pam.d/common-auth"
PAM_ACCOUNT="/etc/pam.d/common-account"
PAM_PASSWORD="/etc/pam.d/common-password"
PAM_SESSION="/etc/pam.d/common-session"

LOGIN_DEFS="/etc/login.defs"
PWQUALITY="/etc/security/pwquality.conf"
FAILLock="/etc/security/faillock.conf"


# ------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------

pam_backup_file() {
    local file="$1"

    if [[ -f "$file" ]]; then
        backup_file "$file"
    fi
}


pam_has_setting() {
    local file="$1"
    local pattern="$2"

    [[ -f "$file" ]] || return 1

    grep -Eq "$pattern" "$file"
}


pam_remove_setting_lines() {
    local file="$1"
    local pattern="$2"

    [[ -f "$file" ]] || return 0

    sed -i -E "/$pattern/d" "$file"
}


pam_append_setting() {
    local file="$1"
    local line="$2"

    printf '%s\n' "$line" >> "$file"
}


# ------------------------------------------------------------
# 5.3.2.2 - PAM faillock
# ------------------------------------------------------------

audit_pam_faillock() {
    local auth_ok=0
    local authsucc_ok=0
    local account_ok=0

    # common-auth must contain both preauth and authfail.
    if [[ -f "$PAM_AUTH" ]]; then

        if grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_faillock\.so.*preauth' \
            "$PAM_AUTH"; then
            auth_ok=$((auth_ok + 1))
        fi

            if grep -Eq '^[[:space:]]*auth[[:space:]]+.*pam_faillock\.so.*authfail' \
            "$PAM_AUTH"; then
            auth_ok=$((auth_ok + 1))
        fi

            if grep -Eq '^[[:space:]]*auth[[:space:]]+.*pam_faillock\.so.*authsucc' \
                "$PAM_AUTH"; then
                authsucc_ok=1
            fi
    fi

    # common-account must contain account pam_faillock.
    if [[ -f "$PAM_ACCOUNT" ]]; then
        if grep -Eq '^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_faillock\.so' \
            "$PAM_ACCOUNT"; then
            account_ok=1
        fi
    fi

    if [[ "$auth_ok" -eq 2 && "$authsucc_ok" -eq 1 && "$account_ok" -eq 1 ]]; then
        audit_pass \
            "5.3.2.2" \
            "PAM faillock" \
            "pam_faillock preauth, authfail, authsucc and account rules are configured"
        return 0
    fi

    audit_fail \
        "5.3.2.2" \
        "PAM faillock" \
        "Required pam_faillock rules are missing"

    return 1
}


pwquality_is_ordered() {
    local pwquality_line unix_line
    pwquality_line="$(grep -nEm1 '^[[:space:]]*password[[:space:]]+.*pam_pwquality\.so' "$PAM_PASSWORD" | cut -d: -f1)"
    unix_line="$(grep -nEm1 '^[[:space:]]*password[[:space:]]+.*pam_unix\.so' "$PAM_PASSWORD" | cut -d: -f1)"

    [[ -n "$pwquality_line" && -n "$unix_line" ]] &&
        (( pwquality_line < unix_line ))
}


audit_pam_pwquality_module() {
    if ! package_installed libpam-pwquality; then
        audit_fail \
            "5.3.3.2" \
            "PAM password quality module" \
            "libpam-pwquality is not installed"
        return 1
    fi

    if ! pwquality_is_ordered; then
        audit_fail \
            "5.3.3.2" \
            "PAM password quality module" \
            "pam_pwquality.so must be enabled before pam_unix in $PAM_PASSWORD"
        return 1
    fi

    audit_pass \
        "5.3.3.2" \
        "PAM password quality module" \
        "libpam-pwquality is installed and enabled"
    return 0
}


remediate_pam_pwquality_module() {
    if ! install_package libpam-pwquality; then
        return 1
    fi

    pam_backup_file "$PAM_PASSWORD" || return 1

    if command_exists pam-auth-update; then
        DEBIAN_FRONTEND=noninteractive pam-auth-update --package --enable pwquality ||
            log_warning "pam-auth-update could not enable pwquality; enforcing the module directly"
    fi

    if ! pwquality_is_ordered; then
        local password_tmp
        password_tmp="$(mktemp)" || return 1

        awk '
            /^[[:space:]]*password[[:space:]]+.*pam_pwquality\.so/ { next }
            /^[[:space:]]*password[[:space:]]+.*pam_unix\.so/ && !inserted {
                print "password requisite pam_pwquality.so retry=3"
                inserted = 1
            }
            { print }
            END { if (!inserted) exit 1 }
        ' "$PAM_PASSWORD" > "$password_tmp" || {
            rm -f "$password_tmp"
            log_error "Could not insert pam_pwquality before pam_unix"
            return 1
        }

        chown --reference="$PAM_PASSWORD" "$password_tmp" || return 1
        chmod --reference="$PAM_PASSWORD" "$password_tmp" || return 1
        mv -f "$password_tmp" "$PAM_PASSWORD" || return 1
    fi

    audit_pam_pwquality_module
}


remediate_pam_faillock() {
    if ! command_exists pam-auth-update; then
        log_warning "pam-auth-update command not found"
    fi

    if [[ ! -f "$PAM_AUTH" || ! -f "$PAM_ACCOUNT" ]]; then
        log_error "Required PAM files are missing"
        return 1
    fi

    pam_backup_file "$PAM_AUTH"
    pam_backup_file "$PAM_ACCOUNT"
    backup_file "$FAILLock"

    # Remove old manually-managed faillock lines first.
    pam_remove_setting_lines \
        "$PAM_AUTH" \
        'pam_faillock\.so'

    pam_remove_setting_lines \
        "$PAM_ACCOUNT" \
        'pam_faillock\.so'

    local deny="${FAILLOCK_DENY:-5}"
    local unlock="${FAILLOCK_UNLOCK_TIME:-900}"
    local interval="${FAILLOCK_FAIL_INTERVAL:-900}"

    # Configure faillock globally.
    cat > "$FAILLock" <<EOF
# ============================================================
# CIS Ubuntu 24.04 LTS Level 1
# pam_faillock configuration
# ============================================================

deny = ${deny}
fail_interval = ${interval}
unlock_time = ${unlock}
EOF

    chown root:root "$FAILLock"
    chmod 644 "$FAILLock"

    # Keep the failure rule after pam_unix and reset the tally after success.
    local auth_tmp
    auth_tmp="$(mktemp)"

    awk '
        BEGIN { inserted_rules = 0 }

        /^[[:space:]]*auth[[:space:]]+.*pam_faillock\.so/ {
            next
        }

        /^[[:space:]]*auth[[:space:]]+.*pam_unix\.so/ && inserted_rules == 0 {
            print "auth required pam_faillock.so preauth"
            print
            print "auth [default=die] pam_faillock.so authfail"
            print "auth sufficient pam_faillock.so authsucc"
            inserted_rules = 1
            next
        }

        {
            print
        }

        END { if (inserted_rules == 0) exit 1 }
    ' "$PAM_AUTH" > "$auth_tmp" || {
        rm -f "$auth_tmp"
        log_error "Could not insert faillock rules around pam_unix"
        return 1
    }

    mv "$auth_tmp" "$PAM_AUTH"

    # The account rule is required so locked accounts are denied.
    if ! grep -Eq '^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_unix\.so' \
        "$PAM_ACCOUNT"; then

        printf '%s\n' \
            'account required pam_faillock.so' >> "$PAM_ACCOUNT"

    else
        local account_tmp
        account_tmp="$(mktemp)"

        awk '
            BEGIN { inserted = 0 }

            /^[[:space:]]*account[[:space:]]+.*pam_unix\.so/ && inserted == 0 {
                print "account required pam_faillock.so"
                inserted = 1
                print
                next
            }

            {
                print
            }
        ' "$PAM_ACCOUNT" > "$account_tmp"

        mv "$account_tmp" "$PAM_ACCOUNT"
    fi

    chmod 644 "$PAM_AUTH" "$PAM_ACCOUNT"
    chown root:root "$PAM_AUTH" "$PAM_ACCOUNT"

    audit_pam_faillock
}


# ------------------------------------------------------------
# 5.3.3.1.1 - Failed attempts lockout
# ------------------------------------------------------------

audit_faillock_deny() {
    local expected="${FAILLOCK_DENY:-5}"
    local actual=""

    if [[ -f "$FAILLock" ]]; then
        actual="$(
            awk -F '=' '
                /^[[:space:]]*deny[[:space:]]*=/ {
                    gsub(/[[:space:]]/, "", $2)
                    print $2
                    exit
                }
            ' "$FAILLock"
        )"
    fi

    if [[ "$actual" == "$expected" ]]; then
        audit_pass \
            "5.3.3.1.1" \
            "Failed authentication lockout" \
            "deny=$actual"
        return 0
    fi

    audit_fail \
        "5.3.3.1.1" \
        "Failed authentication lockout" \
        "Expected deny=$expected, found ${actual:-unset}"

    return 1
}


remediate_faillock_deny() {
    local expected="${FAILLOCK_DENY:-5}"

    if [[ ! -f "$FAILLock" ]]; then
        touch "$FAILLock"
    fi

    backup_file "$FAILLock"

    if grep -Eq '^[[:space:]]*#?[[:space:]]*deny[[:space:]]*=' "$FAILLock"; then
        sed -i -E \
            "s/^[[:space:]]*#?[[:space:]]*deny[[:space:]]*=.*/deny = ${expected}/" \
            "$FAILLock"
    else
        printf 'deny = %s\n' "$expected" >> "$FAILLock"
    fi

    chmod 644 "$FAILLock"
    chown root:root "$FAILLock"

    audit_pass \
        "5.3.3.1.1" \
        "Failed authentication lockout" \
        "deny=$expected"

    return 0
}


# ------------------------------------------------------------
# 5.3.3.1.2 - Unlock time
# ------------------------------------------------------------

audit_faillock_unlock_time() {
    local expected="${FAILLOCK_UNLOCK_TIME:-900}"
    local actual=""

    if [[ -f "$FAILLock" ]]; then
        actual="$(
            awk -F '=' '
                /^[[:space:]]*unlock_time[[:space:]]*=/ {
                    gsub(/[[:space:]]/, "", $2)
                    print $2
                    exit
                }
            ' "$FAILLock"
        )"
    fi

    if [[ "$actual" == "$expected" ]]; then
        audit_pass \
            "5.3.3.1.2" \
            "PAM account unlock time" \
            "unlock_time=$actual"
        return 0
    fi

    audit_fail \
        "5.3.3.1.2" \
        "PAM account unlock time" \
        "Expected unlock_time=$expected, found ${actual:-unset}"

    return 1
}


audit_faillock_fail_interval() {
    local expected="${FAILLOCK_FAIL_INTERVAL:-900}"
    local actual=""

    if [[ -f "$FAILLock" ]]; then
        actual="$(awk -F '=' '/^[[:space:]]*fail_interval[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$FAILLock")"
    fi

    if [[ "$actual" == "$expected" ]]; then
        audit_pass "5.3.3.1.3" "PAM failure interval" "fail_interval=$actual"
        return 0
    fi

    audit_fail "5.3.3.1.3" "PAM failure interval" "Expected fail_interval=$expected, found ${actual:-unset}"
    return 1
}


remediate_faillock_unlock_time() {
    local expected="${FAILLOCK_UNLOCK_TIME:-900}"

    if [[ ! -f "$FAILLock" ]]; then
        touch "$FAILLock"
    fi

    backup_file "$FAILLock"

    if grep -Eq '^[[:space:]]*#?[[:space:]]*unlock_time[[:space:]]*=' "$FAILLock"; then
        sed -i -E \
            "s/^[[:space:]]*#?[[:space:]]*unlock_time[[:space:]]*=.*/unlock_time = ${expected}/" \
            "$FAILLock"
    else
        printf 'unlock_time = %s\n' "$expected" >> "$FAILLock"
    fi

    chmod 644 "$FAILLock"
    chown root:root "$FAILLock"

    audit_pass \
        "5.3.3.1.2" \
        "PAM account unlock time" \
        "unlock_time=$expected"

    return 0
}


# ------------------------------------------------------------
# 5.3.3.2.x - Password quality
# ------------------------------------------------------------

get_pwquality_value() {
    local key="$1"

    [[ -f "$PWQUALITY" ]] || return 1

    awk -F '=' -v wanted="$key" '
        /^[[:space:]]*#/ { next }

        {
            key=$1
            value=$2

            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)

            if (key == wanted) {
                print value
                exit
            }
        }
    ' "$PWQUALITY"
}


set_pwquality_value() {
    local key="$1"
    local value="$2"

    if [[ ! -f "$PWQUALITY" ]]; then
        touch "$PWQUALITY"
    fi

    backup_file "$PWQUALITY"

    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=" "$PWQUALITY"; then
        sed -i -E \
            "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" \
            "$PWQUALITY"
    else
        printf '%s = %s\n' "$key" "$value" >> "$PWQUALITY"
    fi

    chown root:root "$PWQUALITY"
    chmod 644 "$PWQUALITY"
}


set_pwquality_flag() {
    local flag="$1"

    [[ -f "$PWQUALITY" ]] || touch "$PWQUALITY" || return 1
    backup_file "$PWQUALITY" || return 1

    if ! grep -Eq "^[[:space:]]*${flag}([[:space:]]|$)" "$PWQUALITY"; then
        printf '%s\n' "$flag" >> "$PWQUALITY" || return 1
    fi

    chown root:root "$PWQUALITY" && chmod 644 "$PWQUALITY"
}


audit_pwquality_numeric() {
    local check_id="$1"
    local title="$2"
    local key="$3"
    local expected="$4"

    local actual
    actual="$(get_pwquality_value "$key" || true)"

    if [[ "$actual" == "$expected" ]]; then
        audit_pass \
            "$check_id" \
            "$title" \
            "$key=$actual"
        return 0
    fi

    audit_fail \
        "$check_id" \
        "$title" \
        "Expected $key=$expected, found ${actual:-unset}"

    return 1
}


# ------------------------------------------------------------
# 5.3.3.2.1 - Character change requirement
# ------------------------------------------------------------

audit_pwquality_difok() {
    audit_pwquality_numeric \
        "5.3.3.2.1" \
        "Password changed characters" \
        "difok" \
        "${PASSWORD_DIFOK:-2}"
}


remediate_pwquality_difok() {
    set_pwquality_value \
        "difok" \
        "${PASSWORD_DIFOK:-2}"

    audit_pass \
        "5.3.3.2.1" \
        "Password changed characters" \
        "difok=${PASSWORD_DIFOK:-2}"
}


# ------------------------------------------------------------
# 5.3.3.2.2 - Password length
# ------------------------------------------------------------

audit_pwquality_minlen() {
    audit_pwquality_numeric \
        "5.3.3.2.2" \
        "Password minimum length" \
        "minlen" \
        "${PASSWORD_MIN_LENGTH:-14}"
}


remediate_pwquality_minlen() {
    set_pwquality_value \
        "minlen" \
        "${PASSWORD_MIN_LENGTH:-14}"

    audit_pass \
        "5.3.3.2.2" \
        "Password minimum length" \
        "minlen=${PASSWORD_MIN_LENGTH:-14}"
}


# ------------------------------------------------------------
# 5.3.3.2.3 - Password complexity
# ------------------------------------------------------------

audit_pwquality_complexity() {
    local failures=0

    audit_pwquality_numeric \
        "5.3.3.2.3" \
        "Password uppercase requirement" \
        "ucredit" \
            "-${PASSWORD_MIN_UPPER:-1}" || failures=$((failures + 1))

    audit_pwquality_numeric \
        "5.3.3.2.3" \
        "Password lowercase requirement" \
        "lcredit" \
            "-${PASSWORD_MIN_LOWER:-1}" || failures=$((failures + 1))

    audit_pwquality_numeric \
        "5.3.3.2.3" \
        "Password digit requirement" \
        "dcredit" \
            "-${PASSWORD_MIN_DIGITS:-1}" || failures=$((failures + 1))

    audit_pwquality_numeric \
        "5.3.3.2.3" \
        "Password other-character requirement" \
        "ocredit" \
            "-${PASSWORD_MIN_OTHER:-1}" || failures=$((failures + 1))

    return "$failures"
}


remediate_pwquality_complexity() {
    set_pwquality_value \
        "ucredit" \
        "-${PASSWORD_MIN_UPPER:-1}"

    set_pwquality_value \
        "lcredit" \
        "-${PASSWORD_MIN_LOWER:-1}"

    set_pwquality_value \
        "dcredit" \
        "-${PASSWORD_MIN_DIGITS:-1}"

    set_pwquality_value \
        "ocredit" \
        "-${PASSWORD_MIN_OTHER:-1}"

    audit_pass \
        "5.3.3.2.3" \
        "Password complexity" \
        "Upper/lower/digit/other character requirements configured"

    return 0
}


# ------------------------------------------------------------
# 5.3.3.2.4 - Maximum same consecutive characters
# ------------------------------------------------------------

audit_pwquality_maxrepeat() {
    audit_pwquality_numeric \
        "5.3.3.2.4" \
        "Maximum repeated characters" \
        "maxrepeat" \
        "${PASSWORD_MAX_REPEAT:-3}"
}


remediate_pwquality_maxrepeat() {
    set_pwquality_value \
        "maxrepeat" \
        "${PASSWORD_MAX_REPEAT:-3}"

    audit_pass \
        "5.3.3.2.4" \
        "Maximum repeated characters" \
        "maxrepeat=${PASSWORD_MAX_REPEAT:-3}"
}


# ------------------------------------------------------------
# 5.3.3.2.5 - Maximum sequential characters
# ------------------------------------------------------------

audit_pwquality_maxsequence() {
    audit_pwquality_numeric \
        "5.3.3.2.5" \
        "Maximum sequential characters" \
        "maxsequence" \
        "${PASSWORD_MAX_SEQUENCE:-3}"
}


remediate_pwquality_maxsequence() {
    set_pwquality_value \
        "maxsequence" \
        "${PASSWORD_MAX_SEQUENCE:-3}"

    audit_pass \
        "5.3.3.2.5" \
        "Maximum sequential characters" \
        "maxsequence=${PASSWORD_MAX_SEQUENCE:-3}"
}


# ------------------------------------------------------------
# 5.3.3.2.6 - Maximum class repetition
# ------------------------------------------------------------

audit_pwquality_maxclassrepeat() {
    audit_pwquality_numeric \
        "5.3.3.2.6" \
        "Maximum character-class repetition" \
        "maxclassrepeat" \
        "${PASSWORD_MAX_CLASS_REPEAT:-4}"
}


remediate_pwquality_maxclassrepeat() {
    set_pwquality_value \
        "maxclassrepeat" \
        "${PASSWORD_MAX_CLASS_REPEAT:-4}"

    audit_pass \
        "5.3.3.2.6" \
        "Maximum character-class repetition" \
        "maxclassrepeat=${PASSWORD_MAX_CLASS_REPEAT:-4}"
}


# ------------------------------------------------------------
# 5.3.3.2.8 - Root password quality
# ------------------------------------------------------------

audit_root_password_quality() {
    local root_hash

    root_hash="$(getent shadow root 2>/dev/null | cut -d: -f2 || true)"

    if [[ -z "$root_hash" || "$root_hash" == "!" || "$root_hash" == "*" ]]; then
        audit_pass \
            "5.3.3.2.8" \
            "Root password quality" \
            "Root password authentication is disabled/locked"
        return 0
    fi

    local minlen
    minlen="$(get_pwquality_value "minlen" || true)"

    if [[ "$minlen" == "${PASSWORD_MIN_LENGTH:-14}" ]] &&
       [[ -f "$PWQUALITY" ]] &&
       grep -Eq '^[[:space:]]*enforce_for_root([[:space:]]|$)' "$PWQUALITY"; then
        audit_pass \
            "5.3.3.2.8" \
            "Root password quality" \
            "Password quality settings, including enforce_for_root, apply to root"
        return 0
    fi

    audit_fail \
        "5.3.3.2.8" \
        "Root password quality" \
        "Expected minlen=${PASSWORD_MIN_LENGTH:-14} and enforce_for_root in $PWQUALITY"

    return 1
}


remediate_root_password_quality() {
    # Password quality is controlled through pwquality.conf.
    # We do not automatically change the root password.
    set_pwquality_value \
        "minlen" \
        "${PASSWORD_MIN_LENGTH:-14}"

    set_pwquality_value \
        "ucredit" \
        "-${PASSWORD_MIN_UPPER:-1}"

    set_pwquality_value \
        "lcredit" \
        "-${PASSWORD_MIN_LOWER:-1}"

    set_pwquality_value \
        "dcredit" \
        "-${PASSWORD_MIN_DIGITS:-1}"

    set_pwquality_value \
        "ocredit" \
        "-${PASSWORD_MIN_OTHER:-1}" || return 1

    set_pwquality_flag "enforce_for_root" || return 1

    audit_pass \
        "5.3.3.2.8" \
        "Root password quality" \
        "Password quality policy configured without changing the root password"

    return 0
}


# ------------------------------------------------------------
# 5.3.3.3.2 - Root password history
# ------------------------------------------------------------

audit_root_password_history() {
    local expected="${PASSWORD_HISTORY:-24}"

    if [[ ! -f "$PAM_PASSWORD" ]]; then
        audit_fail \
            "5.3.3.3.2" \
            "Root password history" \
            "$PAM_PASSWORD does not exist"
        return 1
    fi

    if grep -Eq \
        "^[[:space:]]*password[[:space:]]+.*pam_pwhistory\.so.*remember=${expected}.*enforce_for_root|^[[:space:]]*password[[:space:]]+.*pam_pwhistory\.so.*enforce_for_root.*remember=${expected}" \
        "$PAM_PASSWORD"; then

        audit_pass \
            "5.3.3.3.2" \
            "Root password history" \
            "pam_pwhistory remember=${expected}"
        return 0
    fi

    audit_fail \
        "5.3.3.3.2" \
        "Root password history" \
        "pam_pwhistory remember=${expected} is not configured"

    return 1
}


remediate_root_password_history() {
    if [[ ! -f "$PAM_PASSWORD" ]]; then
        log_error "$PAM_PASSWORD does not exist"
        return 1
    fi

    pam_backup_file "$PAM_PASSWORD"

    # Remove existing pwhistory entries.
    pam_remove_setting_lines \
        "$PAM_PASSWORD" \
        'pam_pwhistory\.so'

    local tmp
    tmp="$(mktemp)"

        awk -v history="${PASSWORD_HISTORY:-24}" '
        /^[[:space:]]*password[[:space:]]+.*pam_unix\.so/ && inserted == 0 {
            print "password required pam_pwhistory.so use_authtok remember=" history " enforce_for_root"
            inserted = 1
            print
            next
        }

        {
            print
        }
        END { if (inserted == 0) exit 1 }
    ' "$PAM_PASSWORD" > "$tmp" || {
        rm -f "$tmp"
        log_error "Could not place pam_pwhistory before pam_unix"
        return 1
    }

    mv "$tmp" "$PAM_PASSWORD"

    chown root:root "$PAM_PASSWORD"
    chmod 644 "$PAM_PASSWORD"

    audit_pass \
        "5.3.3.3.2" \
        "Root password history" \
        "pam_pwhistory remember=${PASSWORD_HISTORY:-24}"

    return 0
}


# ------------------------------------------------------------
# 5.3.3.4.1 - pam_unix nullok
# ------------------------------------------------------------

audit_pam_unix_nullok() {
    local failures=0

    for file in "$PAM_AUTH" "$PAM_PASSWORD" "$PAM_ACCOUNT"; do
        [[ -f "$file" ]] || continue

        if grep -Eq \
            '^[[:space:]]*(auth|password|account)[[:space:]]+.*pam_unix\.so.*[[:space:]]nullok([[:space:]]|$)' \
            "$file"; then

            audit_fail \
                "5.3.3.4.1" \
                "pam_unix nullok" \
                "nullok found in $file"

            failures=$((failures + 1))
        fi
    done

    if [[ "$failures" -eq 0 ]]; then
        audit_pass \
            "5.3.3.4.1" \
            "pam_unix nullok" \
            "No pam_unix nullok option found"
        return 0
    fi

    return 1
}


remediate_pam_unix_nullok() {
    local file

    for file in "$PAM_AUTH" "$PAM_PASSWORD" "$PAM_ACCOUNT"; do
        [[ -f "$file" ]] || continue

        if grep -Eq \
            '^[[:space:]]*(auth|password|account)[[:space:]]+.*pam_unix\.so.*[[:space:]]nullok([[:space:]]|$)' \
            "$file"; then

            pam_backup_file "$file"

            sed -i -E \
                's/[[:space:]]+nullok([[:space:]]|$)/\1/g' \
                "$file"
        fi
    done

    audit_pass \
        "5.3.3.4.1" \
        "pam_unix nullok" \
        "pam_unix nullok option removed"

    return 0
}


# ------------------------------------------------------------
# Password aging helpers
# ------------------------------------------------------------

get_login_defs_value() {
    local key="$1"

    [[ -f "$LOGIN_DEFS" ]] || return 1

    awk -v wanted="$key" '
        $1 == wanted {
            print $2
            exit
        }
    ' "$LOGIN_DEFS"
}


set_login_defs_value() {
    local key="$1"
    local value="$2"

    if [[ ! -f "$LOGIN_DEFS" ]]; then
        touch "$LOGIN_DEFS"
    fi

    backup_file "$LOGIN_DEFS"

    if grep -Eq "^[[:space:]]*${key}[[:space:]]+" "$LOGIN_DEFS"; then
        sed -i -E \
            "s|^[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" \
            "$LOGIN_DEFS"
    else
        printf '%s %s\n' "$key" "$value" >> "$LOGIN_DEFS"
    fi

    chown root:root "$LOGIN_DEFS"
    chmod 644 "$LOGIN_DEFS"
}


# ------------------------------------------------------------
# 5.4.1.1 - Password expiration
# ------------------------------------------------------------

audit_password_expiration() {
    local expected="${PASSWORD_MAX_DAYS:-365}"
    local failures=0

    if [[ ! -f "$LOGIN_DEFS" ]]; then
        audit_fail \
            "5.4.1.1" \
            "Password expiration" \
            "$LOGIN_DEFS does not exist"
        return 1
    fi

    local max_days
    max_days="$(get_login_defs_value "PASS_MAX_DAYS" || true)"

    if [[ "$max_days" == "$expected" ]]; then
        audit_pass \
            "5.4.1.1" \
            "Password expiration" \
            "PASS_MAX_DAYS=$max_days"
    else
        audit_fail \
            "5.4.1.1" \
            "Password expiration" \
            "Expected PASS_MAX_DAYS=$expected, found ${max_days:-unset}"
        failures=$((failures + 1))
    fi

    return "$failures"
}


remediate_password_expiration() {
    local expected="${PASSWORD_MAX_DAYS:-365}"

    set_login_defs_value \
        "PASS_MAX_DAYS" \
        "$expected"

    # Apply to existing normal user accounts.
    while IFS=: read -r username _ uid _ _ home shell; do

        if (( uid < 1000 )); then
            continue
        fi

          if [[ "$shell" == */nologin || "$shell" == */false ]]; then
            continue
        fi

        if command_exists chage; then
            chage -M "$expected" "$username" 2>/dev/null || {
                log_warning "Could not update PASS_MAX_DAYS for $username"
            }
        fi

    done < /etc/passwd

    audit_pass \
        "5.4.1.1" \
        "Password expiration" \
        "PASS_MAX_DAYS=$expected"

    return 0
}


# ------------------------------------------------------------
# 5.4.1.2 - Password minimum age
# ------------------------------------------------------------

audit_password_min_age() {
    local expected="${PASSWORD_MIN_DAYS:-1}"
    local actual

    actual="$(get_login_defs_value "PASS_MIN_DAYS" || true)"

    if [[ "$actual" == "$expected" ]]; then
        audit_pass \
            "5.4.1.2" \
            "Password minimum age" \
            "PASS_MIN_DAYS=$actual"
        return 0
    fi

    audit_fail \
        "5.4.1.2" \
        "Password minimum age" \
        "Expected PASS_MIN_DAYS=$expected, found ${actual:-unset}"

    return 1
}


remediate_password_min_age() {
    local expected="${PASSWORD_MIN_DAYS:-1}"

    set_login_defs_value \
        "PASS_MIN_DAYS" \
        "$expected"

    while IFS=: read -r username _ uid _ _ home shell; do

        if (( uid < 1000 )); then
            continue
        fi

          if [[ "$shell" == */nologin || "$shell" == */false ]]; then
            continue
        fi

        chage -m "$expected" "$username" 2>/dev/null || {
            log_warning "Could not update PASS_MIN_DAYS for $username"
        }

    done < /etc/passwd

    audit_pass \
        "5.4.1.2" \
        "Password minimum age" \
        "PASS_MIN_DAYS=$expected"

    return 0
}


# ------------------------------------------------------------
# 5.4.1.3 - Password expiration warning
# ------------------------------------------------------------

audit_password_warning() {
    local expected="${PASSWORD_WARN_DAYS:-7}"
    local actual

    actual="$(get_login_defs_value "PASS_WARN_AGE" || true)"

    if [[ "$actual" == "$expected" ]]; then
        audit_pass \
            "5.4.1.3" \
            "Password expiration warning" \
            "PASS_WARN_AGE=$actual"
        return 0
    fi

    audit_fail \
        "5.4.1.3" \
        "Password expiration warning" \
        "Expected PASS_WARN_AGE=$expected, found ${actual:-unset}"

    return 1
}


remediate_password_warning() {
    local expected="${PASSWORD_WARN_DAYS:-7}"

    set_login_defs_value \
        "PASS_WARN_AGE" \
        "$expected"

    while IFS=: read -r username _ uid _ _ home shell; do

        if (( uid < 1000 )); then
            continue
        fi

        if [[ "$shell" == "/usr/sbin/nologin" ||
              "$shell" == "/bin/false" ]]; then
            continue
        fi

        chage -W "$expected" "$username" 2>/dev/null || {
            log_warning "Could not update PASS_WARN_AGE for $username"
        }

    done < /etc/passwd

    audit_pass \
        "5.4.1.3" \
        "Password expiration warning" \
        "PASS_WARN_AGE=$expected"

    return 0
}


# ------------------------------------------------------------
# 5.4.1.5 - Inactive password lock
# ------------------------------------------------------------

shadow_inactive_days() {
    local username="${1:-}"
    [[ -n "$username" ]] || return 1
    getent shadow "$username" 2>/dev/null | awk -F: 'NR == 1 {print $7}'
}

audit_password_inactive_lock() {
    local expected="${PASSWORD_INACTIVE_DAYS:-30}"
    local failures=0
    local default_inactive

    default_inactive="$(useradd -D 2>/dev/null | sed -n 's/^INACTIVE=//p')"
    if [[ "$default_inactive" != "$expected" ]]; then
        audit_fail \
            "5.4.1.5" \
            "Inactive password lock default" \
            "Expected INACTIVE=$expected for new accounts, found ${default_inactive:-unset}"
        failures=$((failures + 1))
    fi

    while IFS=: read -r username _ uid _ _ home shell; do

        if (( uid < 1000 )) && [[ "$username" != "root" ]]; then
            continue
        fi

          if [[ "$shell" == */nologin || "$shell" == */false ]]; then
            continue
        fi

        local inactive
        inactive="$(shadow_inactive_days "$username" || true)"

        if [[ "$inactive" != "$expected" ]]; then
            audit_fail \
                "5.4.1.5" \
                "Inactive password lock" \
                "$username shadow inactive field is '${inactive:-unset}', expected $expected days"
            failures=$((failures + 1))
        fi

    done < /etc/passwd

    if [[ "$failures" -eq 0 ]]; then
        audit_pass \
            "5.4.1.5" \
            "Inactive password lock" \
            "Eligible users have an inactive password lock configured"
        return 0
    fi

    return 1
}


remediate_password_inactive_lock() {
    local expected="${PASSWORD_INACTIVE_DAYS:-30}"
    local actual

    if ! useradd -D -f "$expected"; then
        log_error "Could not set the default inactive password lock for new accounts"
        return 1
    fi

    actual="$(useradd -D 2>/dev/null | sed -n 's/^INACTIVE=//p')"
    if [[ "$actual" != "$expected" ]]; then
        log_error \
            "Default inactive policy remains $actual; expected $expected"
        return 1
    fi

    chage -I "$expected" root 2>/dev/null || {
        log_error "Could not set inactive password lock for root."
        return 1
    }

    while IFS=: read -r username _ uid _ _ home shell; do

        if (( uid < 1000 )); then
            continue
        fi

          if [[ "$shell" == */nologin || "$shell" == */false ]]; then
            continue
        fi

        chage -I "$expected" "$username" 2>/dev/null || {
            log_warning "Could not configure inactive lock for $username"
        }

    done < /etc/passwd

    audit_pass \
        "5.4.1.5" \
        "Inactive password lock" \
        "Inactive password lock set to ${expected} days"

    return 0
}


# ------------------------------------------------------------
# 5.4.2.5 - Root PATH integrity
# ------------------------------------------------------------

audit_root_path() {
    local root_path="${PATH:-}"

    local invalid=0
    local directory

    IFS=':' read -ra path_entries <<< "$root_path"

    for directory in "${path_entries[@]}"; do

        # Empty PATH components mean current directory.
        if [[ -z "$directory" ]]; then
            audit_fail \
                "5.4.2.5" \
                "Root PATH integrity" \
                "Root PATH contains an empty element"
            invalid=1
            continue
        fi

        if [[ ! "$directory" = /* ]]; then
            audit_fail \
                "5.4.2.5" \
                "Root PATH integrity" \
                "Relative path found: $directory"
            invalid=1
            continue
        fi

        local resolved_directory
        resolved_directory="$(readlink -f -- "$directory" 2>/dev/null || true)"
        if [[ -z "$resolved_directory" || ! -d "$resolved_directory" ]]; then
            audit_warning \
                "5.4.2.5" \
                "Root PATH integrity" \
                "PATH directory does not exist: $directory"
            continue
        fi

        local owner mode
        owner="$(stat -c '%U' "$resolved_directory" 2>/dev/null || true)"
        mode="$(stat -c '%a' "$resolved_directory" 2>/dev/null || true)"

        if [[ "$owner" != "root" ]]; then
            audit_fail \
                "5.4.2.5" \
                "Root PATH integrity" \
                "$directory is not owned by root"
            invalid=1
        fi

        # Group/other writable directory is unsafe.
        if (( (8#$mode & 00022) != 0 )); then
            audit_fail \
                "5.4.2.5" \
                "Root PATH integrity" \
                "$directory is writable by group/other"
            invalid=1
        fi

    done

    if [[ "$invalid" -eq 0 ]]; then
        audit_pass \
            "5.4.2.5" \
            "Root PATH integrity" \
            "Root PATH entries passed basic ownership and permission checks"
        return 0
    fi

    return 1
}


remediate_root_path() {
    local directories=(
        /usr/local/sbin
        /usr/local/bin
        /usr/sbin
        /usr/bin
        /sbin
        /bin
    )

    local directory resolved_directory
    local -A processed_directories=()

    for directory in "${directories[@]}"; do
        resolved_directory="$(readlink -f -- "$directory" 2>/dev/null || true)"
        if [[ -z "$resolved_directory" || ! -d "$resolved_directory" ||
              -n "${processed_directories[$resolved_directory]:-}" ]]; then
            continue
        fi
        processed_directories["$resolved_directory"]=1

        chown root:root "$resolved_directory" 2>/dev/null || {
            log_warning "Could not set root ownership on $directory"
        }

        chmod go-w "$resolved_directory" 2>/dev/null || {
            log_warning "Could not remove group/other write permission from $directory"
        }

    done

    audit_root_path
}


# ------------------------------------------------------------
# 5.4.3.3 - Default user umask
# ------------------------------------------------------------

audit_default_umask() {
    local expected="${DEFAULT_UMASK:-027}"
    local failures=0

    if [[ -f /etc/login.defs ]]; then
        local umask_value
        umask_value="$(grep -E '^[[:space:]]*UMASK[[:space:]]+' /etc/login.defs |
            tail -n 1 |
            awk '{print $2}' || true)"

        if [[ "$umask_value" == "$expected" ]]; then
            audit_pass \
                "5.4.3.3" \
                "Default user umask" \
                "login.defs UMASK=$umask_value"
        else
            audit_fail \
                "5.4.3.3" \
                "Default user umask" \
                "Expected UMASK=$expected, found ${umask_value:-unset}"
            failures=$((failures + 1))
        fi
    fi

    local file

    for file in \
        /etc/profile \
        /etc/bash.bashrc \
        /etc/profile.d/*.sh; do

        [[ -f "$file" ]] || continue

        if grep -Eq \
            '^[[:space:]]*umask[[:space:]]+([0-7]{3,4})' \
            "$file"; then

            local value
            value="$(grep -E \
                '^[[:space:]]*umask[[:space:]]+([0-7]{3,4})' \
                "$file" |
                tail -n 1 |
                awk '{print $2}' || true)"

            if [[ "$value" != "$expected" ]]; then
                audit_fail \
                    "5.4.3.3" \
                    "Default user umask" \
                    "$file contains umask $value"
                failures=$((failures + 1))
            fi
        fi
    done

    if [[ "$failures" -eq 0 ]]; then
        audit_pass \
            "5.4.3.3" \
            "Default user umask" \
            "Default umask is configured as $expected"
        return 0
    fi

    return 1
}


remediate_default_umask() {
    local expected="${DEFAULT_UMASK:-027}"

    set_login_defs_value \
        "UMASK" \
        "$expected"

    # Configure system-wide shell sessions.
    local profile_file="/etc/profile.d/99-cis-umask.sh"

    if [[ -f "$profile_file" ]]; then
        backup_file "$profile_file"
    fi

    cat > "$profile_file" <<EOF
# CIS Ubuntu 24.04 LTS Level 1
# Default user umask
umask ${expected}
EOF

    chown root:root "$profile_file"
    chmod 644 "$profile_file"

    local startup_file
    for startup_file in /etc/profile /etc/bash.bashrc; do
        if [[ ! -f "$startup_file" ]]; then
            log_error "Required shell startup file is missing: $startup_file"
            return 1
        fi

        if ! grep -Eq "^[[:space:]]*umask[[:space:]]+${expected}([[:space:]]|$)" "$startup_file"; then
            backup_file "$startup_file" || return 1
            printf '\n# CIS Ubuntu 24.04 LTS default umask\numask %s\n' "$expected" >> "$startup_file" || return 1
        fi
    done

    audit_pass \
        "5.4.3.3" \
        "Default user umask" \
        "Default user umask configured as $expected"

    return 0
}


# ------------------------------------------------------------
# Account checks
# ------------------------------------------------------------

audit_empty_passwords() {
    local empty_accounts=()
    local username hash

    while IFS=: read -r username hash _; do

        if [[ -z "$hash" ]]; then
            empty_accounts+=("$username")
        fi

    done < <(getent shadow 2>/dev/null || true)

    if [[ "${#empty_accounts[@]}" -eq 0 ]]; then
        audit_pass \
            "ACCOUNT-EMPTY-PASSWORD" \
            "Empty account passwords" \
            "No accounts with empty password hashes found"
        return 0
    fi

    audit_fail \
        "ACCOUNT-EMPTY-PASSWORD" \
        "Empty account passwords" \
        "Accounts with empty passwords: ${empty_accounts[*]}"

    return 1
}


remediate_empty_passwords() {
    local username hash

    while IFS=: read -r username hash _; do

        if [[ -z "$hash" ]]; then
            if passwd -l "$username" >/dev/null 2>&1; then
                log_success "Locked empty-password account: $username"
            else
                log_warning "Could not lock account: $username"
            fi
        fi

    done < <(getent shadow 2>/dev/null || true)

    audit_empty_passwords
}


audit_uid_zero_accounts() {
    local users=()
    local username uid

    while IFS=: read -r username _ uid _; do
        if [[ "$uid" == "0" ]]; then
            users+=("$username")
        fi
    done < /etc/passwd

    if [[ "${#users[@]}" -eq 1 && "${users[0]}" == "root" ]]; then
        audit_pass \
            "ACCOUNT-UID0" \
            "UID 0 accounts" \
            "Only root has UID 0"
        return 0
    fi

    audit_fail \
        "ACCOUNT-UID0" \
        "UID 0 accounts" \
        "Additional UID 0 accounts found: ${users[*]}"

    return 1
}


remediate_uid_zero_accounts() {
    local username uid

    while IFS=: read -r username _ uid _; do

        if [[ "$uid" == "0" && "$username" != "root" ]]; then
            log_warning \
                "Additional UID 0 account detected: $username"

            log_warning \
                "UID 0 account was NOT automatically modified"

        fi

    done < /etc/passwd

    audit_uid_zero_accounts
}


# ------------------------------------------------------------
# PAM file permissions
# ------------------------------------------------------------

audit_pam_permissions() {
    local failures=0
    local file

    for file in \
        "$PAM_AUTH" \
        "$PAM_ACCOUNT" \
        "$PAM_PASSWORD" \
        "$PAM_SESSION"; do

        [[ -f "$file" ]] || continue

        local owner group mode
        owner="$(stat -c '%U' "$file" 2>/dev/null || true)"
        group="$(stat -c '%G' "$file" 2>/dev/null || true)"
        mode="$(stat -c '%a' "$file" 2>/dev/null || true)"

        if [[ "$owner" != "root" || "$group" != "root" ]]; then
            audit_fail \
                "PAM-PERM" \
                "PAM file permissions" \
                "$file is owned by ${owner}:${group}"
            failures=$((failures + 1))
        fi

        if (( 8#$mode & 00022 )); then
            audit_fail \
                "PAM-PERM" \
                "PAM file permissions" \
                "$file is writable by group/other"
            failures=$((failures + 1))
        fi
    done

    if [[ "$failures" -eq 0 ]]; then
        audit_pass \
            "PAM-PERM" \
            "PAM file permissions" \
            "PAM configuration files have secure ownership and permissions"
        return 0
    fi

    return 1
}


remediate_pam_permissions() {
    local file

    for file in \
        "$PAM_AUTH" \
        "$PAM_ACCOUNT" \
        "$PAM_PASSWORD" \
        "$PAM_SESSION" \
        "$PWQUALITY" \
        "$FAILLock"; do

        [[ -f "$file" ]] || continue

        chown root:root "$file" 2>/dev/null || {
            log_warning "Could not set root ownership on $file"
        }

        chmod go-w "$file" 2>/dev/null || {
            log_warning "Could not remove group/other write permission from $file"
        }
    done

    audit_pam_permissions
}


# ------------------------------------------------------------
# Section 04 audit
# ------------------------------------------------------------

section_04_audit() {
    start_section "04 - PAM and Account Audit"

    local failures=0

    audit_pam_faillock || failures=$((failures + 1))
    audit_pam_pwquality_module || failures=$((failures + 1))

    audit_faillock_deny || failures=$((failures + 1))
    audit_faillock_unlock_time || failures=$((failures + 1))
    audit_faillock_fail_interval || failures=$((failures + 1))

    audit_pwquality_difok || failures=$((failures + 1))
    audit_pwquality_minlen || failures=$((failures + 1))
    audit_pwquality_complexity || failures=$((failures + 1))
    audit_pwquality_maxrepeat || failures=$((failures + 1))
    audit_pwquality_maxsequence || failures=$((failures + 1))
    audit_pwquality_maxclassrepeat || failures=$((failures + 1))
    audit_root_password_quality || failures=$((failures + 1))

    audit_root_password_history || failures=$((failures + 1))
    audit_pam_unix_nullok || failures=$((failures + 1))

    audit_password_expiration || failures=$((failures + 1))
    audit_password_min_age || failures=$((failures + 1))
    audit_password_warning || failures=$((failures + 1))
    audit_password_inactive_lock || failures=$((failures + 1))

    audit_root_path || failures=$((failures + 1))
    audit_default_umask || failures=$((failures + 1))

    audit_empty_passwords || failures=$((failures + 1))
    audit_uid_zero_accounts || failures=$((failures + 1))
    audit_pam_permissions || failures=$((failures + 1))

    end_section "04 - PAM and Account Audit"

    return "$failures"
}


# ------------------------------------------------------------
# Section 04 remediation
# ------------------------------------------------------------

section_04_remediate() {
    start_section "04 - PAM and Account Remediation"

    local failures=0

    remediate_pam_faillock || failures=$((failures + 1))
    remediate_faillock_deny || failures=$((failures + 1))
    remediate_faillock_unlock_time || failures=$((failures + 1))

    remediate_pwquality_difok || failures=$((failures + 1))
    remediate_pwquality_minlen || failures=$((failures + 1))
    remediate_pwquality_complexity || failures=$((failures + 1))
    remediate_pwquality_maxrepeat || failures=$((failures + 1))
    remediate_pwquality_maxsequence || failures=$((failures + 1))
    remediate_pwquality_maxclassrepeat || failures=$((failures + 1))
    remediate_root_password_quality || failures=$((failures + 1))

    remediate_root_password_history || failures=$((failures + 1))
    remediate_pam_pwquality_module || failures=$((failures + 1))
    remediate_pam_unix_nullok || failures=$((failures + 1))

    remediate_password_expiration || failures=$((failures + 1))
    remediate_password_min_age || failures=$((failures + 1))
    remediate_password_warning || failures=$((failures + 1))
    remediate_password_inactive_lock || failures=$((failures + 1))

    remediate_root_path || failures=$((failures + 1))
    remediate_default_umask || failures=$((failures + 1))

    remediate_empty_passwords || failures=$((failures + 1))
    remediate_uid_zero_accounts || failures=$((failures + 1))
    remediate_pam_permissions || failures=$((failures + 1))

    end_section "04 - PAM and Account Remediation"

    return "$failures"
}


# ------------------------------------------------------------
# Section 04 dispatcher
# ------------------------------------------------------------

section_04_pam_accounts() {
    local mode="${1:-audit}"

    case "$mode" in
        audit)
            section_04_audit
            ;;

        remediate|fix|apply)
            section_04_remediate
            ;;

        *)
            log_error "Unknown Section 04 mode: $mode"
            log_error "Valid modes: audit | remediate"
            return 1
            ;;
    esac
}


# ------------------------------------------------------------
# Section 04 status
# ------------------------------------------------------------

section_04_status() {
    echo
    echo "============================================================"
    echo " Section 04 - PAM and Account Status"
    echo "============================================================"

    echo
    echo "[PAM faillock]"
    if [[ -f "$FAILLock" ]]; then
        cat "$FAILLock"
    else
        echo "faillock.conf: NOT FOUND"
    fi

    echo
    echo "[Password quality]"
    if [[ -f "$PWQUALITY" ]]; then
        grep -E \
            '^[[:space:]]*(minlen|difok|ucredit|lcredit|dcredit|ocredit|maxrepeat|maxsequence|maxclassrepeat)[[:space:]]*=' \
            "$PWQUALITY" 2>/dev/null || true
    else
        echo "pwquality.conf: NOT FOUND"
    fi

    echo
    echo "[Password aging]"
    grep -E \
        '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK)[[:space:]]+' \
        "$LOGIN_DEFS" 2>/dev/null || true

    echo
    echo "[PAM faillock rules]"
    grep -n \
        'pam_faillock\.so' \
        "$PAM_AUTH" "$PAM_ACCOUNT" 2>/dev/null || true

    echo
    echo "[PAM password history]"
    grep -n \
        'pam_pwhistory\.so' \
        "$PAM_PASSWORD" 2>/dev/null || true

    echo
    echo "============================================================"
}


# ------------------------------------------------------------
# Direct execution support
# ------------------------------------------------------------

#!/usr/bin/env bash

# ============================================================
# CIS Ubuntu 24.04 LTS Level 1
# Section 05 - Logging and Audit Hardening
# ============================================================

RSYSLOG_CONFIG="/etc/rsyslog.conf"
RSYSLOG_CIS_CONFIG="/etc/rsyslog.d/99-cis-hardening.conf"
AUDIT_RULES_DIR="/etc/audit/rules.d"
AUDIT_CIS_RULES="${AUDIT_RULES_DIR}/99-cis-hardening.rules"
AUDIT_CONFIG="/etc/audit/auditd.conf"


# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------

logging_backup_file() {
    local file="$1"

    if [[ -f "$file" ]]; then
        backup_file "$file"
    fi
}


package_available() {
    local package="$1"

    dpkg-query -W -f='${Status}' "$package" 2>/dev/null |
        grep -q "install ok installed"
}


service_enabled() {
    local service="$1"

    systemctl is-enabled "$service" 2>/dev/null |
        grep -q '^enabled'
}


service_active() {
    local service="$1"

    systemctl is-active "$service" 2>/dev/null |
        grep -q '^active'
}


# ------------------------------------------------------------
# 6.1.2.4 - rsyslog service
# ------------------------------------------------------------

audit_rsyslog_service() {
    if [[ "${INSTALL_RSYSLOG:-yes}" != "yes" || "${ENABLE_RSYSLOG:-yes}" != "yes" ]]; then
        audit_skip \
            "6.1.2.4" \
            "rsyslog logging" \
            "rsyslog installation or service activation is disabled in the embedded configuration"
        return 0
    fi

    if ! command_exists rsyslogd; then
        audit_fail \
            "6.1.2.4" \
            "rsyslog logging" \
            "rsyslog is not installed"

        return 1
    fi

    if ! service_active "rsyslog"; then
        audit_fail \
            "6.1.2.4" \
            "rsyslog logging" \
            "rsyslog service is not active"

        return 1
    fi

    if ! service_enabled "rsyslog"; then
        audit_fail \
            "6.1.2.4" \
            "rsyslog logging" \
            "rsyslog service is not enabled"

        return 1
    fi

    if ! rsyslogd -N1 >/dev/null 2>"$LOG_DIR/rsyslog-validation.log"; then
        audit_fail \
            "6.1.2.4" \
            "rsyslog logging" \
            "rsyslog configuration validation failed"

        return 1
    fi

    audit_pass \
        "6.1.2.4" \
        "rsyslog logging" \
        "rsyslog is installed, enabled, active and configuration is valid"

    return 0
}


remediate_rsyslog_service() {
    if [[ "${INSTALL_RSYSLOG:-yes}" != "yes" || "${ENABLE_RSYSLOG:-yes}" != "yes" ]]; then
        log_warning "rsyslog installation or service activation is disabled in the embedded configuration"
        return 0
    fi

    if ! command_exists rsyslogd; then
        log_info "Installing rsyslog"

        install_package "rsyslog" || {
            log_error "Failed to install rsyslog"
            return 1
        }
    fi

    systemctl enable rsyslog >/dev/null 2>&1 || {
        log_error "Could not enable rsyslog"
        return 1
    }

    if ! systemctl start rsyslog >/dev/null 2>&1; then
        log_error "Could not start rsyslog"
        return 1
    fi

    if ! rsyslogd -N1 >/dev/null 2>"$LOG_DIR/rsyslog-validation.log"; then
        log_error "rsyslog configuration is invalid"
        return 1
    fi

    audit_pass \
        "6.1.2.4" \
        "rsyslog logging" \
        "rsyslog is installed, enabled and active"

    return 0
}


# ------------------------------------------------------------
# 6.1.2.4 - Local rsyslog facility configuration
# ------------------------------------------------------------

audit_rsyslog_facilities() {
    if [[ ! -f "$RSYSLOG_CONFIG" ]]; then
        audit_fail \
            "6.1.2.4" \
            "rsyslog facility logging" \
            "$RSYSLOG_CONFIG does not exist"

        return 1
    fi

    local failures=0

    # Ubuntu normally uses auth.log rather than the RHEL-style
    # /var/log/secure. Keep the Ubuntu log destinations.
    declare -A expected_rules=(
        ["authpriv"]="/var/log/auth.log"
        ["cron"]="/var/log/cron.log"
        ["kern"]="/var/log/kern.log"
        ["mail"]="/var/log/mail.log"
        ["user"]="/var/log/user.log"
    )

    local facility
    local destination

    for facility in "${!expected_rules[@]}"; do
        destination="${expected_rules[$facility]}"
        local escaped_destination="${destination//\//\\/}"

        if grep -REq \
            "^[[:space:]]*([^#[:space:]]+,)?${facility}\.\*[[:space:]]+-?${escaped_destination}([[:space:]]|$)" \
            /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then

            audit_pass \
                "6.1.2.4" \
                "rsyslog ${facility} logging" \
                "${facility} logs to ${destination}"

        else
            audit_fail \
                "6.1.2.4" \
                "rsyslog ${facility} logging" \
                "Expected ${facility} logging to ${destination}"

            failures=$((failures + 1))
        fi
    done

    return "$failures"
}


remediate_rsyslog_facilities() {
    if [[ ! -d /etc/rsyslog.d ]]; then
        mkdir -p /etc/rsyslog.d || return 1
    fi

    if [[ -f "$RSYSLOG_CIS_CONFIG" ]]; then
        logging_backup_file "$RSYSLOG_CIS_CONFIG"
    fi

    cat > "$RSYSLOG_CIS_CONFIG" <<'EOF'
# ============================================================
# CIS Ubuntu 24.04 LTS Level 1
# rsyslog local facility logging
#
# Ubuntu uses auth.log instead of /var/log/secure.
# ============================================================

auth,authpriv.* /var/log/auth.log
cron.* /var/log/cron.log
kern.* /var/log/kern.log
mail.* -/var/log/mail.log
user.* -/var/log/user.log

EOF

    chown root:root "$RSYSLOG_CIS_CONFIG"
    chmod 644 "$RSYSLOG_CIS_CONFIG"

    if ! rsyslogd -N1 >/dev/null 2>"$LOG_DIR/rsyslog-validation.log"; then
        log_error "New rsyslog configuration failed validation"
        rm -f "$RSYSLOG_CIS_CONFIG"
        return 1
    fi

    if ! systemctl restart rsyslog >/dev/null 2>&1; then
        log_error "Could not restart rsyslog"
        return 1
    fi

    audit_pass \
        "6.1.2.4" \
        "rsyslog facility logging" \
        "Ubuntu local facility logging configured"

    return 0
}


# ------------------------------------------------------------
# 6.1.2.5 - Remote rsyslog host
# ------------------------------------------------------------

audit_remote_rsyslog() {
    local enabled="${REMOTE_SYSLOG_ENABLED:-no}"
    local host="${REMOTE_SYSLOG_HOST:-}"
    local port="${REMOTE_SYSLOG_PORT:-514}"
    local protocol="${REMOTE_SYSLOG_PROTOCOL:-udp}"

    if [[ "${enabled,,}" != "yes" &&
          "${enabled,,}" != "true" &&
          "${enabled}" != "1" ]]; then

        audit_skip \
            "6.1.2.5" \
            "Remote rsyslog host" \
            "Remote logging is disabled in the embedded configuration"

        return 0
    fi

    if [[ -z "$host" ]]; then
        audit_fail \
            "6.1.2.5" \
            "Remote rsyslog host" \
            "Remote logging is enabled but REMOTE_SYSLOG_HOST is empty"

        return 1
    fi

    local transport="@"
    [[ "${protocol,,}" == "tcp" ]] && transport="@@"

    if grep -RFxq \
        "*.* ${transport}${host}:${port}" \
        /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null; then

        audit_pass \
            "6.1.2.5" \
            "Remote rsyslog host" \
            "Remote rsyslog forwarding configuration exists"

        return 0
    fi

    audit_fail \
        "6.1.2.5" \
        "Remote rsyslog host" \
        "Remote rsyslog forwarding is not configured"

    return 1
}


remediate_remote_rsyslog() {
    local enabled="${REMOTE_SYSLOG_ENABLED:-no}"
    local host="${REMOTE_SYSLOG_HOST:-}"
    local port="${REMOTE_SYSLOG_PORT:-514}"
    local protocol="${REMOTE_SYSLOG_PROTOCOL:-tcp}"

    if [[ "${enabled,,}" != "yes" &&
          "${enabled,,}" != "true" &&
          "${enabled}" != "1" ]]; then

        audit_skip \
            "6.1.2.5" \
            "Remote rsyslog host" \
            "Remote logging disabled in the embedded configuration"

        return 0
    fi

    if [[ -z "$host" ]]; then
        audit_warning \
            "6.1.2.5" \
            "Remote rsyslog host" \
            "Remote logging enabled but no destination host configured"

        return 1
    fi

    if [[ -f "$RSYSLOG_CIS_CONFIG" ]]; then
        logging_backup_file "$RSYSLOG_CIS_CONFIG"
    fi

    local forwarding_rule

    case "${protocol,,}" in
        tcp)
            forwarding_rule="*.* @@${host}:${port}"
            ;;

        udp)
            forwarding_rule="*.* @${host}:${port}"
            ;;

        *)
            log_error "Unsupported REMOTE_SYSLOG_PROTOCOL: $protocol"
            return 1
            ;;
    esac

    if ! grep -Fxq "$forwarding_rule" "$RSYSLOG_CIS_CONFIG" 2>/dev/null; then
        printf '\n# Remote rsyslog forwarding\n%s\n' "$forwarding_rule" \
            >> "$RSYSLOG_CIS_CONFIG"
    fi

    if ! rsyslogd -N1 >/dev/null 2>"$LOG_DIR/rsyslog-validation.log"; then
        log_error "rsyslog validation failed after adding remote logging"
        return 1
    fi

    systemctl restart rsyslog >/dev/null 2>&1 || {
        log_error "Could not restart rsyslog"
        return 1
    }

    audit_pass \
        "6.1.2.5" \
        "Remote rsyslog host" \
        "Remote logging configured for ${host}:${port}/${protocol}"

    return 0
}


# ------------------------------------------------------------
# 6.1.3.1 - Log file permissions
# ------------------------------------------------------------

audit_logfile_permissions() {
    local failures=0
    local file

    # Main Ubuntu log files.
    local log_files=(
        /var/log/auth.log
        /var/log/syslog
        /var/log/kern.log
        /var/log/cron.log
        /var/log/mail.log
        /var/log/user.log
        /var/log/dpkg.log
        /var/log/apt/history.log
        /var/log/apt/term.log
    )

    for file in "${log_files[@]}"; do

        [[ -e "$file" ]] || continue

        local owner group mode

        owner="$(stat -c '%U' "$file" 2>/dev/null || true)"
        group="$(stat -c '%G' "$file" 2>/dev/null || true)"
        mode="$(stat -c '%a' "$file" 2>/dev/null || true)"

        if [[ "$owner" != "root" ]]; then
            audit_fail \
                "6.1.3.1" \
                "Log file permissions" \
                "$file is owned by $owner"

            failures=$((failures + 1))
            continue
        fi

        # Logs must not be writable by group or other.
        if [[ "$mode" =~ ^[0-7]+$ ]] &&
           (( 8#$mode & 00022 )); then

            audit_fail \
                "6.1.3.1" \
                "Log file permissions" \
                "$file mode $mode allows group/other write access"

            failures=$((failures + 1))
        fi

    done

    if [[ "$failures" -eq 0 ]]; then
        audit_pass \
            "6.1.3.1" \
            "Log file permissions" \
            "Checked log files are root-owned and not group/other writable"
        return 0
    fi

    return 1
}


remediate_logfile_permissions() {
    local file

    local log_files=(
        /var/log/auth.log
        /var/log/syslog
        /var/log/kern.log
        /var/log/cron.log
        /var/log/mail.log
        /var/log/user.log
        /var/log/dpkg.log
        /var/log/apt/history.log
        /var/log/apt/term.log
    )

    for file in "${log_files[@]}"; do

        [[ -e "$file" ]] || continue

        chown root:root "$file" 2>/dev/null || {
            log_warning "Could not set root ownership on $file"
        }

        chmod go-w "$file" 2>/dev/null || {
            log_warning "Could not remove group/other write permission from $file"
        }

    done

    audit_logfile_permissions
}


# ------------------------------------------------------------
# Auditd installation
# ------------------------------------------------------------

audit_auditd_service() {
    if [[ "${INSTALL_AUDITD:-yes}" != "yes" || "${ENABLE_AUDITD:-yes}" != "yes" ]]; then
        audit_skip \
            "6.2-AUDITD" \
            "auditd service" \
            "auditd installation or service activation is disabled in the embedded configuration"
        return 0
    fi

    if ! command_exists auditd; then
        audit_fail \
            "6.2-AUDITD" \
            "auditd service" \
            "auditd is not installed"

        return 1
    fi

    if ! service_enabled "auditd"; then
        audit_fail \
            "6.2-AUDITD" \
            "auditd service" \
            "auditd is not enabled"

        return 1
    fi

    if ! service_active "auditd"; then
        audit_fail \
            "6.2-AUDITD" \
            "auditd service" \
            "auditd is not active"

        return 1
    fi

    audit_pass \
        "6.2-AUDITD" \
        "auditd service" \
        "auditd is installed, enabled and active"

    return 0
}


remediate_auditd_service() {
    if [[ "${INSTALL_AUDITD:-yes}" != "yes" || "${ENABLE_AUDITD:-yes}" != "yes" ]]; then
        log_warning "auditd installation or service activation is disabled in the embedded configuration"
        return 0
    fi

    if ! command_exists auditd; then
        log_info "Installing auditd"

        install_package "auditd" || {
            log_error "Failed to install auditd"
            return 1
        }
    fi

    systemctl enable auditd >/dev/null 2>&1 || {
        log_error "Could not enable auditd"
        return 1
    }

    if systemctl is-active --quiet auditd; then
        audit_pass \
            "6.2-AUDITD" \
            "auditd service" \
            "auditd is already active"
        return 0
    fi

    # Ubuntu may refuse a normal systemctl start/restart depending
    # on audit kernel state. Try service as fallback.
    if systemctl start auditd >/dev/null 2>&1 ||
       service auditd start >/dev/null 2>&1; then

        audit_pass \
            "6.2-AUDITD" \
            "auditd service" \
            "auditd started successfully"

        return 0
    fi

    log_warning \
        "auditd could not be started in the current boot; reboot may be required"

    return 1
}


# ------------------------------------------------------------
# Audit rules
# ------------------------------------------------------------

audit_audit_rules_directory() {
    if [[ ! -d "$AUDIT_RULES_DIR" ]]; then
        audit_fail \
            "6.2-RULES" \
            "audit rule directory" \
            "$AUDIT_RULES_DIR does not exist"

        return 1
    fi

    audit_pass \
        "6.2-RULES" \
        "audit rule directory" \
        "$AUDIT_RULES_DIR exists"

    return 0
}


audit_cis_audit_rules() {
    if [[ ! -d "$AUDIT_RULES_DIR" ]]; then
        audit_fail \
            "6.2-RULES" \
            "CIS audit rules" \
            "$AUDIT_RULES_DIR does not exist"

        return 1
    fi

    local failures=0
    local rule rule_path

    local expected_rules=(
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/group -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
        "-w /etc/gshadow -p wa -k identity"
        "-w /etc/sudoers -p wa -k scope"
        "-w /etc/sudoers.d/ -p wa -k scope"
        "-w /var/log/auth.log -p wa -k logins"
        "-w /var/log/faillog -p wa -k logins"
        "-w /var/log/lastlog -p wa -k logins"
        "-w /var/log/btmp -p wa -k logins"
        "-w /var/log/wtmp -p wa -k logins"
    )

    for rule in "${expected_rules[@]}"; do
        rule_path="$(awk '{print $2}' <<< "$rule")"

        if [[ ! -e "$rule_path" ]]; then
            audit_skip "6.2-RULES" "Audit watch path does not exist: $rule_path"
            continue
        fi

        if grep -RFx --include='*.rules' -- "$rule" "$AUDIT_RULES_DIR" >/dev/null 2>&1; then
            audit_pass \
                "6.2-RULES" \
                "Audit rule" \
                "$rule"
        else
            audit_fail \
                "6.2-RULES" \
                "Audit rule" \
                "Missing: $rule"

            failures=$((failures + 1))
        fi

    done

    return "$failures"
}


remediate_cis_audit_rules() {
    if [[ ! -d "$AUDIT_RULES_DIR" ]]; then
        mkdir -p "$AUDIT_RULES_DIR" || {
            log_error "Could not create $AUDIT_RULES_DIR"
            return 1
        }
    fi

    if [[ -f "$AUDIT_CIS_RULES" ]]; then
        backup_file "$AUDIT_CIS_RULES"
    fi

    cat > "$AUDIT_CIS_RULES" <<'EOF'
# ============================================================
# CIS Ubuntu 24.04 LTS Level 1
# Core audit rules
# ============================================================

# Identity files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Sudo configuration
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Authentication logs
-w /var/log/auth.log -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/log/wtmp -p wa -k logins

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Cron configuration
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.yearly/ -p wa -k cron

EOF

    chown root:root "$AUDIT_CIS_RULES"
    chmod 640 "$AUDIT_CIS_RULES"

    if [[ ! -e /var/log/faillog ]]; then
        sed -i '\|^-w /var/log/faillog -p wa -k logins$|d' "$AUDIT_CIS_RULES"
    fi

    audit_pass \
        "6.2-RULES" \
        "CIS audit rules" \
        "Core audit rules installed"

    return 0
}


load_audit_rules() {
    if ! command_exists augenrules; then
        log_warning "augenrules command not found"
        return 1
    fi

    if augenrules --load >/dev/null 2>"$LOG_DIR/augenrules.log"; then
        log_success "Audit rules loaded"
        return 0
    fi

    log_warning \
        "augenrules could not load all rules; check $LOG_DIR/augenrules.log"

    return 1
}


# ------------------------------------------------------------
# Auditd configuration
# ------------------------------------------------------------

audit_auditd_config() {
    if [[ ! -f "$AUDIT_CONFIG" ]]; then
        audit_fail \
            "6.2-AUDITD-CONFIG" \
            "auditd configuration" \
            "$AUDIT_CONFIG does not exist"

        return 1
    fi

    local failures=0

    # Keep audit logs on disk.
    if grep -Eq \
        '^[[:space:]]*max_log_file_action[[:space:]]*=[[:space:]]*keep_logs' \
        "$AUDIT_CONFIG"; then

        audit_pass \
            "6.2-AUDITD-CONFIG" \
            "audit log retention" \
            "max_log_file_action=keep_logs"
    else
        audit_fail \
            "6.2-AUDITD-CONFIG" \
            "audit log retention" \
            "max_log_file_action=keep_logs is not configured"
        failures=$((failures + 1))
    fi

    if grep -Eq \
        '^[[:space:]]*space_left_action[[:space:]]*=[[:space:]]*(email|exec|single|halt)' \
        "$AUDIT_CONFIG"; then

        audit_pass \
            "6.2-AUDITD-CONFIG" \
            "audit disk space action" \
            "space_left_action is configured"
    else
        audit_fail \
            "6.2-AUDITD-CONFIG" \
            "audit disk space action" \
            "space_left_action is not configured"
        failures=$((failures + 1))
    fi

    if grep -Eq \
        '^[[:space:]]*admin_space_left_action[[:space:]]*=[[:space:]]*(single|halt|suspend|exec)' \
        "$AUDIT_CONFIG"; then

        audit_pass \
            "6.2-AUDITD-CONFIG" \
            "audit admin disk space action" \
            "admin_space_left_action is configured"
    else
        audit_fail \
            "6.2-AUDITD-CONFIG" \
            "audit admin disk space action" \
            "admin_space_left_action is not configured"
        failures=$((failures + 1))
    fi

    return "$failures"
}


remediate_auditd_config() {
    if [[ ! -f "$AUDIT_CONFIG" ]]; then
        log_error "$AUDIT_CONFIG does not exist"
        return 1
    fi

    backup_file "$AUDIT_CONFIG"

    if grep -Eq \
        '^[[:space:]]*max_log_file_action[[:space:]]*=' \
        "$AUDIT_CONFIG"; then

        sed -i -E \
            's/^[[:space:]]*max_log_file_action[[:space:]]*=.*/max_log_file_action = keep_logs/' \
            "$AUDIT_CONFIG"
    else
        printf '%s\n' \
            'max_log_file_action = keep_logs' >> "$AUDIT_CONFIG"
    fi

    if grep -Eq \
        '^[[:space:]]*space_left_action[[:space:]]*=' \
        "$AUDIT_CONFIG"; then

        sed -i -E \
            's/^[[:space:]]*space_left_action[[:space:]]*=.*/space_left_action = email/' \
            "$AUDIT_CONFIG"
    else
        printf '%s\n' \
            'space_left_action = email' >> "$AUDIT_CONFIG"
    fi

    if grep -Eq \
        '^[[:space:]]*admin_space_left_action[[:space:]]*=' \
        "$AUDIT_CONFIG"; then

        sed -i -E \
            's/^[[:space:]]*admin_space_left_action[[:space:]]*=.*/admin_space_left_action = halt/' \
            "$AUDIT_CONFIG"
    else
        printf '%s\n' \
            'admin_space_left_action = halt' >> "$AUDIT_CONFIG"
    fi

    chown root:root "$AUDIT_CONFIG"
    chmod 640 "$AUDIT_CONFIG"

    audit_pass \
        "6.2-AUDITD-CONFIG" \
        "auditd configuration" \
        "Audit log retention and disk-space actions configured"

    return 0
}


# ------------------------------------------------------------
# Audit service and rules remediation
# ------------------------------------------------------------

remediate_audit_subsystem() {
    local failures=0

    remediate_auditd_service || failures=$((failures + 1))
    remediate_cis_audit_rules || failures=$((failures + 1))
    remediate_auditd_config || failures=$((failures + 1))

    if command_exists augenrules; then
        load_audit_rules || failures=$((failures + 1))
    fi

    return "$failures"
}


# ------------------------------------------------------------
# Log directory permissions
# ------------------------------------------------------------

audit_log_directories() {
    local failures=0
    local directory

    local directories=(
        /var/log
        /var/log/audit
    )

    for directory in "${directories[@]}"; do

        [[ -d "$directory" ]] || continue

        local owner mode

        owner="$(stat -c '%U' "$directory" 2>/dev/null || true)"
        mode="$(stat -c '%a' "$directory" 2>/dev/null || true)"

        if [[ "$owner" != "root" ]]; then
            audit_fail \
                "6.1.3.1" \
                "Log directory ownership" \
                "$directory is owned by $owner"

            failures=$((failures + 1))
        fi

          if [[ "$mode" =~ ^[0-7]+$ ]] &&
              (( 8#$mode & 00022 )); then

            audit_fail \
                "6.1.3.1" \
                "Log directory permissions" \
                "$directory is world writable"

            failures=$((failures + 1))
        fi

    done

    if [[ "$failures" -eq 0 ]]; then
        audit_pass \
            "6.1.3.1" \
            "Log directories" \
            "Log directories passed ownership and world-write checks"

        return 0
    fi

    return 1
}


remediate_log_directories() {
    local directory

    for directory in \
        /var/log \
        /var/log/audit; do

        [[ -d "$directory" ]] || continue

        chown root:root "$directory" 2>/dev/null || {
            log_warning "Could not set root ownership on $directory"
        }

        chmod go-w "$directory" 2>/dev/null || {
            log_warning "Could not remove group/other write permission from $directory"
        }

    done

    audit_log_directories
}


# ------------------------------------------------------------
# Section 05 audit
# ------------------------------------------------------------

section_05_audit() {
    start_section "05 - Logging and Audit Audit"

    local failures=0

    # rsyslog
    if [[ "${INSTALL_RSYSLOG:-yes}" == "yes" && "${ENABLE_RSYSLOG:-yes}" == "yes" ]]; then
        audit_rsyslog_service || failures=$((failures + 1))
        audit_rsyslog_facilities || failures=$((failures + 1))
    else
        audit_skip "6.1.2.4" "rsyslog controls disabled in the embedded configuration"
    fi
    audit_remote_rsyslog || failures=$((failures + 1))

    # Log files
    audit_logfile_permissions || failures=$((failures + 1))
    audit_log_directories || failures=$((failures + 1))

    # auditd
    if [[ "${INSTALL_AUDITD:-yes}" == "yes" && "${ENABLE_AUDITD:-yes}" == "yes" ]]; then
        audit_auditd_service || failures=$((failures + 1))
        audit_audit_rules_directory || failures=$((failures + 1))
        audit_cis_audit_rules || failures=$((failures + 1))
        audit_auditd_config || failures=$((failures + 1))
    else
        audit_skip "6.2-AUDITD" "auditd controls disabled in the embedded configuration"
    fi

    end_section "05 - Logging and Audit Audit"

    return "$failures"
}


# ------------------------------------------------------------
# Section 05 remediation
# ------------------------------------------------------------

section_05_remediate() {
    start_section "05 - Logging and Audit Remediation"

    local failures=0

    # --------------------------------------------------------
    # rsyslog
    # --------------------------------------------------------

    if [[ "${INSTALL_RSYSLOG:-yes}" == "yes" && "${ENABLE_RSYSLOG:-yes}" == "yes" ]]; then
        remediate_rsyslog_service || failures=$((failures + 1))
        remediate_rsyslog_facilities || failures=$((failures + 1))
    fi

    # Remote logging is intentionally configurable.
    remediate_remote_rsyslog || failures=$((failures + 1))

    # --------------------------------------------------------
    # Log permissions
    # --------------------------------------------------------

    remediate_logfile_permissions || failures=$((failures + 1))
    remediate_log_directories || failures=$((failures + 1))

    # --------------------------------------------------------
    # auditd
    # --------------------------------------------------------

    if [[ "${INSTALL_AUDITD:-yes}" == "yes" && "${ENABLE_AUDITD:-yes}" == "yes" ]]; then
        remediate_audit_subsystem || failures=$((failures + 1))
    fi

    end_section "05 - Logging and Audit Remediation"

    return "$failures"
}


# ------------------------------------------------------------
# Section 05 dispatcher
# ------------------------------------------------------------

section_05_logging_audit() {
    local mode="${1:-audit}"

    case "$mode" in
        audit)
            section_05_audit
            ;;

        remediate|fix|apply)
            section_05_remediate
            ;;

        *)
            log_error "Unknown Section 05 mode: $mode"
            log_error "Valid modes: audit | remediate"
            return 1
            ;;
    esac
}


# ------------------------------------------------------------
# Section 05 status
# ------------------------------------------------------------

section_05_status() {
    echo
    echo "============================================================"
    echo " Section 05 - Logging and Audit Status"
    echo "============================================================"

    echo
    echo "[rsyslog]"
    if command_exists rsyslogd; then
        echo "Service:"
        systemctl is-active rsyslog 2>/dev/null || true

        echo "Enabled:"
        systemctl is-enabled rsyslog 2>/dev/null || true

        echo
        echo "Configuration validation:"
        rsyslogd -N1 2>&1 || true
    else
        echo "rsyslog: NOT INSTALLED"
    fi

    echo
    echo "[Remote rsyslog]"
    echo "Enabled: ${REMOTE_SYSLOG_ENABLED:-no}"
    echo "Host: ${REMOTE_SYSLOG_HOST:-not configured}"
    echo "Port: ${REMOTE_SYSLOG_PORT:-514}"
    echo "Protocol: ${REMOTE_SYSLOG_PROTOCOL:-tcp}"

    echo
    echo "[auditd]"
    if command_exists auditd; then
        echo "Service:"
        systemctl is-active auditd 2>/dev/null || true

        echo "Enabled:"
        systemctl is-enabled auditd 2>/dev/null || true
    else
        echo "auditd: NOT INSTALLED"
    fi

    echo
    echo "[CIS audit rules]"
    if [[ -f "$AUDIT_CIS_RULES" ]]; then
        cat "$AUDIT_CIS_RULES"
    else
        echo "$AUDIT_CIS_RULES: NOT FOUND"
    fi

    echo
    echo "[Loaded audit rules]"
    if command_exists auditctl; then
        auditctl -l 2>/dev/null || true
    else
        echo "auditctl: NOT AVAILABLE"
    fi

    echo
    echo "[Log permissions]"
    ls -ld \
        /var/log \
        /var/log/audit \
        /var/log/auth.log \
        /var/log/syslog \
        /var/log/kern.log \
        /var/log/cron.log \
        /var/log/mail.log \
        /var/log/user.log \
        2>/dev/null || true

    echo
    echo "============================================================"
}


# ------------------------------------------------------------
# Direct execution support
# ------------------------------------------------------------

#!/usr/bin/env bash
#
# CIS Ubuntu 24.04 LTS Level 1
# Section 06 - File Permissions
#
# Covers:
# 7.1.11 - Ensure no world-writable files and directories exist
#
# Additional permission hardening:
# - /etc/passwd
# - /etc/group
# - /etc/shadow
# - /etc/gshadow
# - /etc/passwd-
# - /etc/group-
# - /etc/shadow-
# - /etc/gshadow-
# - /etc/sudoers
# - /etc/sudoers.d
# - SSH configuration
# - cron configuration
#
# IMPORTANT:
# This script does NOT blindly chmod every file on the system.
# System files can have application-specific permissions.
# World-writable files/directories are identified and remediated
# carefully.
#

set -o pipefail

###############################################################################
# Configuration
###############################################################################

PERMISSION_REPORT_DIR="/var/log/cis-hardening"
PERMISSION_REPORT="${PERMISSION_REPORT_DIR}/world-writable-files.txt"

###############################################################################
# Helper functions
###############################################################################

permission_file_exists() {
    local file="$1"

    [[ -e "$file" ]]
}

get_file_mode() {
    local file="$1"

    stat -c '%a' "$file" 2>/dev/null
}

get_file_owner() {
    local file="$1"

    stat -c '%U' "$file" 2>/dev/null
}

get_file_group() {
    local file="$1"

    stat -c '%G' "$file" 2>/dev/null
}

###############################################################################
# Sensitive system file permissions
###############################################################################

audit_sensitive_file_permissions() {
    start_section "Sensitive system file permissions"

    local failed=0

    #
    # /etc/passwd
    #
    if [[ -f /etc/passwd ]]; then
        local mode owner group

        mode="$(get_file_mode /etc/passwd)"
        owner="$(get_file_owner /etc/passwd)"
        group="$(get_file_group /etc/passwd)"

        if [[ "$owner" == "root" &&
              "$group" == "root" &&
              "$mode" == "644" ]]; then
            audit_pass "/etc/passwd is root:root 0644."
        else
            audit_fail "/etc/passwd is ${owner}:${group} ${mode}; expected root:root 0644."
            failed=1
        fi
    else
        audit_fail "/etc/passwd does not exist."
        failed=1
    fi

    #
    # /etc/group
    #
    if [[ -f /etc/group ]]; then
        local mode owner group

        mode="$(get_file_mode /etc/group)"
        owner="$(get_file_owner /etc/group)"
        group="$(get_file_group /etc/group)"

        if [[ "$owner" == "root" &&
              "$group" == "root" &&
              "$mode" == "644" ]]; then
            audit_pass "/etc/group is root:root 0644."
        else
            audit_fail "/etc/group is ${owner}:${group} ${mode}; expected root:root 0644."
            failed=1
        fi
    else
        audit_fail "/etc/group does not exist."
        failed=1
    fi

    #
    # /etc/shadow
    #
    if [[ -f /etc/shadow ]]; then
        local mode owner group

        mode="$(get_file_mode /etc/shadow)"
        owner="$(get_file_owner /etc/shadow)"
        group="$(get_file_group /etc/shadow)"

        if [[ "$owner" == "root" &&
              "$group" == "shadow" &&
              "$mode" == "640" ]]; then
            audit_pass "/etc/shadow is root:shadow 0640."
        else
            audit_fail "/etc/shadow is ${owner}:${group} ${mode}; expected root:shadow 0640."
            failed=1
        fi
    else
        audit_fail "/etc/shadow does not exist."
        failed=1
    fi

    #
    # /etc/gshadow
    #
    if [[ -f /etc/gshadow ]]; then
        local mode owner group

        mode="$(get_file_mode /etc/gshadow)"
        owner="$(get_file_owner /etc/gshadow)"
        group="$(get_file_group /etc/gshadow)"

        if [[ "$owner" == "root" &&
              "$group" == "shadow" &&
              "$mode" == "640" ]]; then
            audit_pass "/etc/gshadow is root:shadow 0640."
        else
            audit_fail "/etc/gshadow is ${owner}:${group} ${mode}; expected root:shadow 0640."
            failed=1
        fi
    else
        audit_fail "/etc/gshadow does not exist."
        failed=1
    fi

    #
    # Backup account databases.
    #
    for file in \
        /etc/passwd- \
        /etc/group- \
        /etc/shadow- \
        /etc/gshadow-
    do
        if [[ ! -e "$file" ]]; then
            continue
        fi

        local mode owner group
        mode="$(get_file_mode "$file")"
        owner="$(get_file_owner "$file")"
        group="$(get_file_group "$file")"

        case "$file" in
            /etc/passwd-|/etc/group-)
                if [[ "$owner" == "root" &&
                      "$group" == "root" &&
                      "$mode" == "644" ]]; then
                    audit_pass "$file is root:root 0644."
                else
                    audit_fail "$file is ${owner}:${group} ${mode}; expected root:root 0644."
                    failed=1
                fi
                ;;

            /etc/shadow-|/etc/gshadow-)
                if [[ "$owner" == "root" &&
                      "$group" == "shadow" &&
                      "$mode" == "640" ]]; then
                    audit_pass "$file is root:shadow 0640."
                else
                    audit_fail "$file is ${owner}:${group} ${mode}; expected root:shadow 0640."
                    failed=1
                fi
                ;;
        esac
    done

    return "$failed"
}

remediate_sensitive_file_permissions() {
    start_section "Sensitive system file permission remediation"

    #
    # Account database files.
    #
    if [[ -f /etc/passwd ]]; then
        chown root:root /etc/passwd
        chmod 644 /etc/passwd
    fi

    if [[ -f /etc/group ]]; then
        chown root:root /etc/group
        chmod 644 /etc/group
    fi

    if [[ -f /etc/shadow ]]; then
        chown root:shadow /etc/shadow
        chmod 640 /etc/shadow
    fi

    if [[ -f /etc/gshadow ]]; then
        chown root:shadow /etc/gshadow
        chmod 640 /etc/gshadow
    fi

    #
    # Backup account database files.
    #
    if [[ -f /etc/passwd- ]]; then
        chown root:root /etc/passwd-
        chmod 644 /etc/passwd-
    fi

    if [[ -f /etc/group- ]]; then
        chown root:root /etc/group-
        chmod 644 /etc/group-
    fi

    if [[ -f /etc/shadow- ]]; then
        chown root:shadow /etc/shadow-
        chmod 640 /etc/shadow-
    fi

    if [[ -f /etc/gshadow- ]]; then
        chown root:shadow /etc/gshadow-
        chmod 640 /etc/gshadow-
    fi

    audit_pass "Sensitive account database permissions remediated."
}

###############################################################################
# Sudo permissions
###############################################################################

audit_sudo_permissions() {
    start_section "Sudo configuration permissions"

    local failed=0

    if [[ -f /etc/sudoers ]]; then
        local owner group mode

        owner="$(get_file_owner /etc/sudoers)"
        group="$(get_file_group /etc/sudoers)"
        mode="$(get_file_mode /etc/sudoers)"

        if [[ "$owner" == "root" &&
              "$group" == "root" &&
              "$mode" == "440" ]]; then
            audit_pass "/etc/sudoers is root:root 0440."
        else
            audit_fail "/etc/sudoers is ${owner}:${group} ${mode}; expected root:root 0440."
            failed=1
        fi
    else
        audit_fail "/etc/sudoers does not exist."
        failed=1
    fi

    if [[ -d /etc/sudoers.d ]]; then
        local dir_mode dir_owner dir_group

        dir_mode="$(get_file_mode /etc/sudoers.d)"
        dir_owner="$(get_file_owner /etc/sudoers.d)"
        dir_group="$(get_file_group /etc/sudoers.d)"

        if [[ "$dir_owner" == "root" &&
              "$dir_group" == "root" &&
              "$dir_mode" == "750" ]]; then
            audit_pass "/etc/sudoers.d is root:root 0750."
        else
            audit_fail "/etc/sudoers.d is ${dir_owner}:${dir_group} ${dir_mode}; expected root:root 0750."
            failed=1
        fi

        #
        # Only inspect regular files.
        #
        while IFS= read -r -d '' file; do
            local mode owner group

            mode="$(get_file_mode "$file")"
            owner="$(get_file_owner "$file")"
            group="$(get_file_group "$file")"

            #
            if [[ "$owner" == "root" &&
                  "$group" == "root" &&
                  "$mode" == "440" ]]; then
                audit_pass "$file is root:root 0440."
            else
                audit_fail "$file is ${owner}:${group} ${mode}; expected root:root 0440."
                failed=1
            fi
        done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
    else
        audit_warning "/etc/sudoers.d does not exist."
    fi

    return "$failed"
}

remediate_sudo_permissions() {
    start_section "Sudo configuration permission remediation"

    if [[ -f /etc/sudoers ]]; then
        chown root:root /etc/sudoers
        chmod 440 /etc/sudoers
    fi

    if [[ -d /etc/sudoers.d ]]; then
        chown root:root /etc/sudoers.d
        chmod 750 /etc/sudoers.d

        while IFS= read -r -d '' file; do
            chown root:root "$file"

            #
            chmod 440 "$file"
        done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
    fi

    #
    # Validate sudo configuration after permission changes.
    #
    if command_exists visudo; then
        if visudo -cf /etc/sudoers >/dev/null 2>&1; then
            audit_pass "Sudo configuration syntax is valid."
        else
            audit_fail "Sudo configuration syntax validation failed."
            return 1
        fi
    fi

    audit_pass "Sudo configuration permissions remediated."
}

###############################################################################
# World-writable files
###############################################################################

find_world_writable_files() {
    #
    find / \
        \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
        -type f -perm -0002 -print 2>/dev/null
}

find_world_writable_directories() {
    find / \
        \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
        -type d -perm -0002 ! -perm -1000 -print 2>/dev/null
}

audit_world_writable_files() {
    start_section "7.1.11 World-writable files and directories"

    mkdir -p "$PERMISSION_REPORT_DIR"
    : > "$PERMISSION_REPORT"

    local file_count=0
    local dir_count=0

    {
        echo "CIS Ubuntu 24.04 - World Writable File Report"
        echo "Generated: $(date)"
        echo
        echo "[WORLD-WRITABLE FILES]"
    } >> "$PERMISSION_REPORT"

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue

        printf '%s\n' "$file" >> "$PERMISSION_REPORT"
        file_count=$((file_count + 1))
    done < <(find_world_writable_files)

    {
        echo
        echo "[WORLD-WRITABLE DIRECTORIES]"
    } >> "$PERMISSION_REPORT"

    while IFS= read -r directory; do
        [[ -z "$directory" ]] && continue

        printf '%s\n' "$directory" >> "$PERMISSION_REPORT"
        dir_count=$((dir_count + 1))
    done < <(find_world_writable_directories)

    if [[ "$file_count" -eq 0 && "$dir_count" -eq 0 ]]; then
        audit_pass "No world-writable files or directories found on the persistent root filesystem."
        return 0
    else
        audit_fail "Found ${file_count} world-writable files and ${dir_count} world-writable directories."
        log_warning "Detailed report: $PERMISSION_REPORT"
        return 1
    fi
}

###############################################################################
# World-writable remediation
###############################################################################

remediate_world_writable_files() {
    start_section "7.1.11 World-writable file remediation"

    local changed_files=0
    local changed_dirs=0
    local remediation_failed=0

    #
    # Remove only the 'other write' bit from files.
    #
    # This is safer than replacing the complete permission mode because
    # application-specific read/execute permissions are preserved.
    #
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue

        #
        # Never modify special account/security files through this generic
        # mechanism. They are handled separately.
        #
        case "$file" in
            /etc/shadow|/etc/gshadow|/etc/shadow-|/etc/gshadow-)
                log_warning "Skipping sensitive file from generic world-writable remediation: $file"
                remediation_failed=1
                continue
                ;;
        esac

        log_info "Removing world-write permission from file: $file"

        if chmod o-w "$file"; then
            changed_files=$((changed_files + 1))
        else
            log_warning "Unable to change permissions on: $file"
            remediation_failed=1
        fi
    done < <(find_world_writable_files)

    #
    # Directories are more sensitive.
    #
    # We remove only the other-write bit, preserving sticky-bit semantics.
    #
    while IFS= read -r directory; do
        [[ -z "$directory" ]] && continue

        case "$directory" in
            /tmp|/var/tmp|/dev/shm)
                #
                # These locations commonly require world-write permission.
                # Sticky-bit protection is the relevant control.
                #
                if [[ "$(stat -c '%a' "$directory" 2>/dev/null)" == "1777" ]]; then
                    audit_pass "$directory is world-writable with sticky bit (1777)."
                else
                    log_warning "$directory is world-writable but does not have expected sticky-bit protection."
                    remediation_failed=1
                fi
                continue
                ;;
        esac

        log_info "Removing world-write permission from directory: $directory"

        if chmod o-w "$directory"; then
            changed_dirs=$((changed_dirs + 1))
        else
            log_warning "Unable to change permissions on directory: $directory"
            remediation_failed=1
        fi
    done < <(find_world_writable_directories)

    audit_pass "World-writable remediation completed: ${changed_files} files and ${changed_dirs} directories changed."
    return "$remediation_failed"
}

###############################################################################
# Sticky bit on temporary directories
###############################################################################

audit_temporary_directory_permissions() {
    start_section "Temporary directory permissions"

    local failed=0

    for directory in /tmp /var/tmp /dev/shm; do

        if [[ ! -d "$directory" ]]; then
            audit_warning "$directory does not exist."
            continue
        fi

        local mode

        mode="$(get_file_mode "$directory")"

        if [[ "$mode" == "1777" ]]; then
            audit_pass "$directory has mode 1777."
        else
            audit_fail "$directory has mode $mode; expected 1777 for a standard shared temporary directory."
            failed=1
        fi
    done

    return "$failed"
}

remediate_temporary_directory_permissions() {
    start_section "Temporary directory permission remediation"

    local failed=0

    for directory in /tmp /var/tmp /dev/shm; do

        if [[ ! -d "$directory" ]]; then
            continue
        fi

        #
        # 1777 = rwxrwxrwt
        #
        if chmod 1777 "$directory"; then
            audit_pass "$directory permissions set to 1777."
        else
            audit_fail "Unable to set $directory permissions."
            failed=1
        fi
    done

    return "$failed"
}

###############################################################################
# Cron permission checks
###############################################################################

audit_cron_permissions() {
    start_section "Cron configuration permissions"

    local failed=0

    #
    # Cron directories.
    #
    local cron_dirs=(
        /etc/crontab
        /etc/cron.d
        /etc/cron.hourly
        /etc/cron.daily
        /etc/cron.weekly
        /etc/cron.monthly
        /etc/cron.yearly
    )

    for path in "${cron_dirs[@]}"; do

        if [[ ! -e "$path" ]]; then
            audit_warning "$path does not exist."
            continue
        fi

        local owner group mode

        owner="$(get_file_owner "$path")"
        group="$(get_file_group "$path")"
        mode="$(get_file_mode "$path")"

        #
        # Cron objects must not be writable by group/other.
        #
          if [[ "$owner" == "root" &&
              "$group" == "root" &&
              "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 0022) == 0 )); then
            audit_pass "$path is owned by root:root with restricted write permissions."
        else
            #
            # For /etc/crontab and cron directories, root ownership is
            # important and group/other write permissions are dangerous.
            #
            if [[ "$owner" != "root" || "$group" != "root" ]]; then
                audit_fail "$path is ${owner}:${group}; expected root:root."
                failed=1
            fi

            if [[ "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 0022) != 0 )); then
                audit_fail "$path is writable by group or others."
                failed=1
            fi
        fi
    done

    return "$failed"
}

remediate_cron_permissions() {
    start_section "Cron configuration permission remediation"

    #
    # /etc/crontab
    #
    if [[ -f /etc/crontab ]]; then
        chown root:root /etc/crontab
        chmod 600 /etc/crontab
    fi

    #
    # Cron directories.
    #
    for directory in \
        /etc/cron.d \
        /etc/cron.hourly \
        /etc/cron.daily \
        /etc/cron.weekly \
        /etc/cron.monthly \
        /etc/cron.yearly
    do
        if [[ -d "$directory" ]]; then
            chown root:root "$directory"

            #
            # 700 prevents non-root users from modifying cron jobs.
            #
            chmod 700 "$directory"
        fi
    done

    #
    # Cron files inside those directories.
    #
    for directory in \
        /etc/cron.d \
        /etc/cron.hourly \
        /etc/cron.daily \
        /etc/cron.weekly \
        /etc/cron.monthly \
        /etc/cron.yearly
    do
        [[ -d "$directory" ]] || continue

        while IFS= read -r -d '' file; do
            chown root:root "$file"
            chmod go-w "$file"
        done < <(find "$directory" -type f -print0 2>/dev/null)
    done

    audit_pass "Cron configuration permissions remediated."
}

###############################################################################
# SSH directory permissions
###############################################################################

audit_ssh_directory_permissions() {
    start_section "SSH directory permissions"

    local failed=0

    if [[ -d /etc/ssh ]]; then
        local owner group mode

        owner="$(get_file_owner /etc/ssh)"
        group="$(get_file_group /etc/ssh)"
        mode="$(get_file_mode /etc/ssh)"

          if [[ "$owner" == "root" &&
              "$group" == "root" &&
              "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 0022) == 0 )); then
            audit_pass "/etc/ssh has root ownership and restricted write permissions."
        else
            audit_fail "/etc/ssh permissions are ${owner}:${group} ${mode}."
            failed=1
        fi
    else
        audit_fail "/etc/ssh does not exist."
        failed=1
    fi

    if [[ -d /etc/ssh/sshd_config.d ]]; then
        while IFS= read -r -d '' file; do
            local owner group mode

            owner="$(get_file_owner "$file")"
            group="$(get_file_group "$file")"
            mode="$(get_file_mode "$file")"

            if [[ "$owner" == "root" &&
                "$group" == "root" &&
                "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 0022) == 0 )); then
                audit_pass "$file has restricted permissions."
            else
                audit_fail "$file has ${owner}:${group} ${mode}."
                failed=1
            fi
        done < <(find /etc/ssh/sshd_config.d -type f -print0 2>/dev/null)
    fi

    return "$failed"
}

remediate_ssh_directory_permissions() {
    start_section "SSH directory permission remediation"

    if [[ -d /etc/ssh ]]; then
        chown root:root /etc/ssh
        chmod go-w /etc/ssh
    fi

    if [[ -d /etc/ssh/sshd_config.d ]]; then
        chown root:root /etc/ssh/sshd_config.d
        chmod go-w /etc/ssh/sshd_config.d

        while IFS= read -r -d '' file; do
            chown root:root "$file"
            chmod go-w "$file"
        done < <(find /etc/ssh/sshd_config.d -type f -print0 2>/dev/null)
    fi

    audit_pass "SSH directory permissions remediated."
}

###############################################################################
# Main audit
###############################################################################

audit_section_06() {
    start_section "SECTION 06 - PERMISSIONS AUDIT"

    local failures=0

    audit_sensitive_file_permissions || failures=$((failures + 1))
    audit_sudo_permissions || failures=$((failures + 1))
    audit_world_writable_files || failures=$((failures + 1))
    audit_temporary_directory_permissions || failures=$((failures + 1))
    audit_cron_permissions || failures=$((failures + 1))
    audit_ssh_directory_permissions || failures=$((failures + 1))

    end_section
    return "$failures"
}

###############################################################################
# Main remediation
###############################################################################

remediate_section_06() {
    start_section "SECTION 06 - PERMISSIONS REMEDIATION"

    local failures=0

    #
    # Sensitive system files.
    #
    remediate_sensitive_file_permissions || failures=$((failures + 1))

    #
    # Sudo configuration.
    #
    remediate_sudo_permissions || failures=$((failures + 1))

    #
    # Temporary directories.
    #
    remediate_temporary_directory_permissions || failures=$((failures + 1))

    #
    # Cron configuration.
    #
    remediate_cron_permissions || failures=$((failures + 1))

    #
    # SSH configuration directories.
    #
    remediate_ssh_directory_permissions || failures=$((failures + 1))

    #
    # World-writable objects.
    #
    remediate_world_writable_files || failures=$((failures + 1))

    #
    # Run final audit after remediation.
    #
    audit_world_writable_files || failures=$((failures + 1))

    end_section
    return "$failures"
}

###############################################################################
# Direct execution support
###############################################################################


###############################################################################
# Main
###############################################################################

main() {

    local action="${1:-}"
    ACTION="$action"

    case "$action" in
        audit|remediate|verify)
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
    # Initialize shared helper state.
    #
    load_common_library

    # Syntax-check the unified script and configuration.
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

        verify)
            run_audit
            return $?
            ;;

    esac
}

main "$@"
exit $?