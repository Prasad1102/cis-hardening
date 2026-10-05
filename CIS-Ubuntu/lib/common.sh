#!/bin/bash

# ============================================================
# Common Functions
# CIS Ubuntu 24.04 LTS v2.0.0
# ============================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONFIG_FILE="$SCRIPT_DIR/cis.conf"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "[ERROR] Configuration file not found: $CONFIG_FILE"
    exit 1
fi

source "$CONFIG_FILE"


# ------------------------------------------------------------
# GLOBAL VARIABLES
# ------------------------------------------------------------

TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"

BACKUP_DIR="/root/cis-backup/$TIMESTAMP"
LOG_DIR="/root/cis-logs/$TIMESTAMP"

CURRENT_SECTION=""

mkdir -p "$BACKUP_DIR"
mkdir -p "$LOG_DIR"


# ------------------------------------------------------------
# COLORS
# ------------------------------------------------------------

RED=""
GREEN=""
YELLOW=""
BLUE=""
RESET=""


# ------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------

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

    log_info "Installing package: $package"

    DEBIAN_FRONTEND=noninteractive \
        apt-get install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "$package"

    if [ $? -eq 0 ]; then
        log_success "Installed: $package"
    else
        log_error "Failed to install: $package"
        return 1
    fi
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

run_remediation() {

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

    local destination="$BACKUP_DIR$(dirname "$file")"

    mkdir -p "$destination"

    cp -a "$file" "$destination/"

    log_info "Backed up: $file"
}


# ------------------------------------------------------------
# VERIFY FILE PERMISSIONS
# ------------------------------------------------------------

verify_file_permissions() {

    local file="$1"
    local expected_owner="$2"
    local expected_mode="$3"

    if [ ! -e "$file" ]; then
        log_error "$file does not exist"
        return 1
    fi

    local owner
    local mode

    owner="$(stat -c '%U:%G' "$file")"
    mode="$(stat -c '%a' "$file")"

    if [ "$owner" = "$expected_owner" ] &&
       [ "$mode" = "$expected_mode" ]
    then
        log_success "$file ownership=$owner mode=$mode"
        return 0
    fi

    log_error "$file ownership=$owner mode=$mode expected=$expected_owner/$expected_mode"

    return 1
}


# ------------------------------------------------------------
# SYSCTL
# ------------------------------------------------------------

set_sysctl_value() {

    local key="$1"
    local value="$2"

    if [ "$MODE" = "audit" ]; then

        local current

        current="$(sysctl -n "$key" 2>/dev/null || echo "NOT_FOUND")"

        if [ "$current" = "$value" ]; then
            log_success "$key = $value"
        else
            log_error "$key = $current ; expected $value"
        fi

        return
    fi

    sysctl -w "$key=$value" >> "$LOG_DIR/sysctl.log" 2>&1
}


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

    return
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

 local actual="${1:-}"
 local expected="${2:-}"

 [[ "$actual" == "$expected" ]]
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
 local mode="${2:-}"

 if [[ -z "$file" || -z "$mode" ]]; then
 return 1
 fi

 chmod "$mode" "$file"
}


verify_file_permissions() {

 local file="${1:-}"
 local expected_mode="${2:-}"

 if [[ ! -e "$file" ]]; then
 return 1
 fi

 local actual_mode
 actual_mode="$(stat -c '%a' "$file" 2>/dev/null)" || return 1

 [[ "$actual_mode" == "$expected_mode" ]]
}


set_sysctl_value() {

 local key="${1:-}"
 local value="${2:-}"

 if [[ -z "$key" || -z "$value" ]]; then
 return 1
 fi

 sysctl -w "${key}=${value}" >/dev/null
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

 if ! sshd -t; thens
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
