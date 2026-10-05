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
REMEDIATION_LOG="$LOG_DIR/remediation.log"

CURRENT_SECTION=""
APT_UPDATED="no"

mkdir -p "$BACKUP_DIR"
mkdir -p "$LOG_DIR"
touch "$REMEDIATION_LOG"


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
