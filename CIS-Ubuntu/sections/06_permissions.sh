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
                continue
                ;;
        esac

        log_info "Removing world-write permission from file: $file"

        if chmod o-w "$file"; then
            changed_files=$((changed_files + 1))
        else
            log_warning "Unable to change permissions on: $file"
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
                fi
                continue
                ;;
        esac

        log_info "Removing world-write permission from directory: $directory"

        if chmod o-w "$directory"; then
            changed_dirs=$((changed_dirs + 1))
        else
            log_warning "Unable to change permissions on directory: $directory"
        fi
    done < <(find_world_writable_directories)

    audit_pass "World-writable remediation completed: ${changed_files} files and ${changed_dirs} directories changed."
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
        fi
    done
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

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    if [[ -f "$SCRIPT_DIR/lib/common.sh" ]]; then
        # shellcheck source=/dev/null
        source "$SCRIPT_DIR/lib/common.sh"
    else
        echo "ERROR: lib/common.sh not found"
        exit 1
    fi

    require_root

    case "${1:-audit}" in
        audit)
            audit_section_06
            ;;
        remediate|fix|harden)
            remediate_section_06
            ;;
        *)
            echo "Usage: $0 {audit|remediate}"
            exit 1
            ;;
    esac
fi
