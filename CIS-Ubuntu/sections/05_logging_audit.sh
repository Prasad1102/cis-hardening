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
            "rsyslog installation or service activation is disabled in cis.conf"
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
        log_warning "rsyslog installation or service activation is disabled in cis.conf"
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
            "Remote logging is disabled in cis.conf"

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
            "Remote logging disabled in cis.conf"

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
            "auditd installation or service activation is disabled in cis.conf"
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
        log_warning "auditd installation or service activation is disabled in cis.conf"
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
        audit_skip "6.1.2.4" "rsyslog controls disabled in cis.conf"
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
        audit_skip "6.2-AUDITD" "auditd controls disabled in cis.conf"
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

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    if [[ -f "$SCRIPT_DIR/lib/common.sh" ]]; then
        # shellcheck source=/dev/null
        source "$SCRIPT_DIR/lib/common.sh"
    else
        echo "ERROR: lib/common.sh not found"
        exit 1
    fi

    section_05_logging_audit "${1:-audit}"
fi
