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
        audit_skip "FIREWALL-SSH" "SSH UFW rule requirement is disabled in cis.conf"
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
        if ! grep -Eq "^[[:space:]]*${port}/tcp[[:space:]]+ALLOW IN([[:space:]]|$)" <<< "$status"; then
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

    if ! command_exists sshd; then
        return 1
    fi

    sshd -T 2>/dev/null |
        awk -v search_key="$key" '
            $1 == search_key {
                print $2
                exit
            }
        '
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

    return 1
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
            "No access list configured in cis.conf; refusing to invent allowed users"

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
# Additional SSH hardening from cis.conf
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

        return 1
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

    if ! ufw --force enable >/dev/null 2>&1; then
        log_error "Failed to enable UFW"
        return 1
    fi

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

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    if [[ -f "$SCRIPT_DIR/lib/common.sh" ]]; then
        # shellcheck source=/dev/null
        source "$SCRIPT_DIR/lib/common.sh"
    else
        echo "ERROR: lib/common.sh not found"
        exit 1
    fi

    section_03_firewall_ssh "${1:-audit}"
fi