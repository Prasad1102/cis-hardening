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
            "ATM module hardening disabled in cis.conf"
    fi


    if [ "${DISABLE_CAN_MODULE:-yes}" = "yes" ]; then

        audit_single_kernel_module \
            "3.2.2" \
            "can" \
            "CAN kernel module" || failed=1

    else

        audit_skip \
            "3.2.2" \
            "CAN module hardening disabled in cis.conf"
    fi


    if [ "${DISABLE_SCTP_MODULE:-yes}" = "yes" ]; then

        audit_single_kernel_module \
            "3.2.5" \
            "sctp" \
            "SCTP kernel module" || failed=1

    else

        audit_skip \
            "3.2.5" \
            "SCTP module hardening disabled in cis.conf"
    fi


    if [ "${DISABLE_TIPC_MODULE:-yes}" = "yes" ]; then

        audit_single_kernel_module \
            "3.2.6" \
            "tipc" \
            "TIPC kernel module" || failed=1

    else

        audit_skip \
            "3.2.6" \
            "TIPC module hardening disabled in cis.conf"
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
            "IPv6 network hardening disabled in cis.conf"

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
            "IPv6 hardening disabled in cis.conf."

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
