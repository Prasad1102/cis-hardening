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
# - GRUB password hash must be supplied through cis.conf.
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

    local mount_source

    mount_source="$(findmnt -n -o SOURCE /tmp 2>/dev/null)"

    if [ -z "$mount_source" ]; then

        #
        # /tmp may be part of the root filesystem.
        #
        audit_fail \
            "$control_id" \
            "/tmp is not mounted as a separate filesystem/tmpfs"

        return 1
    fi


    local filesystem_type

    filesystem_type="$(findmnt -n -o FSTYPE /tmp 2>/dev/null)"


    if [ "$filesystem_type" = "tmpfs" ]; then

        audit_pass \
            "$control_id" \
            "/tmp is mounted as tmpfs"

        return 0
    fi


    #
    # If /tmp is a separate block filesystem, determine whether
    # it is actually separate from /.
    #

    local root_source

    root_source="$(findmnt -n -o SOURCE / 2>/dev/null)"


    if [ "$mount_source" != "$root_source" ]; then

        audit_pass \
            "$control_id" \
            "/tmp is on a separate filesystem"

        return 0
    fi


    audit_fail \
        "$control_id" \
        "/tmp shares the root filesystem"

    return 1
}


remediate_tmp_filesystem() {

    log_warning \
        "Automatic /tmp partition creation is intentionally not implemented."

    log_warning \
        "Create a dedicated /tmp filesystem or tmpfs according to your server design."

    return 0
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
# The password hash must come from cis.conf.
# ============================================================

audit_grub_password() {

    local control_id="1.4.1"

    local grub_cfg="/boot/grub/grub.cfg"

    if [ ! -f "$grub_cfg" ]; then

        audit_fail \
            "$control_id" \
            "GRUB configuration file not found"

        return 1
    fi


    local superuser_present="no"
    local password_present="no"


    if grep -Eq \
        '^[[:space:]]*set[[:space:]]+superusers=' \
        "$grub_cfg"
    then

        superuser_present="yes"
    fi


    if grep -Eq \
        '^[[:space:]]*password_pbkdf2[[:space:]]+' \
        "$grub_cfg"
    then

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
            "Then place the generated hash in cis.conf."

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
            "AppArmor remediation disabled in cis.conf."

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
            "Automatic error reporting is not disabled in cis.conf"

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

    local ssh_config="${SSH_CONFIG_FILE:-/etc/ssh/sshd_config}"


    if [ ! -f "$ssh_config" ]; then

        audit_fail \
            "$control_id" \
            "sshd_config does not exist"

        return 1
    fi


    if sshd -T 2>/dev/null \
        | awk '$1 == "banner" {print $2; exit}' \
        | grep -Fxq "${ISSUE_NET_FILE:-/etc/issue.net}"
    then

        audit_pass \
            "$control_id" \
            "SSH Banner points to ${ISSUE_NET_FILE:-/etc/issue.net}"

        return 0
    fi


    audit_fail \
        "$control_id" \
        "SSH Banner is not configured to ${ISSUE_NET_FILE:-/etc/issue.net}"

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

audit_aide() {

    local control_id="AIDE"


    if ! package_installed aide; then

        audit_fail \
            "$control_id" \
            "AIDE package is not installed"

        return 1
    fi


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

        if systemctl list-unit-files \
            | grep -Eq '^aidecheck\.timer[[:space:]]'
        then

            if systemctl is-enabled aidecheck.timer >/dev/null 2>&1 &&
               systemctl is-active aidecheck.timer >/dev/null 2>&1
            then

                audit_pass \
                    "$control_id" \
                    "aidecheck.timer is enabled and active"

            else

                audit_warning \
                    "$control_id" \
                    "aidecheck.timer exists but is not both enabled and active"
            fi
        else

            audit_warning \
                "$control_id" \
                "aidecheck.timer was not found"
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

        if systemctl list-unit-files \
            | grep -Eq '^aidecheck\.timer[[:space:]]'
        then

            systemctl enable aidecheck.timer \
                >> "$REMEDIATION_LOG" 2>&1 || true

            systemctl start aidecheck.timer \
                >> "$REMEDIATION_LOG" 2>&1 || true

        else

            log_warning \
                "aidecheck.timer is not available on this installation."
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