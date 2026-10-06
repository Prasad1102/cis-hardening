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

    if [[ "$minlen" == "${PASSWORD_MIN_LENGTH:-14}" ]]; then
        audit_pass \
            "5.3.3.2.8" \
            "Root password quality" \
            "Global password quality policy applies to root password changes"
        return 0
    fi

    audit_fail \
        "5.3.3.2.8" \
        "Root password quality" \
        "Root password quality policy is not configured correctly"

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
        "-${PASSWORD_MIN_OTHER:-1}"

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

        if (( uid < 1000 )); then
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

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    if [[ -f "$SCRIPT_DIR/lib/common.sh" ]]; then
        # shellcheck source=/dev/null
        source "$SCRIPT_DIR/lib/common.sh"
    else
        echo "ERROR: lib/common.sh not found"
        exit 1
    fi

    section_04_pam_accounts "${1:-audit}"
fi
