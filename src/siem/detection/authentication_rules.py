''' 
4625 — failed logon (needed for almost half this list)
4740 — account locked out
4767 — account unlocked
4725 — account disabled
4726 — account deleted
4722 — account enabled 
4723/4724 — password change / password reset attempt

'''

'''
FAILED LOGON PATTERNS
--> Multiple failed logins, same source
--> Multiple failed logins, different source
--> Multiple failed logins, multiple accounts

'''


from datetime import timedelta
from .generic_rules import detect_count_threshold_breach, detect_distinct_count_threshold_breach, _parse_ts


# ---- Group 1: failed logon volume patterns ----

def detect_failed_logons_same_source(events):
    return detect_count_threshold_breach(events, "failed_logon", "source_ip", threshold=5, window_minutes=10,
                                   rule_name="multiple_failed_logons_same_source", severity="high")

def detect_failed_logons_same_account(events):
    return detect_count_threshold_breach(events, "failed_logon", "actor", threshold=5, window_minutes=10,
                                   rule_name="multiple_failed_logons_same_account", severity="high")

def detect_brute_force(events):
    # tighter window, higher count = classic brute force against one account
    return detect_count_threshold_breach(events, "failed_logon", "actor", threshold=10, window_minutes=5,
                                   rule_name="brute_force_attack", severity="critical")

def detect_password_spraying(events):
    # same source, many DISTINCT accounts = spraying
    return detect_distinct_count_threshold_breach(events, "failed_logon", "source_ip", "actor",
                                            threshold=5, window_minutes=15,
                                            rule_name="password_spraying", severity="critical")



def run_detections(events):
    rule_functions = [
        detect_failed_logons_same_source,
        detect_failed_logons_same_account,
        detect_brute_force,
        detect_password_spraying,
        # detect_success_after_failures,
        # detect_unusual_logon_type,
        # detect_rdp_logon,
        # detect_network_logon,
        # detect_interactive_logon_unexpected_account,
        # detect_explicit_credential_usage,
        # detect_privileged_account_login,
        # detect_disabled_account_auth_attempt,
        # detect_locked_account_activity,
        # detect_account_created,
        # detect_account_deleted,
        # detect_account_enabled,
        # detect_account_disabled,
        # detect_password_changed,
        # detect_password_reset,
        # detect_privileged_group_change,
        # detect_unexpected_admin_activity,
        # detect_guest_account_enabled,
        # detect_default_account_activity,
        # detect_auth_across_multiple_hosts,
        # detect_log_tampering,
    ]

    all_alerts = []
    for fn in rule_functions:
        all_alerts.extend(fn(events))
    return all_alerts