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

PRIVILEGED_GROUPS = ["Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins"]
DEFAULT_ACCOUNTS = ["Guest", "Administrator", "DefaultAccount"]
EXPECTED_INTERACTIVE_ACCOUNTS = ["user1", "user2"]
NOISE_ACCOUNTS = ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]
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

def detect_success_after_failures(events, threshold = 3, window_minutes = 10):
    failed = []
    success = []
    alerts = []
    for e in events:
        if e.get("actor") is not None:
            if e.get("type") == "successful_logon":
                success.append(e)
            elif e.get("type") == "failed_logon":
                success.append(e)
    
    for s in success:
        actor = s.get("actor")
        s_time = _parse_ts(s.get("timestamp"))
        if actor is None or s_time is None:
            continue
        
        recent_fails = []
        for f in failed:
            if f.get("actor") == actor:
                f_time = _parse_ts(s.get("timestamp"))
                if (s_time - f_time).total_seconds() <= window_minutes * 60:
                    recent_fails.append(f)

        if len(recent_fails) > threshold:
            alerts.append({
                "rule": "success_after_repeated_failures",
                "severity": "high",
                "timestamp": s.get("timestamp"),
                "computer": s.get("computer"),
                "message": f"'{actor}' succeeded after {len(recent_fails)} failed attempts within {window_minutes}min",
            })
    return alerts

def detect_rdp_logon(events):
    alerts = []
    for e in events:
        if e.get("type") == "successful_logon" and e.get("logon_type") == "10":
            alerts.append({
                "rule": "rdp_logon", "severity": "low",
                "timestamp": e.get("timestamp"), "computer": e.get("computer"),
                "message": f"RDP logon by '{e.get('actor')}' from {e.get('source_ip')}",
            })

    return alerts


def detect_network_logon(events):
    alerts = []
    for e in events:
        if e.get("type") == "successful_logon" and e.get("logon_type") == "3":
            alerts.append({
            "rule": "network_logon", "severity": "low",
            "timestamp": e.get("timestamp"), "computer": e.get("computer"),
            "message": f"Network logon by '{e.get('actor')}' from {e.get('source_ip')}",
        })

    return alerts

def detect_interactive_logon_unexpected_account(events):
    alerts = []
    for e in events:
        if e.get("type") == "successful_logon" and e.get("logon_type") == "2":
            actor = e.get("actor")
            if EXPECTED_INTERACTIVE_ACCOUNTS and actor not in EXPECTED_INTERACTIVE_ACCOUNTS:
                alerts.append({
                    "rule": "interactive_logon_unexpected_account", "severity": "medium",
                    "timestamp": e.get("timestamp"), "computer": e.get("computer"),
                    "message": f"Unexpected interactive logon by '{actor}'",
                })
    return alerts

def detect_explicit_credential_usage(events):
    alerts = []
    for e in events:
        if e.get("type") == "explicit_credential_logon":
            alerts.append( {
            "rule": "explicit_credential_usage", "severity": "medium",
            "timestamp": e.get("timestamp"), "computer": e.get("computer"),
            "message": f"'{e.get('actor')}' used explicit credentials for '{e.get('target_account')}' on {e.get('target_server')}",
        })
    return alerts

def detect_privileged_account_login(events):
    alerts = []
    for e in events:
        if e.get("type") == "special_privileges_assigned" and e.get("actor") not in NOISE_ACCOUNTS:
            alerts.append({
            "rule": "privileged_account_login", "severity": "medium",
            "timestamp": e.get("timestamp"), "computer": e.get("computer"),
            "message": f"Privileged logon: '{e.get('actor')}' assigned special privileges",
        })
    return alerts


def detect_disabled_account_auth_attempt(events):
    alerts = []
    for e in events:
        if e.get("type") == "failed_logon" and e.get("failure_reason") and "disabled" in str(e.get("failure_reason")).lower():
            alerts.append({
            "rule": "disabled_account_auth_attempt", "severity": "high",
            "timestamp": e.get("timestamp"), "computer": e.get("computer"),
            "message": f"Auth attempt on disabled account '{e.get('actor')}'",
        })
    return alerts


def detect_locked_account_activity(events):
    alerts = []
    for e in events:
        if e.get("type") == "account_locked_out":
            alerts.append({
            "rule": "locked_account_activity", "severity": "high",
            "timestamp": e.get("timestamp"), "computer": e.get("computer"),
            "message": f"Account '{e.get('actor')}' was locked out",
        })
    return alerts

def _lifecycle_alerts(events, event_type, rule_name, severity="low"):
    alerts = []
    for e in events:
        if e.get("type") == event_type:
            alerts.append({
            "rule": rule_name, "severity": severity,
            "timestamp": e.get("timestamp"), "computer": e.get("computer"),
            "message": f"{rule_name}: actor='{e.get('actor')}' target='{e.get('target_account')}'",
        })
    return alerts

def detect_account_created(events):
    return _lifecycle_alerts(events, "account_created", "account_created")

def detect_account_deleted(events):
    return _lifecycle_alerts(events, "account_deleted", "account_deleted", severity="medium")

def detect_account_enabled(events):
    return _lifecycle_alerts(events, "account_enabled", "account_enabled")

def detect_account_disabled(events):
    return _lifecycle_alerts(events, "account_disabled", "account_disabled")

def detect_password_changed(events):
    return _lifecycle_alerts(events, "password_changed", "password_changed")

def detect_password_reset(events):
    return _lifecycle_alerts(events, "password_reset", "password_reset", severity="medium")


def detect_privileged_group_change(events):
    alerts = []
    for e in events:
        if e.get("type") not in {"group_membership_added", "group_membership_removed"}:
            continue
        if e.get("group") in PRIVILEGED_GROUPS:
            if e.get("type") == "group_membership_added":
                action = "added to" 
            else:
                action = "removed from"

            alerts.append({
                "rule": f"privileged_group_{'added' if action.startswith('added') else 'removed'}",
                "severity": "high",
                "timestamp": e.get("timestamp"), "computer": e.get("computer"),
                "message": f"'{e.get('member_changed')}' {action} privileged group '{e.get('group')}'",
            })
    return alerts


def detect_unexpected_admin_activity(events):
    alerts = []
    for e in events:
        if e.get("type") == "special_privileges_assigned" and e.get("actor") not in NOISE_ACCOUNTS:
            alerts.append({
                "rule": "non_standard_admin_logon", "severity": "medium",
                "timestamp": e.get("timestamp"), "computer": e.get("computer"),
                "message": f"Admin privileges assigned to non-standard account: {e.get('actor')}",
            })
    return alerts


def detect_guest_account_enabled(events):
    alerts = []
    for e in events:
        if e.get("type") == "account_enabled" and e.get("target_account") == "Guest":
            alerts.append({
                "rule": "non_standard_admin_logon", "severity": "medium",
                "timestamp": e.get("timestamp"), "computer": e.get("computer"),
                "message": f"Admin privileges assigned to non-standard account: {e.get('actor')}",
            })
    return alerts

def detect_default_account_activity(events):
    alerts = []
    for e in events:
        if (e.get("actor") in DEFAULT_ACCOUNTS or e.get("target_account") in DEFAULT_ACCOUNTS):
            alerts.append({
            "rule": "default_account_activity", "severity": "medium",
            "timestamp": e.get("timestamp"), "computer": e.get("computer"),
            "message": f"Activity on default account '{e.get('actor') or e.get('target_account')}' ({e.get('type')})",
        })
    return alerts

def detect_auth_across_multiple_hosts(events, threshold=3, window_minutes=30):
    return detect_distinct_count_threshold_breach(events, "successful_logon", "actor", "computer",
                                            threshold=threshold, window_minutes=window_minutes,
                                            rule_name="auth_across_multiple_hosts", severity="high")

def detect_log_tampering(events):
    alerts = []
    for e in events:
        if e.get("type") in {"event_log_service_shutdown", "event_log_cleared"}:
            alerts.append({
            "rule": "log_tampering", "severity": "high",
            "timestamp": e.get("timestamp"), "computer": e.get("computer"),
            "message": f"Event log service changed on {e.get('computer')} — possible anti-forensics",
        })   
    return alerts

def run_detections(events):
    rule_functions = [
        detect_failed_logons_same_source,
        detect_failed_logons_same_account,
        detect_brute_force,
        detect_password_spraying,
        detect_success_after_failures,
        # detect_unusual_logon_type,
        detect_rdp_logon,
        detect_network_logon,
        detect_interactive_logon_unexpected_account,
        detect_explicit_credential_usage,
        detect_privileged_account_login,
        detect_disabled_account_auth_attempt,
        detect_locked_account_activity,
        detect_account_created,
        detect_account_deleted,
        detect_account_enabled,
        detect_account_disabled,
        detect_password_changed,
        detect_password_reset,
        detect_privileged_group_change,
        detect_unexpected_admin_activity,
        detect_guest_account_enabled,
        detect_default_account_activity,
        detect_auth_across_multiple_hosts,
        detect_log_tampering,
    ]

    all_alerts = []
    for fn in rule_functions:
        result = fn(events)
        all_alerts.extend(result)
    return all_alerts