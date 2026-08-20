from datetime import timedelta, datetime
def detect_alerts(events):
    alerts = []
    for event in events:
        if event["type"] == "log_service_change":
            detect_log_tampering(alerts, event)
    

    ##detecting privilege escalation...INTERESTING STUFFFF
    detect_privilege_escalation(alerts, events)
    detect_interesting_admin_logon(alerts, events)

    return alerts


def get_time(timestamp):
    try:
        return datetime.fromisoformat(timestamp)
    except(ValueError, TypeError):
        None

def detect_log_tampering(alerts, event):
    alerts.append({
        "rule": "log_tampering",
        "severity": "high",
        "timestamp": event.get("timestamp"),
        "computer": event.get("computer"),
        "message": f"Event log service changed on {event.get('computer')} — possible log tampering/anti-forensics",
        "raw_event": event,
    })
    
def detect_privilege_escalation(alerts, events):
    new_accounts_created = []
    added_to_group = []

    for event in events:
        if event["type"] == "account_created":
            new_accounts_created.append(event)
        elif event["type"] == "group_membership_added":
            added_to_group.append(event)

    
    for account in new_accounts_created:
        account_created = account["target_account"]
        created_time = get_time(account["timestamp"])

        if not account_created or not created_time:
            continue

        for added_event in added_to_group:
            if (added_event["member_added"] != account_created):
                continue
            print("Founding something")
            added_time = get_time(added_event["timestamp"])

            time_difference = added_time - created_time

            if (timedelta(0) <= time_difference <= timedelta(minutes=window_minutes)):
                alerts.append({
                    "rule": "privilege_escalation_chain",
                    "severity": "high",
                    "timestamp": added_event.get("timestamp"),
                    "computer": added_event.get("computer"),
                    "message": f"Account '{created_account}' created then added to group '{added_event.get('group')}' within {time_difference}",
                    "raw_event": added_event,
                })


def detect_interesting_admin_logon(alerts, events):
    NOISE_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}

    for event in events:
        if event.get("type") != "admin_privileges_assigned":
            continue
        actor = event.get("actor")
        if actor and actor not in NOISE_ACCOUNTS:
            alerts.append({
                "rule": "non_standard_admin_logon",
                "severity": "medium",
                "timestamp": event.get("timestamp"),
                "computer": event.get("computer"),
                "message": f"Admin privileges assigned to non-standard account: {actor}",
                "raw_event": event,
            })
    return alerts