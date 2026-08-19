def normalize(event):
    #we are goin go normalize only some events as the current dataset is incomplete
    #4720 --> User Account Created
    #4732 --> User Account Enabled / added to a group
    #4648 --> explicit credential logon
    #4672 --> administrative privilege assigned to a user
    #1100/1101 --> log cleared

    handlers = {
        "4720": handle_user_account_created,
        "4732": handle_group_membership_change,
        "4648": handle_explicit_credential_logon,
        "4672": handle_administrative_privilege_assigned,
        "1100": handle_log_cleared,
        "1101": handle_log_cleared
    }
    handler = handlers[event.event_id] if event.event_id in handlers else None
    if handler is None:
        return None
    
    return handler(event)


def handle_user_account_created(event):
    data = event.event_data or {}
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "computer": event.computer,
        "type": "account_created",
        "actor": data.get("SubjectUserName"),
        "target_account": data.get("TargetUserName"),
        "target_sid": data.get("TargetSid"),
    }


def handle_group_membership_change(event):
    data = event.event_data or {}
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "computer": event.computer,
        "type": "group_membership_added",
        "actor": data.get("SubjectUserName"),
        "member_added": data.get("MemberName"),
        "group": data.get("TargetUserName"),
    }


def handle_explicit_credential_logon(event):
    data = event.event_data or {}
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "computer": event.computer,
        "type": "explicit_credential_logon",
        "actor": data.get("SubjectUserName"),
        "target_account": data.get("TargetUserName"),
        "target_server": data.get("TargetServerName"),
        "source_ip": data.get("IpAddress"),
        "process": data.get("ProcessName"),
    }


def handle_administrative_privilege_assigned(event):
    data = event.event_data or {}
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "computer": event.computer,
        "type": "admin_privileges_assigned",
        "actor": data.get("SubjectUserName"),
        "privileges": data.get("PrivilegeList"),
    }


def handle_log_cleared(event):
    # 1100/1101 typically have no EventData — just System block info
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "computer": event.computer,
        "type": "log_service_change",
        "note": "Event logging service shutdown/change — possible log tampering",
    }
    
