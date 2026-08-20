EVENT_TYPES = {
    # Windows Security
    ("Microsoft-Windows-Security-Auditing", "4720"): "account_created",
    ("Microsoft-Windows-Security-Auditing", "4732"): "group_membership_added",
    ("Microsoft-Windows-Security-Auditing", "4648"): "explicit_credential_logon",
    ("Microsoft-Windows-Security-Auditing", "4672"): "special_privileges_assigned",
    ("Microsoft-Windows-Security-Auditing", "1100"): "event_log_service_shutdown",
    ("Microsoft-Windows-Security-Auditing", "1101"): "event_log_cleared",

    # Sysmon
    ("Microsoft-Windows-Sysmon", "1"): "process_created",
    ("Microsoft-Windows-Sysmon", "3"): "network_connection",
    ("Microsoft-Windows-Sysmon", "6"): "driver_loaded",
    ("Microsoft-Windows-Sysmon", "7"): "image_loaded",
    ("Microsoft-Windows-Sysmon", "8"): "remote_thread_created",
    ("Microsoft-Windows-Sysmon", "10"): "process_access",
    ("Microsoft-Windows-Sysmon", "11"): "file_created",
    ("Microsoft-Windows-Sysmon", "12"): "registry_object_created",
    ("Microsoft-Windows-Sysmon", "13"): "registry_value_set",
    ("Microsoft-Windows-Sysmon", "14"): "registry_object_renamed",
    ("Microsoft-Windows-Sysmon", "22"): "dns_query",
}

def normalize(event):
    data = event.event_data or {}
    provider = event.provider or "Microsoft-Windows-Security-Auditing"
    event_id = str(event.event_id)
    event_type = EVENT_TYPES.get((provider, event_id), "unknown")

    normalized = {
        "event_id": event_id,
        "timestamp": event.timestamp,
        "computer": event.computer,
        "provider": provider,
        "type": event_type,
        "data": data,
    }

    if event_type == "account_created":
        normalized.update({
            "actor": data.get("SubjectUserName"),
            "target_account": data.get("TargetUserName"),
            "target_sid": data.get("TargetSid"),
        })

    elif event_type == "group_membership_added":
        normalized.update({
            "actor": data.get("SubjectUserName"),
            "member_added": data.get("MemberName"),
            "group": data.get("TargetUserName"),
        })

    elif event_type == "explicit_credential_logon":
        normalized.update({
            "actor": data.get("SubjectUserName"),
            "target_account": data.get("TargetUserName"),
            "target_server": data.get("TargetServerName"),
            "source_ip": data.get("IpAddress"),
            "process": data.get("ProcessName"),
        })

    elif event_type == "special_privileges_assigned":
        normalized.update({
            "actor": data.get("SubjectUserName"),
            "privileges": data.get("PrivilegeList"),
        })

    elif event_type == "process_access":
        # Confirmed from real data: uses SourceImage/TargetImage, NOT Image/ParentImage
        normalized.update({
            "source_process": data.get("SourceImage"),
            "target_process": data.get("TargetImage"),
            "granted_access": data.get("GrantedAccess"),
            "call_trace": data.get("CallTrace"),
        })

    elif event_type in {
        "process_created",
        "network_connection",
        "file_created",
        "dns_query",
        "remote_thread_created",
        "image_loaded",
    }:
        normalized.update({
            "user": data.get("User"),
            "process": data.get("Image"),
            "parent_process": data.get("ParentImage"),
            "command_line": data.get("CommandLine"),
            "source_ip": data.get("SourceIp"),
            "source_port": data.get("SourcePort"),
            "destination_ip": data.get("DestinationIp"),
            "destination_port": data.get("DestinationPort"),
            "destination_hostname": data.get("DestinationHostname"),
        })

    return normalized

    data = event.event_data or {}

    provider = getattr(event, "provider", None)

    # Some event models may not currently expose provider.
    # Fall back to a sensible default for existing Security events.
    if not provider:
        provider = "Microsoft-Windows-Security-Auditing"

    event_id = str(event.event_id)

    event_type = EVENT_TYPES.get(
        (provider, event_id),
        "unknown"
    )

    normalized = {
        "event_id": event_id,
        "timestamp": event.timestamp,
        "computer": event.computer,
        "provider": provider,
        "type": event_type,
        "data": data,
    }

    # Add useful semantic fields for the events where
    # they make detection/correlation easier.
    if event_type == "account_created":
        normalized.update({
            "actor": data.get("SubjectUserName"),
            "target_account": data.get("TargetUserName"),
            "target_sid": data.get("TargetSid"),
        })

    elif event_type == "group_membership_added":
        normalized.update({
            "actor": data.get("SubjectUserName"),
            "member_added": data.get("MemberName"),
            "group": data.get("TargetUserName"),
        })

    elif event_type == "explicit_credential_logon":
        normalized.update({
            "actor": data.get("SubjectUserName"),
            "target_account": data.get("TargetUserName"),
            "target_server": data.get("TargetServerName"),
            "source_ip": data.get("IpAddress"),
            "process": data.get("ProcessName"),
        })

    elif event_type == "special_privileges_assigned":
        normalized.update({
            "actor": data.get("SubjectUserName"),
            "privileges": data.get("PrivilegeList"),
        })

    elif event_type in {
        "process_created",
        "network_connection",
        "file_created",
        "dns_query",
        "remote_thread_created",
        "process_access",
        "image_loaded",
    }:
        # Common Sysmon fields are kept as convenient top-level fields,
        # while the complete event remains available in "data".
        normalized.update({
            "user": data.get("User"),
            "process": data.get("Image"),
            "parent_process": data.get("ParentImage"),
            "command_line": data.get("CommandLine"),
            "source_ip": data.get("SourceIp"),
            "source_port": data.get("SourcePort"),
            "destination_ip": data.get("DestinationIp"),
            "destination_port": data.get("DestinationPort"),
            "destination_hostname": data.get("DestinationHostname"),
        })

    return normalized