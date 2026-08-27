EVENT_TYPES = {
    # Windows Security — logon
    ("Microsoft-Windows-Security-Auditing", "4624"): "successful_logon",
    ("Microsoft-Windows-Security-Auditing", "4625"): "failed_logon",
    ("Microsoft-Windows-Security-Auditing", "4648"): "explicit_credential_logon",
    ("Microsoft-Windows-Security-Auditing", "4672"): "special_privileges_assigned",
    ("Microsoft-Windows-Security-Auditing", "4740"): "account_locked_out",

    # Windows Security — account lifecycle
    ("Microsoft-Windows-Security-Auditing", "4720"): "account_created",
    ("Microsoft-Windows-Security-Auditing", "4722"): "account_enabled",
    ("Microsoft-Windows-Security-Auditing", "4725"): "account_disabled",
    ("Microsoft-Windows-Security-Auditing", "4726"): "account_deleted",
    ("Microsoft-Windows-Security-Auditing", "4723"): "password_changed",
    ("Microsoft-Windows-Security-Auditing", "4724"): "password_reset",

    # Group membership — added
    ("Microsoft-Windows-Security-Auditing", "4732"): "group_membership_added",   # local group
    ("Microsoft-Windows-Security-Auditing", "4728"): "group_membership_added",   # global group
    ("Microsoft-Windows-Security-Auditing", "4756"): "group_membership_added",   # universal group

    # Group membership — removed
    ("Microsoft-Windows-Security-Auditing", "4733"): "group_membership_removed", # local group
    ("Microsoft-Windows-Security-Auditing", "4729"): "group_membership_removed", # global group
    ("Microsoft-Windows-Security-Auditing", "4757"): "group_membership_removed", # universal group

    # Log tampering
    ("Microsoft-Windows-Security-Auditing", "1100"): "event_log_service_shutdown",
    ("Microsoft-Windows-Security-Auditing", "1101"): "event_log_cleared",

    # Sysmon
    ("Microsoft-Windows-Sysmon", "1"): "process_created",
    ("Microsoft-Windows-Sysmon", "3"): "network_connection",
    ("Microsoft-Windows-Sysmon", "6"): "driver_loaded",
    ("Microsoft-Windows-Sysmon", "7"): "image_loaded", #check for signed, unsigned
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

    if event_type == "successful_logon":
        normalized.update({
            "actor": data.get("TargetUserName"),
            "logon_type": data.get("LogonType"),
            "source_ip": data.get("IpAddress"),
            "logon_process": data.get("LogonProcessName"),
        })
    
    elif event_type == "failed_logon":
        normalized.update({
            "actor": data.get("TargetUserName"),
            "logon_type": data.get("LogonType"),
            "source_ip": data.get("IpAddress"),
            "failure_reason": data.get("FailureReason") or data.get("Status"),
            "sub_status": data.get("SubStatus"),
        })
    
    elif event_type == "account_locked_out":
        normalized.update({
            "actor": data.get("TargetUserName"),
            "source_computer": data.get("TargetDomainName"),
        })

    elif event_type in {"account_created", "account_enabled", "account_disabled",
                         "account_deleted", "password_changed", "password_reset"}:
        normalized.update({
            "actor": data.get("SubjectUserName"),
            "target_account": data.get("TargetUserName"),
            "target_sid": data.get("TargetSid"),
        })


    elif event_type in {"group_membership_added", "group_membership_removed"}:
        normalized.update({
            "actor": data.get("SubjectUserName"),
            "member_changed": data.get("MemberName"),
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
            "parent_command_line": data.get("ParentCommandLine"),
            "current_directory": data.get("CurrentDirectory"),
            "process_guid": data.get("ProcessGuid"),
            "parent_process_guid": data.get("ParentProcessGuid"),
            "source_ip": data.get("SourceIp"),
            "source_port": data.get("SourcePort"),
            "destination_ip": data.get("DestinationIp"),
            "destination_port": data.get("DestinationPort"),
            "destination_hostname": data.get("DestinationHostname"),
        })

    return normalized
