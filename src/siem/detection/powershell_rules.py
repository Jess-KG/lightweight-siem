from datetime import timedelta

from .generic_rules import _parse_ts

POWERSHELL_NAMES = ["powershell.exe", "pwsh.exe"]

DOWNLOAD_INDICATORS = [
    "DownloadString", "DownloadFile", "Net.WebClient",
    "Invoke-WebRequest", "iwr", "curl", "wget"
]

HIDDEN_FLAGS = ["-WindowStyle Hidden", "-w hidden", "-NoProfile", "-NonInteractive"]
ENCODED_FLAGS = ["-EncodedCommand", "-enc", "-e "]
BYPASS_FLAGS = ["-ExecutionPolicy Bypass", "-ep bypass"]

SUSPICIOUS_STRINGS = [
    "IEX", "Invoke-Expression", "FromBase64String",
    "Net.Sockets",          # connect to external script and download
    "Reflection.Assembly",  # load code directly into memory, without leaving traces
]

OFFICE_APPS = ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"]

EXPECTED_POWERSHELL_PARENTS = [
    "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "taskeng.exe", "svchost.exe"
]

SUSPICIOUS_LOGGING_KEYS = ["EnableScriptBlockLogging", "EnableModuleLogging", "EnableTranscripting"]
PERSISTENCE_REGISTRY_PATHS = ["\\Run\\", "\\RunOnce\\", "\\Winlogon\\Shell", "\\Winlogon\\Userinit"]


def extract_filename(path):
    if not path:
        return ""
    return path[path.rfind("\\") + 1:]


def make_alert(rule, severity, event, message):
    return {
        "rule": rule,
        "severity": severity,
        "timestamp": event.get("timestamp"),
        "computer": event.get("computer"),
        "message": message,
        "event" : event
    }


def is_powershell(event):
    process = event.get("process") or ""
    process_name = extract_filename(process).lower()
    return process_name in [p.lower() for p in POWERSHELL_NAMES]


def powershell_execution(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue
        if not is_powershell(e):
            continue
        alerts.append(make_alert(
            "powershell_execution", "low", e,
            f"PowerShell executed: '{extract_filename(e.get('process') or '')}'"
        ))
    return alerts


def encoded_powershell_commands(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created" or not e.get("command_line"):
            continue
        if not is_powershell(e):
            continue
        command = e.get("command_line")
        for flag in ENCODED_FLAGS:
            if flag.lower() in command.lower():
                alerts.append(make_alert(
                    "encoded_powershell_command", "high", e,
                    f"PowerShell executed with encoded command parameter: {flag}"
                ))
                break
    return alerts


def hidden_powershell_commands(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created" or not e.get("command_line"):
            continue
        if not is_powershell(e):
            continue
        command = e.get("command_line")
        for flag in HIDDEN_FLAGS:
            if flag.lower() in command.lower():
                alerts.append(make_alert(
                    "hidden_powershell_execution", "high", e,
                    f"PowerShell executed with suspicious hidden/non-interactive parameter: {flag}"
                ))
                break
    return alerts


def bypass_powershell_commands(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created" or not e.get("command_line"):
            continue
        if not is_powershell(e):
            continue
        command = e.get("command_line")
        for flag in BYPASS_FLAGS:
            if flag.lower() in command.lower():
                alerts.append(make_alert(
                    "bypass_powershell_execution", "high", e,
                    f"PowerShell executed with suspicious bypass parameter: {flag}"
                ))
                break
    return alerts


def powershell_downloading_content(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created" or not e.get("command_line"):
            continue
        if not is_powershell(e):
            continue
        command = e.get("command_line")
        for flag in DOWNLOAD_INDICATORS:
            if flag.lower() in command.lower():
                alerts.append(make_alert(
                    "powershell_downloading_content", "high", e,
                    f"PowerShell command contains download indicator: {flag}"
                ))
                break
    return alerts


def powershell_network_connections(events, window_minutes=5):
    # if the ProcessGuid matches between a powershell process_created event and
    # a network_connection event, that connection came from that specific
    # powershell process instance
    alerts = []
    powershell_processes = [e for e in events if e.get("type") == "process_created" and is_powershell(e)]
    network_events = [e for e in events if e.get("type") == "network_connection"]

    for ps in powershell_processes:
        ps_guid = ps.get("process_guid")
        ps_timestamp = _parse_ts(ps.get("timestamp"))

        if not ps_guid or not ps_timestamp:
            continue
        ps_guid = ps_guid.lower()

        for net in network_events:
            net_guid = net.get("process_guid")
            net_time = _parse_ts(net.get("timestamp"))

            if not net_guid or not net_time:
                continue

            if net_guid.lower() != ps_guid:
                continue

            gap = net_time - ps_timestamp

            if timedelta(0) <= gap <= timedelta(minutes=window_minutes):
                destination_ip = net.get("destination_ip") or "unknown"
                destination_port = net.get("destination_port") or "unknown"

                alerts.append(make_alert(
                    "powershell_followed_by_network", "high", net,
                    f"PowerShell activity was followed by network activity to "
                    f"{destination_ip}:{destination_port} within {gap}"
                ))
                break

    return alerts


def powershell_script_execution(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue
        if not is_powershell(e):
            continue
        command_lower = (e.get("command_line") or "").lower()
        if ".ps1" in command_lower or "-file" in command_lower:
            alerts.append(make_alert(
                "powershell_script_execution", "low", e,
                "PowerShell executed a script"
            ))
    return alerts


def suspicious_powershell_command_strings(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue
        if not is_powershell(e):
            continue
        command_lower = (e.get("command_line") or "").lower()
        for suspicious_string in SUSPICIOUS_STRINGS:
            if suspicious_string.lower() in command_lower:
                alerts.append(make_alert(
                    "suspicious_powershell_command_string", "high", e,
                    f"PowerShell command contains suspicious string: {suspicious_string}"
                ))
                break
    return alerts


def powershell_unusual_parent(events):
    alerts = []
    expected_parents = [p.lower() for p in EXPECTED_POWERSHELL_PARENTS]
    office_apps_lower = [a.lower() for a in OFFICE_APPS]

    for e in events:
        if e.get("type") != "process_created":
            continue
        if not is_powershell(e):
            continue

        parent_process = e.get("parent_process")
        if not parent_process:
            continue

        parent_name = extract_filename(parent_process).lower()

        # Office -> PowerShell is already covered by suspicious_parent_child's
        # KNOWN_HIGH_VALUE_CHAINS list, with its own message. Skip it here so
        # the same event doesn't produce two near-duplicate alerts.
        if parent_name in office_apps_lower:
            continue

        if parent_name not in expected_parents:
            alerts.append(make_alert(
                "powershell_unusual_parent", "high", e,
                f"PowerShell was launched by unusual parent process: '{parent_name}'"
            ))

    return alerts


def powershell_and_persistence(events, window_minutes=5):
    powershell_processes = [e for e in events if e.get("type") == "process_created" and is_powershell(e)]
    registry_events = [e for e in events if e.get("type") == "registry_value_set" and e.get("target_object")]

    alerts = []
    for ps in powershell_processes:
        ps_guid = ps.get("process_guid")
        ps_timestamp = _parse_ts(ps.get("timestamp"))
        if not ps_guid or not ps_timestamp:
            continue
        ps_guid = ps_guid.lower()

        for reg in registry_events:
            reg_guid = reg.get("process_guid")
            reg_time = _parse_ts(reg.get("timestamp"))
            if not reg_guid or not reg_time:
                continue

            if reg_guid.lower() != ps_guid:
                continue

            target = reg.get("target_object") or ""
            if not any(path.lower() in target.lower() for path in PERSISTENCE_REGISTRY_PATHS):
                continue

            gap = reg_time - ps_timestamp
            if timedelta(0) <= gap <= timedelta(minutes=window_minutes):
                alerts.append(make_alert(
                    "powershell_followed_by_persistence", "critical", reg,
                    f"PowerShell activity was followed by a persistence-related "
                    f"registry write to '{target}' within {gap}"
                ))
                break

    return alerts


def suspicious_script_block(events):
    alerts = []
    for e in events:
        if e.get("type") != "script_block_logged":
            continue

        script_text = e.get("script_block_text") or ""
        script_lower = script_text.lower()

        for suspicious_string in SUSPICIOUS_STRINGS:
            if suspicious_string.lower() in script_lower:
                alerts.append(make_alert(
                    "suspicious_script_block", "high", e,
                    f"PowerShell script block contains suspicious string: {suspicious_string}"
                ))
                break

    return alerts


def suspicious_powershell_logging_change(events):
    DISABLE_INDICATORS = ["0x0", "dword (0x00000000)", "disable"]

    alerts = []
    for e in events:
        if e.get("type") != "registry_value_set":
            continue

        target = e.get("target_object") or ""
        details = (e.get("details") or "").lower()

        for key in SUSPICIOUS_LOGGING_KEYS:
            if key.lower() not in target.lower():
                continue

            if any(indicator in details for indicator in DISABLE_INDICATORS):
                alerts.append(make_alert(
                    "suspicious_powershell_logging_change", "critical", e,
                    f"PowerShell logging setting '{key}' was changed to disabled "
                    f"(registry: {target})"
                ))
            break

    return alerts

def run_detections_powershell(events):
    rule_functions = [
        powershell_execution,
        encoded_powershell_commands,
        hidden_powershell_commands,
        bypass_powershell_commands,
        powershell_downloading_content,
        powershell_network_connections,
        powershell_script_execution,
        suspicious_powershell_command_strings,
        powershell_unusual_parent,
        powershell_and_persistence,
        suspicious_script_block,
        suspicious_powershell_logging_change,
    ]

    all_alerts = []
    for fn in rule_functions:
        all_alerts.extend(fn(events))
    return all_alerts