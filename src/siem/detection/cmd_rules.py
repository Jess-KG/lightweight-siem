from datetime import timedelta

from .generic_rules import _parse_ts, join_events_by_process_guid

SCRIPT_ENGINES = ["cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
POWERSHELL_NAMES = ["powershell.exe", "pwsh.exe"]

NETWORK_TOOLS = ["nc.exe", "ncat.exe", "psexec.exe", "plink.exe", "certutil.exe", "bitsadmin.exe", "curl.exe"]
CREDENTIAL_ACCESS_TARGETS = ["lsass.exe"]

SUSPICIOUS_PATHS = ["\\Temp\\", "\\Tmp\\", "\\AppData\\Local\\", "\\AppData\\Roaming\\", "\\Users\\Public\\"]
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


def is_script_engine(event):
    return extract_filename(event.get("process") or "").lower() in SCRIPT_ENGINES


def is_powershell(event):
    return extract_filename(event.get("process") or "").lower() in POWERSHELL_NAMES


def _normalize_username(user):
    # Sysmon's "User" field is usually "DOMAIN\user"
    if not user:
        return ""
    return user.split("\\")[-1].lower()


def script_engine_execution(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created" or not is_script_engine(e):
            continue
        engine = extract_filename(e.get("process")).lower()
        severity = "low" if engine == "cmd.exe" else "medium"
        alerts.append(make_alert(
            "script_engine_execution", severity, e,
            f"Script engine executed: '{engine}'"
        ))
    return alerts



def scripts_from_suspicious_paths(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created" or not is_script_engine(e):
            continue
        process = e.get("process") or ""
        for path in SUSPICIOUS_PATHS:
            if path in process:
                alerts.append(make_alert(
                    "script_from_suspicious_path", "medium", e,
                    f"'{extract_filename(process)}' launched from suspicious path: {process}"
                ))
                break
    return alerts

def scripts_spawning_network_tools(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue
        if not e.get("process") or not e.get("parent_process"):
            continue
        parent = extract_filename(e.get("parent_process")).lower()
        child = extract_filename(e.get("process")).lower()
        if parent in SCRIPT_ENGINES and child in NETWORK_TOOLS:
            alerts.append(make_alert(
                "script_spawning_network_tool", "high", e,
                f"'{parent}' spawned network tool '{child}'"
            ))
    return alerts

def scripts_spawning_powershell(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue
        if not e.get("process") or not e.get("parent_process"):
            continue
        parent = extract_filename(e.get("parent_process")).lower()
        if parent in SCRIPT_ENGINES and is_powershell(e):
            alerts.append(make_alert(
                "script_spawning_powershell", "high", e,
                f"'{parent}' spawned PowerShell"
            ))
    return alerts


# ---- 10. scripts creating persistence ----

def scripts_creating_persistence(events, window_minutes=5):
    script_processes = [e for e in events if e.get("type") == "process_created" and is_script_engine(e)]
    registry_events = [e for e in events if e.get("type") == "registry_value_set" and e.get("target_object")]

    def is_persistence_key(reg_event):
        target = reg_event.get("target_object") or ""
        return any(p.lower() in target.lower() for p in PERSISTENCE_REGISTRY_PATHS)

    return join_events_by_process_guid(
        script_processes, registry_events,
        guid_field_a="process_guid", guid_field_b="process_guid",
        window_minutes=window_minutes,
        condition_fn=is_persistence_key,
        rule_name="script_followed_by_persistence",
        severity="critical",
        message_fn=lambda a, b, gap: (
            f"'{extract_filename(a.get('process'))}' was followed by a persistence-related "
            f"registry write to '{b.get('target_object')}' within {gap}"
        ),
    )


def scripts_followed_by_credential_access(events, window_minutes=5):
    script_processes = [e for e in events if e.get("type") == "process_created" and is_script_engine(e)]
    process_access_events = [e for e in events if e.get("type") == "process_access" and e.get("target_process")]

    def targets_lsass(pa_event):
        target = extract_filename(pa_event.get("target_process") or "").lower()
        return target in CREDENTIAL_ACCESS_TARGETS

    return join_events_by_process_guid(
        script_processes, process_access_events,
        guid_field_a="process_guid", guid_field_b="source_process_guid",
        window_minutes=window_minutes,
        condition_fn=targets_lsass,
        rule_name="script_followed_by_credential_access",
        severity="critical",
        message_fn=lambda a, b, gap: (
            f"'{extract_filename(a.get('process'))}' was followed by access to "
            f"'{extract_filename(b.get('target_process'))}' within {gap} — possible credential dumping"
        ),
    )



def scripts_followed_by_lateral_movement(events, window_minutes=15):
    #did the same person who just ran a script, show up on a different computer after some time?
    script_processes = [e for e in events if e.get("type") == "process_created" and is_script_engine(e)]
    logons = [e for e in events if e.get("type") == "successful_logon" and e.get("actor")]

    alerts = []
    for sp in script_processes:
        sp_user = _normalize_username(sp.get("user"))
        sp_time = _parse_ts(sp.get("timestamp"))
        sp_computer = sp.get("computer")
        if not sp_user or not sp_time:
            continue

        for logon in logons:
            logon_user = _normalize_username(logon.get("actor"))
            logon_time = _parse_ts(logon.get("timestamp"))
            if not logon_user or not logon_time:
                continue
            if logon_user != sp_user:
                continue
            if logon.get("computer") == sp_computer:
                continue  # same host isn't lateral movement

            gap = logon_time - sp_time
            if timedelta(0) <= gap <= timedelta(minutes=window_minutes):
                alerts.append(make_alert(
                    "script_followed_by_lateral_movement", "high", logon,
                    f"'{sp_user}' ran a script on {sp_computer}, then logged into "
                    f"{logon.get('computer')} within {gap}"
                ))
                break
    return alerts


def run_detections_command_shells(events):
    rule_functions = [
        script_engine_execution,
        scripts_from_suspicious_paths,
        scripts_spawning_network_tools,
        scripts_spawning_powershell,
        scripts_creating_persistence,
        scripts_followed_by_credential_access,
        scripts_followed_by_lateral_movement,
    ]
    all_alerts = []
    for fn in rule_functions:
        all_alerts.extend(fn(events))
    return all_alerts