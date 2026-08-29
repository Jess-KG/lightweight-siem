#smss -> sql
#wininit -> microsoft windows core process
#lsass.exe -> handles auth stuff
#services -> manages services; svchost -> runs those services
#crss -> cmd, shutdown
from datetime import timedelta

from .generic_rules import _parse_ts

SYSTEM_PROCESSES = ["svchost.exe", "services.exe", "lsass.exe", "wininit.exe", "csrss.exe", "smss.exe"]
EXPECTED_CHILDREN = {
    "smss.exe": {"csrss.exe", "wininit.exe"},
    "wininit.exe": {"services.exe", "lsass.exe", "fontdrvhost.exe"},
    "services.exe": {"svchost.exe"},
    "svchost.exe": set(),
    "lsass.exe": set(),
    "csrss.exe": set(),
}

EXPECTED_SYSTEM32_PATH = "C:\\Windows\\System32\\"

OFFICE_APPS = ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"]
BROWSERS = ["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"]
SCRIPT_INTERPRETERS = ["powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe"]
SHELL_PROCESSES = ["cmd.exe", "powershell.exe"]

SUSPICIOUS_PATHS = ["\\Temp\\", "\\Tmp\\", "\\AppData\\Local\\", "\\AppData\\Roaming\\", "\\Users\\Public\\"]
NORMAL_SYSTEM32_LOCATIONS = ["C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\"]

SUSPICIOUS_CLI_FLAGS = ["-EncodedCommand", "-enc", "-WindowStyle Hidden", "-NoProfile", "-ExecutionPolicy Bypass"]

KNOWN_HIGH_VALUE_CHAINS = [
    ("WINWORD.EXE", ["cmd.exe"]),
    ("WINWORD.EXE", ["powershell.exe"]),
    ("EXCEL.EXE", ["powershell.exe"]),
    ("OUTLOOK.EXE", ["powershell.exe"]),
    ("powershell.exe", ["cmd.exe"]),
    ("wscript.exe", ["powershell.exe"]),
    ("mshta.exe", ["powershell.exe"]),
]


# ---- helpers ----

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


# ---- rules ----

def process_from_suspicious_paths(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue

        process = e.get("process") or ""
        for path in SUSPICIOUS_PATHS:
            if path in process:
                alerts.append(make_alert(
                    "process_from_suspicious_path", "medium", e,
                    f"'{extract_filename(process)}' launched from suspicious path: {process}"
                ))
                break  # one match is enough per event
    return alerts


def executable_from_suspicious_paths(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue

        process = e.get("process") or ""
        if "exe" not in process:
            continue

        executable_file = extract_filename(process).lower()

        if executable_file in [p.lower() for p in SYSTEM_PROCESSES]:
            if EXPECTED_SYSTEM32_PATH not in process:
                alerts.append(make_alert(
                    "system_binary_wrong_location", "high", e,
                    f"System binary '{executable_file}' running from unexpected location: {process}"
                ))
    return alerts


def suspicious_command_line(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue

        command_line = e.get("command_line")
        if not command_line:
            continue

        for flag in SUSPICIOUS_CLI_FLAGS:
            if flag in command_line:
                alerts.append(make_alert(
                    "suspicious_command_line_flag", "high", e,
                    f"'{extract_filename(e.get('process') or '')}' run with suspicious flag: {flag}"
                ))
                break
    return alerts


def suspicious_parent_child(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue
        if not e.get("process") or not e.get("parent_process"):
            continue

        child_process = extract_filename(e.get("process")).lower()
        parent_process = extract_filename(e.get("parent_process")).lower()

        for chain_parent, chain_children in KNOWN_HIGH_VALUE_CHAINS:
            if parent_process == chain_parent.lower() and child_process in [c.lower() for c in chain_children]:
                alerts.append(make_alert(
                    "suspicious_parent_child_chain", "critical", e,
                    f"'{parent_process}' spawned '{child_process}' — known high-value attack chain"
                ))
                break
    return alerts


def unexpected_system_process(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue

        user = e.get("user")
        if not user:
            continue

        if user.lower() == "system":
            process_name = extract_filename(e.get("process") or "").lower()
            if process_name and process_name not in [p.lower() for p in SYSTEM_PROCESSES]:
                alerts.append(make_alert(
                    "unexpected_system_level_process", "high", e,
                    f"'{process_name}' executed under SYSTEM, which is not a known system process"
                ))
    return alerts


def system_process_unusual_children(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue
        if not e.get("process") or not e.get("parent_process"):
            continue

        parent = extract_filename(e.get("parent_process")).lower()
        child = extract_filename(e.get("process")).lower()

        if parent in EXPECTED_CHILDREN:
            expected = {c.lower() for c in EXPECTED_CHILDREN[parent]}
            if child not in expected:
                alerts.append(make_alert(
                    "system_process_unusual_child", "high", e,
                    f"'{parent}' spawned unexpected child process '{child}'"
                ))
    return alerts


# Process execution by unusual users --> SKIPPING IT FOR NOW, no genuine userbase to baseline against

# Unsigned/suspicious executables --> SKIPPING for now, only reliably available on Event ID 7 (ImageLoaded),
# which fires per-DLL rather than per-process — needs a proper join against process_created before it's usable.


def execution_of_newly_created_files(events, window_minutes=5):
    file_creates = [e for e in events if e.get("type") == "file_created" and e.get("target_filename")]
    process_creates = [e for e in events if e.get("type") == "process_created" and e.get("process")]

    alerts = []
    for pc in process_creates:
        pc_time = _parse_ts(pc.get("timestamp"))
        if not pc_time:
            continue
        for fc in file_creates:
            if fc.get("target_filename") != pc.get("process"):
                continue
            fc_time = _parse_ts(fc.get("timestamp"))
            if not fc_time:
                continue
            gap = pc_time - fc_time
            if timedelta(0) <= gap <= timedelta(minutes=window_minutes):
                alerts.append(make_alert(
                    "execution_of_newly_created_file", "medium", pc,
                    f"'{extract_filename(pc.get('process'))}' was created and executed within {gap}"
                ))
                break
    return alerts


def execution_from_network_share(events):
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue
        process = e.get("process")
        if process and process.startswith("\\\\"):
            alerts.append(make_alert(
                "execution_from_network_share", "medium", e,
                f"Process executed from network share: {process}"
            ))
    return alerts


def execution_from_non_c_drive(events):
    # weak signal on its own — a non-C drive letter could be another internal
    # disk or a mapped network drive, not necessarily removable media.
    alerts = []
    for e in events:
        if e.get("type") != "process_created":
            continue
        process = e.get("process")
        if process and len(process) >= 2 and process[1] == ":" and process[0].upper() != "C":
            alerts.append(make_alert(
                "execution_from_non_c_drive", "low", e,
                f"Process executed from non-C drive: {process}"
            ))
    return alerts

def run_detections_process(events):
    rule_functions = [
        process_from_suspicious_paths,
        executable_from_suspicious_paths,
        suspicious_command_line,
        suspicious_parent_child,
        unexpected_system_process,
        system_process_unusual_children,
        execution_from_non_c_drive,
        execution_of_newly_created_files,
        execution_from_network_share
    ]

    all_alerts = []
    for fn in rule_functions:
        result = fn(events)
        all_alerts.extend(result)
    return all_alerts