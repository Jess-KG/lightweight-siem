from .authentication_rules import run_detections
from .process_execution_rules import run_detections_process
from .powershell_rules import run_detections_powershell
def detect_alerts(events):
    all_alerts = []
    major_alerts = [
        run_detections,
        run_detections_process,
        run_detections_powershell
    ]
    for fn in major_alerts:
        all_alerts.extend(fn(events))
    return all_alerts