# test_loader.py
#
# Reads test_security_events.xml (synthetic test data — NOT a real binary .evtx)
# and feeds it through your existing Event model + normalizer + detector,
# without needing python-evtx / a real binary EVTX file.
#
# Usage:
#   Place this file anywhere in your project (e.g. src/siem/), adjust the
#   import paths below to match your actual package layout, then run:
#       python test_loader.py
#
# This mimics what open_evtx() gives you (a generator of Event objects) —
# so everything downstream (normalize, detect) works exactly the same way
# it would against a real EVTX file.

import xml.etree.ElementTree as ET

# --- adjust these imports to match your project structure ---
# from src.siem.models.event import Event
# from src.siem.normalizer.normalizer import normalize
# from src.siem.detection.detector import run_detections

from .normalizer.normalizer import normalize
from .detection.detection_v2 import detect_alerts

class Event:
    def __init__(self, event_id, timestamp, computer, event_data, provider=None):
        self.event_id = event_id
        self.timestamp = timestamp
        self.computer = computer
        self.event_data = event_data
        self.provider = provider


def load_test_events(xml_file):
    """
    Parses the synthetic multi-<Event> XML file and yields Event objects,
    using the exact same parsing logic as your real collector.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()  # <Events> wrapper

    for event_elem in root:  # each child is one <Event>
        event = Event(event_id=None, timestamp=None, computer=None, event_data=None, provider=None)
        system = None
        event_data = None

        for child in event_elem:
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "System":
                system = child
            elif tag in ("EventData", "UserData"):
                event_data = child

        for child in system:
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "Provider":
                event.provider = child.attrib.get("Name")
            elif tag == "EventID":
                event.event_id = child.text
            elif tag == "TimeCreated":
                event.timestamp = child.attrib.get("SystemTime")
            elif tag == "Computer":
                event.computer = child.text

        if event_data is not None:
            event.event_data = {}
            for child in event_data:
                tag = child.tag.rsplit("}", 1)[-1]
                if tag == "Data":
                    name = child.attrib.get("Name", "Value")
                    event.event_data[name] = child.text

        yield event


if __name__ == "__main__":
    raw_events = list(load_test_events(
        "src\\siem\\data\\raw_logs\\test_security_events.xml"
    ))

    print(f"Loaded {len(raw_events)} raw test events")

    print("Normalizing events...")

    normalized_count = 0
    not_normalized_count = 0
    normalized_events = []

    for event in raw_events:
        normalized_event = normalize(event)

        if normalized_event:
            normalized_count += 1
            normalized_events.append(normalized_event)
        else:
            not_normalized_count += 1

    print(
        f"Normalization complete. "
        f"Normalized events: {normalized_count}, "
        f"Not normalized events: {not_normalized_count}"
    )

    print("Detecting alerts...")

    alerts = detect_alerts(normalized_events)

    print("Detection complete")

    if len(alerts) > 0:
        for alert in alerts:
            print(f"[{alert['severity'].upper()}] {alert['rule']}")
            print(f"  Time:     {alert['timestamp']}")
            print(f"  Computer: {alert['computer']}")
            print(f"  Message:  {alert['message']}")
            print()
    else:
        print("No alerts detected")
