import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
from ..models.event import Event

# src/siem/collector/collector.py
def open_evtx(input_file):
    with evtx.Evtx(input_file) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue

            event = Event(event_id=None, timestamp=None, computer=None, event_data=None, provider=None)
            system = None
            event_data = None

            for child in root:
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