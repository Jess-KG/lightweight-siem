import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
from ..models.event import Event

def open_evtx(input_file):

    with evtx.Evtx(input_file) as log:

        for record in log.records():
            event = Event(event_id=None, timestamp=None, computer=None, event_data=None)
            root = ET.fromstring(record.xml())

            system = None
            event_data = None

            # Get the two main children of Event
            for child in root:
                tag = child.tag.rsplit("}", 1)[-1] 
                if tag == "System":
                    system = child
                elif tag in ("EventData", "UserData"):  # see point 4
                    event_data = child

            # -------------------------
            # System information
            # -------------------------

            for child in system:

                if "EventID" in child.tag:
                    event.event_id = child.text

                elif "TimeCreated" in child.tag:
                    event.timestamp = child.attrib["SystemTime"]

                elif "Computer" in child.tag:
                    event.computer = child.text

            # -------------------------
            # Event-specific information
            # -------------------------

            if event_data is not None:
                event.event_data = {}
                for child in event_data:
                    if "Data" in child.tag:
                        name = child.attrib.get("Name")
                        value = child.text
                        event.event_data[name] = value
            yield event


