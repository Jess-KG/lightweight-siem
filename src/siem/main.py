from .collector.collector import open_evtx
from .normalizer.normalizer import normalize
from .detection.detection_v2 import detect_alerts
import csv
import json
import os

def main():
    print("Starting SIEM Collector...")
    input_file = "src/siem/data/raw_logs/security.evtx"

    print(f"Opening EVTX file: {input_file}")
    events = open_evtx(input_file)

    #list of unique event IDs
    # unique_event_ids = set(event.event_id for event in events)
    # print(f"Unique Event IDs: {unique_event_ids}")

    print("Normalizing events...")
    
    normalized_count = 0
    not_normalized_count = 0

    normalized_events = []
    for event in events:
        # print(event)
        normalized_event = normalize(event)
        if normalized_event:
            normalized_count += 1
            normalized_events.append(normalized_event)
        else:
            not_normalized_count += 1
        
    print(f"Normalization complete. Normalized events: {normalized_count}, Not normalized events: {not_normalized_count}")

    # Store normalized events in CSV
    print("Storing normalized events in CSV...")
    store_in_csv(normalized_events)

    #fetching alerts
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

def store_in_csv(events):
    csv_file = "src/siem/data/processed/normalized_events.csv"

    csv_ready_events = [
        {k: v for k, v in event.items() if k != "data"}
        for event in events
    ]

    common_field_names = ["event_id", "timestamp", "computer", "type", "provider"]
    for event in csv_ready_events:
        for key in event.keys():
            if key not in common_field_names:
                common_field_names.append(key)

    write_header = not os.path.exists(csv_file) or os.path.getsize(csv_file) == 0

    with open(csv_file, mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=common_field_names, extrasaction='ignore')
        if write_header:
            writer.writeheader()
        for event in csv_ready_events:
            writer.writerow(event)

if __name__ == "__main__":
    main()