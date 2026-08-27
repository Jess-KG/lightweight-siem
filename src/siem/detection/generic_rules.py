from datetime import datetime, timedelta
from collections import defaultdict


def make_alert(rule, severity, event, message):
    return {
        "rule": rule,
        "severity": severity,
        "timestamp": event.get("timestamp"),
        "computer": event.get("computer"),
        "message": message,
    }

def _parse_ts(ts_str):
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


def detect_count_threshold_breach(events, event_type, group_by, threshold, window_minutes, rule_name, severity = "medium"):
    #first we want to find all events that are of that particular event type and have that group_by parameter
    related_events = []

    for event in events:
        if event.get("type") == event_type and event.get(group_by) is not None:
            related_events.append(event)
    
    #now we have all the related events.
    
    grouped = defaultdict(list)

    for r in related_events:
        timestamp = _parse_ts(r["timestamp"])
        if timestamp is not None:
            grouped[r[group_by]].append((timestamp, r))
    
    alerts = []

    for key, items in grouped.items():
        items.sort(key= lambda x : x[0])
        for i in range(len(items)):
            window_start = items[i][0] #this is the timestamp to compare with
            window_events = []
            for j in items[i:]:
                time_diff = j[0] - window_start
                time_diff_seconds = time_diff.total_seconds()
                if time_diff_seconds <= window_minutes * 60:
                    window_events.append(j)

            if len(window_events) >= threshold:
                alerts.append({
                    "rule": rule_name,
                    "severity": severity,
                    "timestamp": window_events[-1][1].get("timestamp"),
                    "computer": window_events[-1][1].get("computer"),
                    "message": f"{rule_name}: {len(window_events)} '{event_type}' events for {group_by}='{key}' within {window_minutes}min",
                    "group_key": key,
                    "count": len(window_events),
                })
                break

    return alerts

def detect_distinct_count_threshold_breach(events, event_type, group_by, distinct_field, threshold, window_minutes, rule_name, severity = "medium"):
    '''
    This will be used to detect events like password spraying
    '''
    related_events = []

    for event in events:
        if event.get("type") == event_type and event.get(group_by) is not None:
            related_events.append(event)

    grouped = defaultdict(list)

    for r in related_events:
        ts = _parse_ts(r.get("timestamp"))
        if ts is not None:
            grouped[r[group_by]].append((ts, r))

    alerts = []

    for key, items in grouped.items():
        items.sort(key= lambda x : x[0])
        for i in range(len(items)):
            window_start = items[i][0]
            window_events = []
            for j in items[i:]:
                time_diff = j[0] - window_start
                time_diff_seconds = time_diff.total_seconds()
                if time_diff_seconds <= window_minutes * 60:
                    window_events.append(j)
            
            distinct_values = []
            for e in window_events:
                event = e[1]
                if event.get(distinct_field) not in distinct_values:
                    distinct_values.append(event.get(distinct_field))

            if len(distinct_values) >= threshold:
                alerts.append({
                    "rule": rule_name,
                    "severity": severity,
                    "timestamp": window_events[-1][1].get("timestamp"),
                    "computer": window_events[-1][1].get("computer"),
                    "message": f"{rule_name}: {group_by}='{key}' hit {len(distinct_values)} distinct {distinct_field} values within {window_minutes}min",
                    "group_key": key,
                    "count": len(window_events),
                })
                break

    return alerts

def join_events_by_process_guid(events_a, events_b, guid_field_a, guid_field_b,
                                  window_minutes, condition_fn, rule_name, severity, message_fn):
    alerts = []
    for a in events_a:
        guid_a = a.get(guid_field_a)
        time_a = _parse_ts(a.get("timestamp"))
        if not guid_a or not time_a:
            continue
        guid_a = guid_a.lower()

        for b in events_b:
            guid_b = b.get(guid_field_b)
            time_b = _parse_ts(b.get("timestamp"))
            if not guid_b or not time_b:
                continue
            if guid_b.lower() != guid_a:
                continue
            if not condition_fn(b):
                continue

            gap = time_b - time_a
            if timedelta(0) <= gap <= timedelta(minutes=window_minutes):
                alerts.append(make_alert(rule_name, severity, b, message_fn(a, b, gap)))
                break
    return alerts