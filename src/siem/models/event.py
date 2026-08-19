class Event:
    def __init__(self, event_id, timestamp, computer, event_data):
        self.event_id = event_id
        self.timestamp = timestamp
        self.computer = computer
        self.event_data = event_data

    def __str__(self):
        return f"Event ID: {self.event_id} \n , Timestamp: {self.timestamp} \n , Computer: {self.computer} \n, Event Data: {self.event_data} \n\n"