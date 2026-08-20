class Event:
    def __init__(self, event_id, timestamp, computer, event_data, provider = None):
        self.event_id = event_id
        self.timestamp = timestamp
        self.computer = computer
        self.event_data = event_data
        self.provider = provider

    def __str__(self):
        return f"Event ID: {self.event_id} \n , Timestamp: {self.timestamp} \n , Computer: {self.computer} \n, Provider: {self.provider} \n,Event Data: {self.event_data} \n\n"