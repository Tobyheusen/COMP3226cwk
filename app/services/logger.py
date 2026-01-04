import csv
import time
import os

LOG_FILE = "experiment_results.csv"

# Initialize CSV with headers if it doesn't exist
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "event_type", "session_id", "outcome", "latency_ms"])

def log_event(event_type: str, session_id: str, outcome: str, latency_ms: int = 0):
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([time.time(), event_type, session_id, outcome, latency_ms])