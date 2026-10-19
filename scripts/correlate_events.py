import csv
from collections import defaultdict
from datetime import datetime

INPUT_FILE = "data/authentication_events.csv"

events = []

with open(INPUT_FILE, newline="", encoding="utf-8") as file:
    reader = csv.DictReader(file)
    for row in reader:
        row["timestamp"] = datetime.strptime(
            row["timestamp"], "%Y-%m-%d %H:%M:%S"
        )
        events.append(row)

events.sort(key=lambda event: event["timestamp"])

groups = defaultdict(list)

for event in events:
    key = (
        event["username"],
        event["source_ip"],
        event["hostname"],
    )
    groups[key].append(event)

print("SOC EVENT CORRELATION REPORT")
print("=" * 60)
print(f"Total events analysed: {len(events)}")

for key, related_events in groups.items():
    failures = [
        event for event in related_events
        if event["event_type"] == "Logon Failure"
    ]

    successes = [
        event for event in related_events
        if event["event_type"] == "Successful Logon"
    ]

    if len(failures) >= 3 and successes:
        first_failure = failures[0]["timestamp"]
        successful_logon = successes[0]["timestamp"]

        if successful_logon > first_failure:
            username, source_ip, hostname = key

            print("\nPOTENTIAL AUTHENTICATION INCIDENT")
            print(f"Username: {username}")
            print(f"Source IP: {source_ip}")
            print(f"Host: {hostname}")
            print(f"Failed logins: {len(failures)}")
            print(
                "First failure: "
                f"{first_failure.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            print(
                "Successful logon: "
                f"{successful_logon.strftime('%Y-%m-%d %H:%M:%S')}"
            )

            print("Related events:")
            for event in related_events:
                print(
                    f"  {event['timestamp'].strftime('%H:%M:%S')} | "
                    f"{event['event_type']} | {event['result']}"
                )

print("\nAnalysis complete.")
print("Correlated patterns require further investigation.")
print("This simulated dataset does not prove account compromise.")
