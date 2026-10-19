# SOC Event Correlation and Incident Investigation Lab

## Overview

This project demonstrates a beginner-level Security Operations Center (SOC) investigation using simulated authentication and endpoint events.

The objective is to correlate related security events, build an incident timeline, identify suspicious authentication patterns, and document findings without treating suspicious activity as confirmed compromise.

## Investigation Scenario

The simulated dataset contains 12 security events involving several users and Windows hosts.

The correlation script identifies groups containing at least three failed logins followed by a successful logon, using the username, source IP address, and hostname to group related events.

## Key Findings

The analysis identified a potential authentication incident involving:

- Account: `jsmith`
- Host: `WIN-CLIENT07`
- Source IP: `203.0.113.50`
- Failed logins: 5
- Successful logon: 08:02:03
- Subsequent recorded activity: PowerShell execution and process creation

The events warrant further investigation but do not independently prove account compromise.

## Tools and Technologies

- Kali Linux
- Python 3
- CSV event data
- Linux terminal
- Git and GitHub

## Project Structure

```text
Day11-SOC-Event-Correlation/
├── data/
│   └── authentication_events.csv
├── evidence/
│   ├── correlation_output.txt
│   └── incident_investigation_report.md
├── screenshots/
├── scripts/
│   └── correlate_events.py
└── README.md
## Skills Demonstrated

- Security event correlation
- Authentication pattern analysis
- Timeline construction
- Python CSV processing
- Basic detection logic
- Incident documentation
- Evidence-based reporting
- Distinguishing observations from assumptions

## How to Run

From the project root directory, run:

    python3 scripts/correlate_events.py

To save the output:

    python3 scripts/correlate_events.py | tee evidence/correlation_output.txt

## Limitations

This project uses simulated data and a basic correlation heuristic. It does not connect to a live SIEM or prove malicious activity.

The source IP addresses are reserved for documentation examples.

## Future Improvements

- Add configurable detection thresholds.
- Add time-window-based correlation.
- Include automated tests and malformed-data handling.
- Extend the investigation with additional Windows event fields.
