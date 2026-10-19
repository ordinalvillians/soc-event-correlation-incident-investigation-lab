# SOC Event Correlation and Incident Investigation

## 1. Investigation Overview

This lab investigates a simulated sequence of authentication and host activity events.

The objective was to correlate events using timestamps, usernames, source IP addresses, and hostnames to identify activity requiring further investigation.

All records in this exercise are simulated.

## 2. Data Source and Method

The investigation used `data/authentication_events.csv`, containing 12 security events.

A Python script parsed the CSV, converted timestamps into datetime values, sorted the events chronologically, and grouped related activity by username, source IP, and hostname.

The script flagged groups containing at least three failed logins and a subsequent successful logon.

## 3. Key Findings

The script identified a potential authentication incident involving:

- Username: `jsmith`
- Source IP: `203.0.113.50`
- Host: `WIN-CLIENT07`
- Failed logins: 5
- Successful logon: 2026-10-20 08:02:03

Five failed logins occurred between 08:01:12 and 08:01:42.

A successful logon followed at 08:02:03.

PowerShell execution was recorded at 08:03:15, followed by a process creation event at 08:04:21.

These events share the same account, source IP, and hostname in the simulated dataset.

## 4. Incident Timeline

| Time | Event | Observation |
|---|---|---|
| 08:01:12 | Logon Failure | First recorded failure |
| 08:01:19 | Logon Failure | Second recorded failure |
| 08:01:27 | Logon Failure | Third recorded failure |
| 08:01:34 | Logon Failure | Fourth recorded failure |
| 08:01:42 | Logon Failure | Fifth recorded failure |
| 08:02:03 | Successful Logon | Authentication succeeded |
| 08:03:15 | PowerShell Execution | PowerShell activity recorded |
| 08:04:21 | Process Created | Process creation recorded |

## 5. Analyst Assessment

The sequence is suspicious because multiple authentication failures were followed by successful authentication and subsequent host activity.

However, the available records do not establish whether the activity was authorised, whether the account was compromised, or whether the PowerShell and process events were malicious.

The source IP belongs to a documentation-reserved range and is used here only for simulation.

## 6. Recommended Follow-up Actions

1. Review the authentication method and available authentication details.
2. Examine surrounding Windows security events for additional context.
3. Inspect PowerShell command-line details and process execution metadata.
4. Check whether the account owner expected the login.
5. Correlate the activity with endpoint detection alerts, if available.
6. Escalate according to the organisation's incident response procedure if further evidence supports suspected compromise.

## 7. Limitations

- The dataset is simulated and does not represent a live security incident.
- No production SIEM or endpoint telemetry was queried.
- The process and PowerShell events contain no command-line or parent-process details.
- The correlation rule is a basic detection heuristic and may produce false positives.
- The findings do not prove malicious activity or account compromise.

## 8. Conclusion

The exercise demonstrated how authentication failures, successful logons, and subsequent host activity can be correlated into a preliminary investigation timeline.

The analysis identified a pattern warranting further review while distinguishing observed events from unverified conclusions.

## 9. Evidence

- `data/authentication_events.csv`
- `scripts/correlate_events.py`
- `evidence/correlation_output.txt`
