# Troubleshooting Notes — Lab 25

## 1. Office-Parent Query Returns Zero Documents

### Symptom

The query filtering for Sysmon Event ID 1 and Office parent processes returned zero documents processed.

### Query Used

```esql
FROM logs-*
| WHERE event.code == "1"
  AND process.parent.name IN (
    "WINWORD.EXE",
    "EXCEL.EXE",
    "POWERPNT.EXE",
    "OUTLOOK.EXE"
  )
| KEEP @timestamp, host.name, user.name,
       process.parent.name, process.parent.executable,
       process.name, process.executable,
       process.command_line, process.pid,
       process.parent.pid
| SORT @timestamp DESC
| LIMIT 200
```

### Troubleshooting Steps

1. Confirm the selected time range includes the period under investigation.
2. Check whether `event.code` is available and contains the expected value for process-creation events.
3. Inspect actual values in `process.parent.name`.
4. Search process-creation events without the Office-parent filter.
5. Verify that the relevant Sysmon data is present in `logs-*`.
6. Add filters incrementally and record the result count after each change.

### Important Limitation

Zero results do not establish that Office applications never executed. The cause of the empty result remains unconfirmed.

## 2. Missing Parent-Process Information

### Symptom

Some PowerShell records returned by the general process query did not contain a visible value for `process.parent.name`.

### Troubleshooting Steps

1. Open the complete event in Discover.
2. Inspect the raw event and determine whether parent-process fields are present.
3. Verify the actual field names used by the event.
4. Check whether the relevant process-creation event contains parent-process details.
5. Compare nearby records using timestamps and process identifiers where available.

### Important Limitation

Do not infer a parent process from temporal proximity alone. If the required information is unavailable, record the relationship as unknown.

## 3. Incomplete Command-Line Evidence

### Symptom

Some PowerShell records contained no visible command line, while another displayed only a truncated command.

### Troubleshooting Steps

1. Inspect the complete event in Discover.
2. Verify whether `process.command_line` contains a value.
3. Check whether the complete command is available in the raw event.
4. Review related process-creation events where a reliable relationship can be established.
5. Record any remaining gaps.

### Important Limitation

The process name `powershell.exe` does not establish that the process executed malicious commands. An incomplete command line is insufficient to determine the process's purpose.

## 4. Network Events Require Context

### Observation

The network query returned 123 documents, including events associated with `Zoho Mail - Desktop.exe` and destination IP `169.148.149.13`.

### Troubleshooting Steps

1. Inspect the complete event and verify the source and destination fields.
2. Record the timestamp, process ID, destination IP, destination port, and any available domain.
3. Review related network events for the same process where appropriate.
4. Check destination reputation using an approved source if required.
5. Correlate network events with process activity only when the available evidence supports the relationship.

### Important Limitation

A network connection is not proof of command-and-control communication, data exfiltration, or malicious activity. The destination's reputation and purpose remain unverified in the current findings.

## 5. General Process Query Returns Records

### Observation

The general process query returned 100 records, including PowerShell execution under `SYSTEM`.

### Troubleshooting Steps

1. Inspect the full process record.
2. Validate the timestamp, host, user, executable path, and command line.
3. Determine whether the parent process is available.
4. Review related events before classifying the activity.
5. Record the actual evidence and any unresolved questions.

