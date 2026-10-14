# Investigation Notes — Lab 25

## 1. General Process Activity

### Query

```esql
FROM logs-*
| WHERE process.name IS NOT NULL
| KEEP @timestamp, host.name, user.name,
       process.name, process.executable,
       process.command_line, process.parent.name
| SORT @timestamp DESC
| LIMIT 100
```

### Observed Results

The query processed 100 documents and returned 100 records.

One of the displayed records contained:

- **Timestamp:** October 14, 2026, 06:29:38.244
- **Host:** `desktop-9mmm37v`
- **User:** `SYSTEM`
- **Process:** `powershell.exe`
- **Executable path:** Under `C:\Windows\System32\WindowsPowerShell\...`
- **Command line:** Missing in the displayed record
- **Parent process:** Missing in the displayed record

Another PowerShell record at approximately 06:29:38.149 contained a command line beginning with `powershell.exe -NoProfile -...`, although the full command was not available in the extracted output.

### Assessment

PowerShell execution under the `SYSTEM` account is confirmed in the displayed telemetry. However, the available records do not establish the purpose of the execution, its initiating process, or whether it was malicious.

The missing parent-process and command-line values prevent a complete assessment of these individual records. Additional events and the full field values would be required to establish execution context.

## 2. Office-Parent Process Investigation

### Query

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

### Observed Result

The query returned zero documents. Elastic displayed zero documents processed for this query.

### Assessment

No records matched the query in the observed run. This does not prove that Office applications did not execute or that no suspicious child processes existed.

Possible explanations include an absence of matching activity in the selected period, differences in field values or mappings, missing parent-process information, or limitations in the collected telemetry. The available result does not identify which explanation applies.

Further validation is required before drawing conclusions about Office-related execution.

## 3. Network Connection Investigation

### Query

```esql
FROM logs-*
| WHERE event.code == "3"
| KEEP @timestamp, host.name, user.name,
       process.name, process.executable,
       process.pid, destination.ip,
       destination.port, destination.domain
| SORT @timestamp DESC
| LIMIT 200
```

### Observed Results

The query processed 123 documents and returned 123 records.

Two displayed records included:

- **Timestamp:** October 14, 2026, 06:32:41.714
- **Timestamp:** October 14, 2026, 06:30:32.246
- **Host:** `desktop-9mmm37v`
- **User:** `Dell`
- **Process:** `Zoho Mail - Desktop.exe`
- **Process ID:** `15892`
- **Destination IP:** `169.148.149.13`

The executable path was displayed under the user's local application directory, but the full path was truncated in the extracted output.

### Assessment

The records establish that `Zoho Mail - Desktop.exe` was associated with network connection events to `169.148.149.13` at the displayed timestamps.

The destination's ownership, reputation, and relationship to any phishing activity have not been established by these records. The observed connection alone does not demonstrate malicious communication, a successful phishing attack, or endpoint compromise.

## 4. Correlation Assessment

The current evidence establishes three separate observations:

1. Process-creation telemetry contains PowerShell activity running under `SYSTEM`.
2. The Office-parent process query returned no matching documents.
3. Network telemetry contains connections associated with `Zoho Mail - Desktop.exe`.

The available evidence does not yet connect these observations into a single incident sequence. In particular, no confirmed email delivery, user click, malicious attachment execution, or causal relationship between the observed processes has been established.

