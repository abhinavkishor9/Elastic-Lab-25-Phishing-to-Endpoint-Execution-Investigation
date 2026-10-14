# Investigation Timeline — Lab 25

## Investigation Scope

- **Date:** October 14, 2026
- **Endpoint:** `desktop-9mmm37v`
- **Platform:** Elastic Security
- **Telemetry:** Windows Sysmon Operational events
- **Observed query time range:** Last 15 minutes

This timeline records the observed investigation activity. The timestamps below reflect event timestamps or query observations explicitly available in the captured results. They must not be interpreted as proof of a single attack sequence.

## Timeline

| Timestamp | Evidence Source | Observation | Assessment |
|---|---|---|---|
| 06:29:33.119 | Process creation | A PowerShell process was recorded under `SYSTEM`. | Execution observed; purpose and parent process not established. |
| 06:29:38.149 | Process creation | A PowerShell record contained a partially visible command line beginning with `powershell.exe -NoProfile -...`. | Full command and execution context require validation. |
| 06:29:38.244 | Process creation | A PowerShell process was recorded under `SYSTEM`; the displayed parent-process and command-line values were missing. | Parent-child relationship remains unknown for this record. |
| 06:30:32.246 | Network connection | `Zoho Mail - Desktop.exe`, PID `15892`, was associated with a connection to `169.148.149.13`. | Connection observed; destination purpose and security significance not established. |
| 06:30:40.003 | Process creation | A PowerShell record appeared in the general process results. | Additional context is needed to assess this event. |
| 06:32:41.714 | Network connection | `Zoho Mail - Desktop.exe`, PID `15892`, was associated with another connection to `169.148.149.13`. | A second connection was observed; maliciousness is not established. |

## Query Execution Results

| Investigation Step | Result | Interpretation |
|---|---|---|
| General process search | 100 records returned | Process telemetry was available for analysis. |
| Office-parent process search | 0 documents processed | No matching records were returned by the query. |
| Network connection search | 123 records returned | Network connection telemetry was available for analysis. |

## Timeline Assessment

The observed events establish that PowerShell process activity and network connections associated with `Zoho Mail - Desktop.exe` were present in the available telemetry.

The current timeline does not establish that these events belong to the same incident. No confirmed phishing email, malicious attachment, user click, or causal relationship between the observed processes has been demonstrated.

## Outstanding Actions

- Validate missing parent-process and command-line fields.
- Recheck the Office-parent query against the actual event schema and time range.
- Investigate the network destination if required and document the source used.
- Obtain relevant email or browser evidence if available.
- Update the timeline only when additional observations are supported by actual event records.
