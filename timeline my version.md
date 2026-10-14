# Investigation Timeline 

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

