# Lab 25 — Phishing → Endpoint Execution Investigation

## Overview

This lab investigates whether available endpoint telemetry can help establish a relationship between a potential phishing entry point and subsequent system activity. The investigation uses Elastic Security, Sysmon events, and ES|QL to examine process execution, process relationships, and network connections.

Phishing investigations require more than identifying a suspicious process or network connection. A defensible assessment must establish what the available evidence actually shows and whether the events can be linked to a suspected initial access technique.

## Investigation Objectives

- Examine Windows process-creation telemetry using ES|QL.
- Investigate potential relationships between Office applications and child processes.
- Review process execution details, including executable paths, command lines, users, and timestamps.
- Examine Sysmon network connection events and identify the processes associated with observed connections.
- Investigate missing parent-process information and empty query results.
- Distinguish endpoint observations from unverified phishing hypotheses.
- Document evidence limitations and identify the additional telemetry required to reconstruct an incident.

## Lab Environment

- **Platform:** Elastic Security
- **Query language:** ES|QL
- **Data view:** `logs-*`
- **Endpoint:** `desktop-9mmm37v`
- **Operating system:** Windows 11
- **Telemetry:** Windows Sysmon Operational events
- **Agent policy:** `Windows-SOC-Lab`

## Investigation Workflow

1. Verify that endpoint process and network telemetry is available.
2. Search general process-creation events and inspect the available execution context.
3. Search for processes whose recorded parent is a Microsoft Office application.
4. Review network connection events and identify the associated processes.
5. Compare timestamps and process identifiers where available.
6. Investigate missing fields and empty results without assuming that the underlying activity did not occur.
7. Document verified observations, unresolved questions, and the additional evidence needed to establish a phishing-to-execution sequence.

## Key Observations

The initial investigation produced the following results:

- The general process query returned 100 records, including `powershell.exe` running as `SYSTEM`.
- Some process records contained missing command-line or parent-process information.
- The Office-parent process query returned zero documents.
- The Sysmon network connection query returned 123 records.
- Network records included connections from `Zoho Mail - Desktop.exe` to `169.148.149.13`.

These observations demonstrate that process and network events were available for analysis. They do not independently confirm phishing, malicious execution, or a relationship between the observed network connections and a phishing event.

## Evidence and Limitations

The investigation must distinguish between endpoint activity and the initial phishing event.

Sysmon process-creation events can help establish which processes were recorded, while network connection events can provide information about observed connections. However, email delivery, user clicks, attachment downloads, and document opening require suitable supporting telemetry.

An empty Office-parent query does not prove that Office applications never executed. Missing parent-process fields also limit the ability to reconstruct process relationships.

## Expected Outcome

The objective is to determine what the available telemetry establishes about endpoint execution and network activity, whether a phishing-related sequence can be supported, and which evidence gaps prevent a stronger conclusion.

The investigation must not classify the endpoint as compromised solely because PowerShell was observed, a network connection occurred, or a query returned no matching records.

## Conclusion

A phishing-to-endpoint investigation requires correlation across multiple evidence sources. Process and network events can provide valuable investigative leads, but the connection between an initial access event and subsequent execution must be demonstrated rather than assumed.
