# Elastic-Lab-25-Phishing-to-Endpoint-Execution-Investigation
## Overview
A phishing attack may begin with a deceptive email or attachment and progress to activity on a user's endpoint. If a user opens a malicious attachment or follows a harmful link, the resulting activity may involve document execution, script interpreters, suspicious child processes, or other system changes.
The investigation follows this sequence:
Phishing indicator → User interaction evidence → Process execution → Related endpoint activity → Evidence-based assessment
Not every stage will necessarily be visible in the available logs. Sysmon can provide endpoint evidence, such as process creation and network connections, but it does not independently establish that an email was delivered, opened, or clicked. Those claims require appropriate email, browser, or other supporting telemetry.

This lab investigates whether available endpoint telemetry can help establish a relationship between a potential phishing entry point and subsequent system activity. The investigation uses Elastic Security, Sysmon events, and ES|QL to examine process execution, process relationships, and network connections.

Phishing investigations require more than identifying a suspicious process or network connection. A defensible assessment must establish what the available evidence actually shows and whether the events can be linked to a suspected initial access technique.

# Lab Objectives

- Investigate endpoint telemetry to identify process activity that may be relevant to a suspected phishing incident.
- Analyze Windows process-creation events to understand executable behavior, user context, and execution timestamps.
- Examine parent-child process relationships to identify potential links between document-handling applications and script interpreters.
- Investigate PowerShell execution by reviewing available command-line arguments, executable paths, and process identifiers.
- Analyze Sysmon network connection events to identify associated processes, destination IP addresses, and connection timestamps.
- Correlate process and network events using available timestamps and identifiers without assuming that nearby events share a common cause.
- Troubleshoot missing process details and empty query results by validating field mappings, time ranges, and telemetry availability.
- Identify the additional email, browser, or endpoint evidence needed to establish whether phishing led to execution.
- Document confirmed observations, plausible hypotheses, and unresolved evidence gaps in a chronological investigation record.
- Produce an evidence-based assessment that distinguishes suspicious activity from confirmed malicious behavior.

# Lab Scenario

A security analyst is examining Windows endpoint activity to determine whether the available telemetry reveals a possible connection between a phishing attempt and subsequent process execution. The investigation uses Elastic Security and Sysmon logs to examine process activity, execution context, and network connections on the endpoint.

During the investigation, the analyst observes PowerShell processes running under the `SYSTEM` account. Some records contain incomplete command-line information or lack visible parent-process details. A separate search for processes whose parent is Microsoft Office returns no matching documents, while the network investigation identifies connections associated with `Zoho Mail - Desktop.exe` to `169.148.149.13`.

The analyst must investigate these observations without assuming they represent a single attack. The investigation focuses on:
- Examining process execution details and identifying missing evidence.
- Validating parent-child process relationships using available telemetry.
- Reviewing network connections and their associated processes.
- Investigating empty query results and potential data-collection limitations.
- Determining whether the available evidence supports a connection to a phishing event.

The investigation must establish what the collected events demonstrate, what remains uncertain, and which additional data sources—such as email security logs, browser activity, or complete process-creation records—would be needed to reconstruct the suspected attack sequence.

The expected outcome is an evidence-based investigation report with a chronological timeline, documented findings, and a clear assessment of the limitations. The analyst must not conclude that phishing caused endpoint execution or that the endpoint is compromised unless the available evidence supports that conclusion.
  
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

