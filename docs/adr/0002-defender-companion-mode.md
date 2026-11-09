# ADR 0002: Run in companion mode alongside Microsoft Defender

- Status: Accepted (2026-11-08)

## Context

Microsoft documents that a non-Microsoft antivirus registering through the Windows Security Center (WSC) API causes Microsoft Defender Antivirus to turn off on Windows clients, after which Defender stops receiving updates ([Defender compatibility without MDE](https://learn.microsoft.com/en-us/defender-endpoint/defender-antivirus-compatibility-without-mde)). Since Windows 10 RS5 / LTSC 2019, products must run as a protected process to register with WSC; products that do not register run side by side with an active Defender ([Windows Security app](https://learn.microsoft.com/en-us/windows/win32/devnotes/windows-security-center)). Protected-process status requires an ELAM driver signed by Microsoft ([ELAM overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware)), which in practice means Microsoft Virus Initiative membership.

A product rule for Kshatriya is that it must never disable or weaken Defender or other Windows protections.

## Decision

Kshatriya does **not** register with WSC as an antivirus provider. Defender stays fully enabled; Kshatriya provides additional scanning and protection features alongside it. Kshatriya never changes Defender settings, adds Defender exclusions, or instructs users to do so.

## Consequences

- Kshatriya does not appear as the antivirus provider in the Windows Security app.
- Two real-time scanners may both inspect new files; Kshatriya's real-time design (M7) must keep its overhead low and avoid interfering with Defender.
- Kshatriya cannot run as a protected process, so it cannot resist an administrator-level attacker; we state this plainly ([threat model](../threat-model.md), T14).
- Becoming a primary antivirus would require a new ADR and a business decision (MVI membership, ELAM, PPL).
