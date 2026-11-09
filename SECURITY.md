# Security policy

## Status

Kshatriya is a pre-release **prototype**. It is not supported for production use and does not replace
Microsoft Defender or any other security product. Keep Microsoft Defender turned on.

## Reporting a vulnerability

Report suspected vulnerabilities **privately**:

- Preferred: GitHub's private vulnerability reporting ("Report a vulnerability" on the repository's
  Security tab, which creates a private security advisory).
- Do not open public issues or pull requests for security problems.

Please include the affected version (`kshatriya version`) or commit, reproduction steps, the impact you
observed and whether you believe it is being exploited.

### What to expect (prototype targets, best effort)

| Step | Target |
|---|---|
| Acknowledge the report | 3 working days |
| Initial assessment and severity | 10 working days |
| Fix or mitigation for high/critical issues | 30 days, or sooner if exploited |
| Coordinated public disclosure | After a fix is available, normally within 90 days of the report |

Reporters are credited in the advisory unless they ask not to be. We will not take legal action
against good-faith research that respects users' data and these guidelines.

### In scope

Sandbox escapes from `Kshatriya.Worker`; privilege escalation or confused-deputy issues through the
service pipe; bypassing quarantine, restore, exclusion or audit controls; forging or replaying content
packages; crashes or hangs triggered by scanned files; anything that lets Kshatriya weaken Windows
security. Out of scope: detection misses of a prototype with no shipped threat content, and findings
that require an attacker who is already an administrator (unless they defeat a documented control).

## Ground rules for contributors

- This is a **defensive** product. Do not add stealth, evasion, credential access, exploit delivery, or monitoring that the device owner has not consented to.
- Never disable, weaken or add exclusions to Microsoft Defender or other Windows security controls, in code, scripts, tests, or documentation.
- **Never commit live malware.** Tests use the EICAR string assembled in memory and generated benign files. Real samples are handled only in isolated, offline analysis VMs and are referenced by hash.
- Never commit signing keys or certificates. Content and release signing keys stay with their owners.
- Code that parses untrusted content must handle malformed input without crashing, enforce size and time limits, and never follow links or write to paths derived from that content. Fuzz parsers before changing them.
