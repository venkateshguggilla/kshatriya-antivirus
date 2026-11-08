# Security policy

## Status

Sentinel is a pre-release prototype. It is not supported for production use and does not replace Microsoft Defender or any other security product.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers rather than in a public issue. Include the affected version or commit, reproduction steps, and the impact you observed. A dedicated security contact and disclosure timeline will be published before the first beta.

## Ground rules for contributors

- This is a **defensive** product. Do not add stealth, evasion, credential access, exploit delivery, or monitoring that the device owner has not consented to.
- Never disable, weaken or add exclusions to Microsoft Defender or other Windows security controls, in code, scripts, tests, or documentation.
- **Never commit live malware.** Tests use the EICAR string assembled in memory and generated benign files. Real samples are handled only in isolated, offline analysis VMs and are referenced by hash.
- Code that parses untrusted content must handle malformed input without crashing, enforce size and time limits, and never follow links or write to paths derived from that content.
