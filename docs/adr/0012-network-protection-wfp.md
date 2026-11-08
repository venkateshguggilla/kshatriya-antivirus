# ADR 0012: Network protection with user-mode WFP filters

- Status: accepted (M10)
- Date: 2026-11-08

## Context

Blocking connections to known command-and-control or malware-hosting addresses complements file
scanning. The Windows Filtering Platform (WFP) management API (`fwpuclnt.dll`) lets a user-mode service
add filters without a driver (no callout, no kernel code).

## Decision

- **Filters:** one block filter per entry at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` (outbound connection
  authorization), matching `FWPM_CONDITION_IP_REMOTE_ADDRESS` (exact address or address/mask). GUIDs,
  struct layouts and constants are taken from the Windows SDK headers (`fwpmu.h`, `fwpmtypes.h`,
  `fwptypes.h`, 10.0.26100.0); a test checks the x64 struct sizes against those definitions.
- **Dynamic session** (`FWPM_SESSION_FLAG_DYNAMIC`): all filters disappear when the session closes,
  including on a crash. The failure mode is *fail open* (connections allowed), never a stranded machine.
  Updates replace all filters in one WFP transaction.
- **Blocklists** come only from signed content (`*.netblock`, header `# sentinel-netblock v1`, one
  `address[/prefix] name` per line). Guardrails reject unspecified, loopback, link-local and multicast
  addresses and ranges broader than /16 (IPv4) or /48 (IPv6); one bad line rejects the package.
- **Opt-in:** `networkProtection: true` in `service.json`. Status reports `blocking N address range(s)`,
  `on (no blocklist installed)` or `unavailable: …` (for example without administrator rights).

## Consequences

- IP-based only: no domain, URL or TLS-SNI filtering (that needs DNS integration or a callout driver).
  Attackers can rotate addresses; blocklists age quickly.
- Blocked connections fail with "access denied" in the application; Sentinel does not yet surface a
  per-connection notification (WFP net-event subscription is future work).
- No blocklist is published by this project.
