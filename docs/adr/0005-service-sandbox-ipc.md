# ADR 0005: Service, sandboxed scan workers and authenticated pipe IPC

- Status: accepted (M3)
- Date: 2026-11-08

## Context

Milestone 3 moves scanning from a single CLI process to a long-running Windows service while
keeping untrusted-content parsing away from privileged code. The service runs as LocalSystem, so
three things must hold:

1. A parser bug triggered by a malicious file must not run code with the service's privileges.
2. A standard user must not be able to use the service to read files they cannot read themselves
   (confused deputy).
3. A local process must not be able to impersonate the service to clients, or the clients to the service.

## Decision

### Broker / worker split

- The broker (service or CLI) does everything that needs file access: enumeration, the safe open,
  hashing, Authenticode checks, the verdict cache. It then streams the **bytes** of each item to a
  worker over an anonymous pipe. Workers never receive a path they are expected to open.
- Workers (`Kshatriya.Worker.exe`) run the engines and archive expansion. Each is created with:
  - a restricted copy of the broker's token: `DISABLE_MAX_PRIVILEGE` (only SeChangeNotify left),
    BUILTIN\Administrators deny-only, mandatory label **low**;
  - a Job Object: kill on job close, one active process, per-process memory cap (1.5 GiB default),
    die on unhandled exception, all UI restrictions;
  - process mitigations: child-process creation blocked, extension points disabled, no remote or
    low-label images, no non-system fonts, heap terminate on corruption, bottom-up and high-entropy ASLR;
  - only its three standard handles inherited (explicit handle list), no console (`DETACHED_PROCESS`),
    and code-loading environment variables (startup hooks, profilers) stripped.
- The broker checks that each worker reports low integrity and refuses to scan otherwise.
- A worker that crashes, exceeds its memory cap, violates the protocol or is still running at the
  item deadline is killed and replaced. The item is reported `notScanned` (`engineError` or
  `timeout`); the scan continues.
- The CLI uses the same workers by default. `--no-sandbox` analyses in-process for development and
  benchmarking and is documented as less safe.

### Scanning as the caller

- The service identifies a client only through the pipe (`ImpersonateNamedPipeClient` via
  `RunAsClient`), never from anything the client sends.
- Each client-requested scan runs under `WindowsIdentity.RunImpersonatedAsync` with the caller's
  token, so every enumeration and open is checked against the caller's rights. Workers are always
  created as the service identity (impersonation is explicitly reverted around process creation).
- Clients therefore connect at the **Impersonation** level. A client that allows only
  Identification is refused. This replaces the Identification level sketched in the earlier
  plan, which would have forced the service to scan with its own (SYSTEM) rights.
- Only fully qualified local drive paths are accepted: no UNC, `\\?\`, device paths, alternate
  data streams or wildcards. At most 64 paths per request, and a cap on concurrent scans.
- Scheduled scans are configured by administrators and run as LocalSystem.

### Authenticating the peers

- **Server → client:** the pipe ACL denies network logons and gives Authenticated Users read/write
  but not `FILE_CREATE_PIPE_INSTANCE`. The service claims the name with
  `FILE_FLAG_FIRST_PIPE_INSTANCE` and refuses to start if it is taken, and keeps several listening
  instances so the name never becomes free while it runs.
- **Client → server:** before writing anything, the client checks the pipe server's process ID.
  In production it must equal the PID that the Service Control Manager reports for
  `KshatriyaService` (only administrators can install or reconfigure the service). In development
  (`--dev`) the server must run as the same user. Because the client writes nothing before this
  check, a squatting server cannot impersonate it: `ImpersonateNamedPipeClient` needs data to have
  been read first.

### Protocol

- Length-prefixed frames (`u32 length | u8 type | u32 jsonLength | json | binary`) with limits
  enforced before any allocation. Strict source-generated JSON DTOs: unknown members, missing
  required members and nulls are rejected. Enum values use explicit wire names.
- This replaces gRPC from the earlier plan. The message set is tiny, gRPC over named pipes would
  add a large dependency surface (ASP.NET Core/Kestrel in the service), and a hand-written framing
  layer is easier to bound and fuzz. Versioning is a protocol number in the handshake; a mismatch
  is refused (N-1 support is future work).

### Configuration trust

- Settings (`%ProgramData%\Kshatriya\config\service.json`) and any signature or rule files they
  name are refused unless only SYSTEM, Administrators or TrustedInstaller own them and can write
  them. In production the data directory gets a protected ACL: SYSTEM and Administrators full
  control, Users read.

## Consequences

- A parser compromise is contained to a low-integrity, privilege-less, single-process job that
  cannot write the user's files or start programs. **It can still read files the account can read**
  (low integrity does not block reads by default). For the service that account is LocalSystem.
  This is the main residual risk and is tracked in the threat model; AppContainer or a dedicated
  low-privilege worker account is the planned next step.
- Per-item IPC costs throughput (measured in the README) in exchange for isolation.
- `WinVerifyTrust` still parses PE files in the broker process. It is Windows code, but it is
  parsing attacker-controlled input with the broker's privileges.
- No operation that weakens protection exists yet. Such operations arrive with quarantine in M4 and
  will require an elevated administrator caller.

## Amendment (2026-11-09): private window station for workers

Installing the service as LocalSystem showed every worker failing with `0xC0000142`
(STATUS_DLL_INIT_FAILED). user32 connects each process to its window station during start-up; workers
inherited the service's `Service-0x0-3e7$` station, whose DACL grants only SYSTEM and Administrators,
both deny-only in the worker token. Development mode and CI never saw it, because the interactive
station also grants the logon SID, which the worker keeps.

The broker now creates one private window station and desktop per process (`WorkerDesktop`), with a
DACL for SYSTEM, the broker's account and Everyone and a low mandatory label, and starts workers on it.
Only administrators and SYSTEM may create named window stations; a standard user (development mode)
falls back to the inherited interactive station. `SandboxTests.Worker_runs_on_a_private_window_station`
covers both cases. The service also now reports a failed start to the Service Control Manager as an
error, and the install script sets `failureflag`, so the restart actions apply.
