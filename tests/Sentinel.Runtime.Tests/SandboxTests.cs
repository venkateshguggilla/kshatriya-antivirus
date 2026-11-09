using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Runtime.Sandbox;
using Sentinel.Runtime.Workers;
using Sentinel.Tests.Shared;

namespace Sentinel.Runtime.Tests;

/// <summary>
/// Proves the worker sandbox holds, using real worker processes: low integrity, no writes to the
/// user's files, no child processes, a memory cap, and no diagnostics without explicit test hooks.
/// </summary>
public class SandboxTests
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task Worker_runs_at_low_integrity()
    {
        using WorkerPoolAnalyzer pool = await StartAsync(testHooks: true);

        ProbeReplyDto reply = await pool.ProbeAsync(new ProbeDto { Kind = "integrity" }, ProbeTimeout);

        Assert.True(reply.Succeeded);
        Assert.Equal("low", reply.Detail);
    }

    [Fact]
    public async Task Worker_runs_on_a_private_window_station()
    {
        // Under LocalSystem the service's own window station admits only SYSTEM and Administrators, which
        // the worker token makes deny-only; the worker must use a station of its own (0xC0000142 otherwise).
        using WorkerPoolAnalyzer pool = await StartAsync(testHooks: true);

        ProbeReplyDto reply = await pool.ProbeAsync(new ProbeDto { Kind = "station" }, ProbeTimeout);

        Assert.True(reply.Succeeded);
        // Only administrators and SYSTEM may create window stations (CI runs elevated); a standard user's
        // workers inherit the interactive station, which grants the logon SID the worker keeps.
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        if (new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
        {
            Assert.StartsWith($"SentinelWorker-{Environment.ProcessId}-", reply.Detail, StringComparison.Ordinal);
        }
        else
        {
            Assert.Equal(TokenInfo.CurrentWindowStation(), reply.Detail);
        }
    }

    [Fact]
    public async Task Worker_cannot_write_to_the_users_files()
    {
        using var temp = new TempDirectory();
        string target = Path.Combine(temp.Path, "written-by-worker.txt");
        using WorkerPoolAnalyzer pool = await StartAsync(testHooks: true);

        ProbeReplyDto reply = await pool.ProbeAsync(new ProbeDto { Kind = "write", Argument = target }, ProbeTimeout);

        Assert.False(reply.Succeeded);
        Assert.Equal(nameof(UnauthorizedAccessException), reply.Detail);
        Assert.False(File.Exists(target));
    }

    [Fact]
    public async Task Worker_cannot_read_files_private_to_the_account()
    {
        // A typical profile file: readable by the account, SYSTEM and Administrators only.
        using var temp = new TempDirectory();
        string secret = temp.File("private.txt", "not for the worker"u8.ToArray());
        var security = new System.Security.AccessControl.FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[]
        {
            System.Security.Principal.WindowsIdentity.GetCurrent().User!,
            new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null),
            new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null),
        })
        {
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
        }

        new FileInfo(secret).SetAccessControl(security);
        using WorkerPoolAnalyzer pool = await StartAsync(testHooks: true);

        ProbeReplyDto reply = await pool.ProbeAsync(new ProbeDto { Kind = "read", Argument = secret }, ProbeTimeout);

        Assert.False(reply.Succeeded);
        Assert.Equal(nameof(UnauthorizedAccessException), reply.Detail);
    }

    [Fact]
    public async Task Worker_can_still_read_world_readable_files()
    {
        // Documents the residual risk recorded in the threat model: files readable by Users/Everyone
        // (system binaries, shared configuration) stay readable from inside the sandbox.
        using WorkerPoolAnalyzer pool = await StartAsync(testHooks: true);

        ProbeReplyDto reply = await pool.ProbeAsync(new ProbeDto { Kind = "read", Argument = Path.Combine(Environment.SystemDirectory, "kernel32.dll") }, ProbeTimeout);

        Assert.True(reply.Succeeded);
    }

    [Fact]
    public async Task Worker_cannot_start_child_processes()
    {
        using WorkerPoolAnalyzer pool = await StartAsync(testHooks: true);

        ProbeReplyDto reply = await pool.ProbeAsync(new ProbeDto { Kind = "spawn" }, ProbeTimeout);

        Assert.False(reply.Succeeded);
    }

    [Fact]
    public async Task Worker_exceeding_the_memory_cap_is_terminated()
    {
        using WorkerPoolAnalyzer pool = await StartAsync(testHooks: true, memoryLimit: 192L * 1024 * 1024);

        ProbeReplyDto reply = await pool.ProbeAsync(new ProbeDto { Kind = "allocate", Argument = "512" }, ProbeTimeout);

        Assert.False(reply.Succeeded);
        Assert.StartsWith("worker-exited", reply.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Probes_are_refused_without_test_hooks()
    {
        using WorkerPoolAnalyzer pool = await StartAsync(testHooks: false);

        ProbeReplyDto reply = await pool.ProbeAsync(new ProbeDto { Kind = "integrity" }, ProbeTimeout);

        Assert.False(reply.Succeeded);
        Assert.Equal("probes-disabled", reply.Detail);
    }

    [Fact]
    public void Sandboxed_process_is_killed_with_its_job()
    {
        using SandboxedProcess process = SandboxedProcess.Start(WorkerPoolOptions.DefaultWorkerPath, "--worker", new SandboxOptions());
        Assert.False(process.HasExited);

        process.Kill();

        Assert.True(process.WaitForExit(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public void Missing_worker_executable_is_reported()
    {
        var ex = Assert.Throws<SandboxException>(() => SandboxedProcess.Start(@"C:\does-not-exist\Sentinel.Worker.exe", "--worker", new SandboxOptions()));
        Assert.Contains("not found", ex.Message, StringComparison.Ordinal);
    }

    internal static Task<WorkerPoolAnalyzer> StartAsync(bool testHooks, long? memoryLimit = null, EngineConfiguration? engines = null, int workers = 2) =>
        WorkerPoolAnalyzer.StartAsync(new WorkerPoolOptions
        {
            Engines = engines ?? new EngineConfiguration(),
            WorkerCount = workers,
            TestHooks = testHooks,
            Sandbox = new SandboxOptions { MemoryLimitBytes = memoryLimit ?? new SandboxOptions().MemoryLimitBytes },
        });
}
