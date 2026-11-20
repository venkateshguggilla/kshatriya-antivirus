using System.Security.Principal;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;
using Kshatriya.Service.DeviceLock;
using Kshatriya.Tests.Shared;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kshatriya.Service.Tests;

/// <summary>A clock tests move by hand.</summary>
internal sealed class FakeTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public FakeTimeProvider()
        : this(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero))
    {
    }

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>In-memory devices: tests never disable a real device.</summary>
internal sealed class FakeDeviceControl : IDeviceControl
{
    private Action<string>? _arrived;

    public Dictionary<string, DiskInfo> Disks { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> Disabled { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> InUse { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool Watching => _arrived is not null;

    /// <summary>Simulates plugging a disk in.</summary>
    public void Plug(DiskInfo disk)
    {
        Disks[disk.InstanceId] = disk;
        _arrived?.Invoke(disk.InstanceId);
    }

    public void Unplug(string id)
    {
        Disks.Remove(id);
        Disabled.Remove(id);
    }

    public void StartNotifications(Action<string> arrived) => _arrived = arrived;

    public void StopNotifications() => _arrived = null;

    public IReadOnlyList<string> PresentDisks() => [.. Disks.Keys];

    public DiskInfo? Describe(string instanceId) => Disks.GetValueOrDefault(instanceId);

    public bool IsPresent(string instanceId) => Disks.ContainsKey(instanceId);

    public string? Disable(string instanceId)
    {
        if (InUse.Contains(instanceId))
        {
            return "The drive is in use.";
        }

        Disabled.Add(instanceId);
        return null;
    }

    public string? Enable(string instanceId)
    {
        Disabled.Remove(instanceId);
        _arrived?.Invoke(instanceId); // Windows raises a new arrival when the disk comes back
        return null;
    }

    public void Dispose() => _arrived = null;
}

public sealed class DriveLockTests
{
    private static readonly DiskInfo Stick = new(@"USBSTOR\DISK&VEN_TEST&PROD_STICK\0001", "Test Stick", 32_000_000_000, IsUsb: true, IsProtected: false);
    private static readonly DiskInfo Internal = new(@"SCSI\DISK&VEN_NVME\4&1", "NVMe disk", 1_000_000_000_000, IsUsb: false, IsProtected: false);
    private static readonly DiskInfo UsbBoot = new(@"USBSTOR\DISK&VEN_BOOT\9", "Windows To Go", 64_000_000_000, IsUsb: true, IsProtected: true);

    private static (DriveLock Lock, FakeDeviceControl Devices, FakeTimeProvider Time, TempDirectory Temp) Create(bool enabled = true)
    {
        var temp = new TempDirectory();
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero));
        var devices = new FakeDeviceControl();
        var settings = new LockSettings(temp.Path, production: false, time);
        var driveLock = new DriveLock(devices, settings, time, NullLogger.Instance);
        if (enabled)
        {
            Assert.True(driveLock.SetPassword("correct horse", null, isAdmin: true).Succeeded);
            Assert.True(driveLock.Configure(true).Succeeded);
        }

        return (driveLock, devices, time, temp);
    }

    [Fact]
    public void LocksNewUsbDisksAndUnlocksWithThePassword()
    {
        (DriveLock driveLock, FakeDeviceControl devices, _, TempDirectory temp) = Create();
        using (temp)
        using (driveLock)
        {
            DriveEntry? notified = null;
            driveLock.Locked += e => notified = e;

            devices.Plug(Stick);

            Assert.Contains(Stick.InstanceId, devices.Disabled);
            Assert.Equal(DriveStates.Locked, Assert.Single(driveLock.Drives).State);
            Assert.Equal("Test Stick", notified?.Name);

            Assert.Equal("wrongPassword", driveLock.Unlock(Stick.InstanceId, "nope nope").Code);
            Assert.Contains(Stick.InstanceId, devices.Disabled);

            LockResult unlocked = driveLock.Unlock(Stick.InstanceId, "correct horse");
            Assert.True(unlocked.Succeeded, unlocked.Message);
            Assert.DoesNotContain(Stick.InstanceId, devices.Disabled); // and the arrival from enabling did not re-lock it
            Assert.Equal(DriveStates.Approved, Assert.Single(driveLock.Drives).State);

            // Unplugged and plugged in again: locked again.
            devices.Unplug(Stick.InstanceId);
            driveLock.Sweep();
            Assert.Empty(driveLock.Drives);
            devices.Plug(Stick);
            Assert.Contains(Stick.InstanceId, devices.Disabled);
        }
    }

    [Fact]
    public void NeverLocksInternalOrProtectedDisks()
    {
        (DriveLock driveLock, FakeDeviceControl devices, _, TempDirectory temp) = Create();
        using (temp)
        using (driveLock)
        {
            devices.Plug(Internal);
            devices.Plug(UsbBoot);

            Assert.Empty(devices.Disabled);
            Assert.Empty(driveLock.Drives);
        }
    }

    [Fact]
    public void InUseDrivesAreReportedNotForced()
    {
        (DriveLock driveLock, FakeDeviceControl devices, _, TempDirectory temp) = Create();
        using (temp)
        using (driveLock)
        {
            devices.InUse.Add(Stick.InstanceId);
            devices.Plug(Stick);

            DriveEntry entry = Assert.Single(driveLock.Drives);
            Assert.Equal(DriveStates.CouldNotLock, entry.State);
            Assert.NotNull(entry.Message);
        }
    }

    [Fact]
    public void DrivesConnectedBeforeTheLockStartsAreLeftAlone()
    {
        using var temp = new TempDirectory();
        var time = new FakeTimeProvider();
        var devices = new FakeDeviceControl();
        devices.Disks[Stick.InstanceId] = Stick;
        var settings = new LockSettings(temp.Path, production: false, time);
        settings.SetPassword("correct horse");
        settings.SetEnabled(true);
        using var driveLock = new DriveLock(devices, settings, time, NullLogger.Instance);

        driveLock.Start();

        Assert.Empty(devices.Disabled);
        Assert.Equal(DriveStates.PresentBeforeLock, Assert.Single(driveLock.Drives).State);
        Assert.True(devices.Watching);
    }

    [Fact]
    public void OffMeansNothingIsLockedAndTurningOffReleasesLockedDrives()
    {
        (DriveLock driveLock, FakeDeviceControl devices, _, TempDirectory temp) = Create();
        using (temp)
        using (driveLock)
        {
            devices.Plug(Stick);
            Assert.Contains(Stick.InstanceId, devices.Disabled);

            Assert.True(driveLock.Configure(false).Succeeded);

            Assert.Empty(devices.Disabled);
            Assert.False(devices.Watching);
            devices.Unplug(Stick.InstanceId);
            devices.Plug(Stick);
            Assert.Empty(devices.Disabled);
        }
    }

    [Fact]
    public void TheLockNeedsAPasswordAndWeakPasswordsAreRefused()
    {
        (DriveLock driveLock, _, _, TempDirectory temp) = Create(enabled: false);
        using (temp)
        using (driveLock)
        {
            Assert.Equal("noPassword", driveLock.Configure(true).Code);
            Assert.Equal("weakPassword", driveLock.SetPassword("short", null, isAdmin: true).Code);
            Assert.Equal("accessDenied", driveLock.SetPassword("long enough", null, isAdmin: false).Code);
        }
    }

    [Fact]
    public void NonAdministratorsChangeThePasswordOnlyWithTheCurrentOne()
    {
        (DriveLock driveLock, _, _, TempDirectory temp) = Create();
        using (temp)
        using (driveLock)
        {
            Assert.Equal("currentPasswordRequired", driveLock.SetPassword("new password", null, isAdmin: false).Code);
            Assert.Equal("wrongPassword", driveLock.SetPassword("new password", "wrong one", isAdmin: false).Code);
            Assert.True(driveLock.SetPassword("new password", "correct horse", isAdmin: false).Succeeded);
            Assert.Equal(LockSettings.Check.Correct, driveLock.Settings.Verify("new password"));
        }
    }

    [Fact]
    public void WrongPasswordsAreSlowedDownServiceWide()
    {
        (DriveLock driveLock, FakeDeviceControl devices, FakeTimeProvider time, TempDirectory temp) = Create();
        using (temp)
        using (driveLock)
        {
            devices.Plug(Stick);
            for (int i = 0; i < LockSettings.FreeAttempts; i++)
            {
                Assert.Equal("wrongPassword", driveLock.Unlock(Stick.InstanceId, "guess " + i).Code);
            }

            // Even the right password waits now.
            Assert.Equal("tooManyAttempts", driveLock.Unlock(Stick.InstanceId, "correct horse").Code);
            Assert.InRange(driveLock.Settings.RetryAfterSeconds, 1, 30);

            time.Advance(TimeSpan.FromSeconds(31));
            Assert.True(driveLock.Unlock(Stick.InstanceId, "correct horse").Succeeded);
            Assert.Equal(0, driveLock.Settings.RetryAfterSeconds);
        }
    }

    [Fact]
    public void ThePasswordIsStoredOnlyAsASaltedHash()
    {
        using var temp = new TempDirectory();
        var settings = new LockSettings(temp.Path, production: false, TimeProvider.System);
        settings.SetPassword("correct horse battery");

        string stored = File.ReadAllText(Path.Combine(temp.Path, "lock.json"));
        Assert.DoesNotContain("correct horse", stored, StringComparison.Ordinal);
        Assert.Contains("\"iterations\":600000", stored, StringComparison.Ordinal);

        // Same password, new salt: different hash.
        settings.SetPassword("correct horse battery");
        Assert.NotEqual(stored, File.ReadAllText(Path.Combine(temp.Path, "lock.json")));

        var reloaded = new LockSettings(temp.Path, production: false, TimeProvider.System);
        Assert.Equal(LockSettings.Check.Correct, reloaded.Verify("correct horse battery"));
        Assert.Equal(LockSettings.Check.Wrong, reloaded.Verify("correct horse batterY"));
    }
}

public sealed class DriveLockServiceTests
{
    private static bool IsElevatedAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    [Fact]
    public async Task Unlock_over_the_pipe_is_audited_without_the_password()
    {
        var devices = new FakeDeviceControl();
        await using RunningService service = await RunningService.StartAsync(devices: devices);
        await using ServiceClient client = await service.ConnectAsync();

        Assert.True((await client.SetPasswordAsync("correct horse", null)).Succeeded);
        Assert.True((await client.ConfigureDeviceLockAsync(true)).Succeeded);
        var stick = new DiskInfo(@"USBSTOR\DISK&VEN_PIPE\1", "Pipe Stick", null, true, false);
        devices.Plug(stick);

        DeviceLockReplyDto status = await client.GetDeviceLockAsync();
        Assert.Equal("on", status.State);
        Assert.True(status.Enabled && status.PasswordSet);
        Assert.Equal("locked", Assert.Single(status.Drives).State);

        Assert.Equal("wrongPassword", (await client.UnlockDeviceAsync(stick.InstanceId, "wrong guess")).Code);
        Assert.True((await client.UnlockDeviceAsync(stick.InstanceId, "correct horse")).Succeeded);

        AuditReplyDto audit = await client.GetAuditAsync(10);
        Assert.Equal(["deviceUnlock", "deviceUnlock", "deviceLockOn", "passwordSet"], audit.Records.Select(r => r.Action));
        Assert.Equal(["succeeded", "denied"], audit.Records.Take(2).Select(r => r.Outcome));
        Assert.DoesNotContain(audit.Records, r => (r.Detail ?? string.Empty).Contains("horse", StringComparison.Ordinal) || r.Target.Contains("horse", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Non_administrators_cannot_turn_the_lock_off_or_set_the_first_password()
    {
        if (IsElevatedAdmin)
        {
            return; // covered on non-elevated runs; CI runs elevated
        }

        await using RunningService service = await RunningService.StartAsync(requireAdministrator: true);
        await using ServiceClient client = await service.ConnectAsync();

        var ex = await Assert.ThrowsAsync<ServiceException>(() => client.ConfigureDeviceLockAsync(false));
        Assert.Equal(ErrorCodes.AccessDenied, ex.Code);
        Assert.Equal("accessDenied", (await client.SetPasswordAsync("long enough", null)).Code);
        Assert.Contains(service.Core.Quarantine.Audit.ReadRecent(5), r => r.Action == "deviceLockOff" && r.Outcome == "denied");
    }
}

public sealed class WindowsDeviceControlTests
{
    /// <summary>Read-only: lists this machine's disks; nothing is disabled.</summary>
    [Fact]
    public void The_Windows_disk_is_listed_as_protected_and_never_usb_locked()
    {
        using var devices = new WindowsDeviceControl();
        IReadOnlyList<string> disks = devices.PresentDisks();
        Assert.NotEmpty(disks);

        // At least one disk holds Windows, and every disk Windows reports can be described.
        var described = disks.Select(devices.Describe).OfType<DiskInfo>().ToList();
        Assert.Equal(disks.Count, described.Count);
        Assert.Contains(described, d => d.IsProtected);
        Assert.All(described, d => Assert.True(devices.IsPresent(d.InstanceId)));
        Assert.All(described.Where(d => !d.IsUsb), d => Assert.DoesNotContain("USBSTOR", d.InstanceId, StringComparison.OrdinalIgnoreCase));
    }
}