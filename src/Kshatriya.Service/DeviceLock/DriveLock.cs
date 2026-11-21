using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Kshatriya.Service.DeviceLock;

/// <summary>A disk the device layer reported.</summary>
/// <param name="InstanceId">The disk's device instance id.</param>
/// <param name="Name">Friendly name for the user.</param>
/// <param name="SizeBytes">Disk size when known.</param>
/// <param name="IsUsb">True when the disk or one of its parents is enumerated by USB.</param>
/// <param name="IsProtected">True for the disk holding Windows, the boot volume or Kshatriya's program or data folder.</param>
public sealed record DiskInfo(string InstanceId, string Name, long? SizeBytes, bool IsUsb, bool IsProtected);

/// <summary>The device operations the lock needs (ADR 0023). The Windows implementation uses cfgmgr32.</summary>
public interface IDeviceControl : IDisposable
{
    /// <summary>Starts reporting disk arrivals (device instance ids) to <paramref name="arrived"/>.</summary>
    void StartNotifications(Action<string> arrived);

    void StopNotifications();

    /// <summary>Disks connected now.</summary>
    IReadOnlyList<string> PresentDisks();

    DiskInfo? Describe(string instanceId);

    /// <summary>True while the device node exists (connected), enabled or not.</summary>
    bool IsPresent(string instanceId);

    /// <summary>Disables the device node politely (not persistent). Null on success, otherwise why not.</summary>
    string? Disable(string instanceId);

    string? Enable(string instanceId);
}

public static class DriveStates
{
    public const string Locked = "locked";
    public const string Approved = "approved";

    /// <summary>Windows refused the disable (another program has the disk open); the lock keeps trying for a short while.</summary>
    public const string Locking = "locking";
    public const string CouldNotLock = "couldNotLock";
    public const string PresentBeforeLock = "presentBeforeLock";
}

public sealed record DriveEntry(string Id, string Name, long? SizeBytes, string State, DateTimeOffset ArrivedUtc, string? Message);

/// <summary>Outcome of an unlock, lock or password request.</summary>
public sealed record LockResult(bool Succeeded, string Code, string Message);

/// <summary>
/// The removable-drive lock (ADR 0023): while on, each newly connected USB disk is disabled until the Kshatriya
/// password is entered. Never touches the Windows, boot or Kshatriya disk or any non-disk device, and never
/// disables persistently. Authorisation and auditing are the caller's job (the pipe server).
/// </summary>
public sealed class DriveLock : IDisposable
{
    private static readonly TimeSpan s_sweepInterval = TimeSpan.FromSeconds(1);

    /// <summary>
    /// How long a refused disable is retried. Programs that read disk details (temperature monitors, indexers,
    /// antivirus) often hold a new disk open for a moment right after it arrives.
    /// </summary>
    public static readonly TimeSpan RetryWindow = TimeSpan.FromSeconds(30);

    private readonly IDeviceControl _devices;
    private readonly LockSettings _settings;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly ConcurrentDictionary<string, DriveEntry> _drives = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private readonly object _lockGate = new();
    private bool _started;

    public DriveLock(IDeviceControl devices, LockSettings settings, TimeProvider time, ILogger logger)
    {
        _devices = devices;
        _settings = settings;
        _time = time;
        _logger = logger;
    }

    public LockSettings Settings => _settings;

    /// <summary>"off", "on" or "unavailable: ...".</summary>
    public string State { get; private set; } = "off";

    public IReadOnlyList<DriveEntry> Drives => [.. _drives.Values.OrderBy(d => d.ArrivedUtc)];

    /// <summary>Raised when a drive is locked (the app shows the unlock prompt).</summary>
    public event Action<DriveEntry>? Locked;

    /// <summary>Starts watching if the lock is on. Disks connected before it started are listed, not locked.</summary>
    public void Start()
    {
        lock (_gate)
        {
            if (_started || !_settings.Enabled)
            {
                State = _settings.Enabled ? State : "off";
                return;
            }

            try
            {
                foreach (string id in _devices.PresentDisks())
                {
                    if (_devices.Describe(id) is { IsUsb: true, IsProtected: false } disk)
                    {
                        _drives[id] = new DriveEntry(id, disk.Name, disk.SizeBytes, DriveStates.PresentBeforeLock, _time.GetUtcNow(), "Connected before the lock started; not locked.");
                    }
                }

                _devices.StartNotifications(OnArrived);
                _started = true;
                State = "on";
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or DllNotFoundException or EntryPointNotFoundException)
            {
                State = $"unavailable: {ex.Message}";
                Log.DriveLockProblem(_logger, $"The USB drive lock could not start: {ex.Message}");
            }
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            if (_started)
            {
                _devices.StopNotifications();
                _started = false;
            }

            State = "off";
        }
    }

    /// <summary>
    /// Forgets drives that were unplugged (so a re-plug is locked again) and retries drives whose disable was
    /// refused. Runs until cancelled.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Start();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(s_sweepInterval, _time, cancellationToken);
                Sweep();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Shutdown.
        }
        finally
        {
            Stop();
        }
    }

    internal void Sweep()
    {
        foreach (DriveEntry drive in _drives.Values)
        {
            if (!_devices.IsPresent(drive.Id))
            {
                _drives.TryRemove(drive.Id, out _);
            }
            else if (drive.State == DriveStates.Locking && _settings.Enabled)
            {
                TryLock(drive.Id, drive.Name, drive.SizeBytes, drive.ArrivedUtc);
            }
        }
    }

    /// <summary>A disk appeared. Locks it if it is a USB disk that is not protected and not approved.</summary>
    internal void OnArrived(string instanceId)
    {
        if (!_settings.Enabled || (_drives.TryGetValue(instanceId, out DriveEntry? known) && known.State != DriveStates.Locked))
        {
            return; // approved, already listed, or the lock is off (enabling an approved drive also raises an arrival)
        }

        DiskInfo? disk = _devices.Describe(instanceId);
        if (disk is not { IsUsb: true, IsProtected: false })
        {
            return;
        }

        TryLock(instanceId, disk.Name, disk.SizeBytes, arrivedUtc: null);
    }

    /// <summary>
    /// Disables the disk. A refusal is retried by <see cref="Sweep"/> until <see cref="RetryWindow"/> has passed
    /// since the disk arrived; then the drive is reported as could not be locked.
    /// </summary>
    private void TryLock(string instanceId, string name, long? sizeBytes, DateTimeOffset? arrivedUtc)
    {
        lock (_lockGate)
        {
            // A retry only continues a drive that is still waiting (it may have been locked or unplugged meanwhile).
            if (arrivedUtc is not null && (!_drives.TryGetValue(instanceId, out DriveEntry? current) || current.State != DriveStates.Locking))
            {
                return;
            }

            TryLockCore(instanceId, name, sizeBytes, arrivedUtc);
        }
    }

    private void TryLockCore(string instanceId, string name, long? sizeBytes, DateTimeOffset? arrivedUtc)
    {
        DateTimeOffset now = _time.GetUtcNow();
        DateTimeOffset arrived = arrivedUtc ?? now;
        string? problem = _devices.Disable(instanceId);
        if (problem is null)
        {
            var entry = new DriveEntry(instanceId, name, sizeBytes, DriveStates.Locked, arrived, null);
            _drives[instanceId] = entry;
            Log.DriveLock(_logger, name, instanceId, "locked until the Kshatriya password is entered");
            Locked?.Invoke(entry);
            return;
        }

        bool givingUp = now - arrived >= RetryWindow;
        string state = givingUp ? DriveStates.CouldNotLock : DriveStates.Locking;
        string message = givingUp
            ? $"{problem} Close that program, then unplug the drive and plug it in again."
            : $"{problem} Kshatriya keeps trying for {RetryWindow.TotalSeconds:0} seconds.";
        _drives[instanceId] = new DriveEntry(instanceId, name, sizeBytes, state, arrived, message);
        if (arrivedUtc is null || givingUp)
        {
            Log.DriveLock(_logger, name, instanceId, givingUp ? $"could not be locked: {problem}" : $"could not be locked yet, retrying: {problem}");
        }
    }

    /// <summary>Checks the password and enables a locked drive. The caller audits the outcome.</summary>
    public LockResult Unlock(string instanceId, string password)
    {
        if (!_drives.TryGetValue(instanceId, out DriveEntry? drive) || drive.State != DriveStates.Locked)
        {
            return new(false, "notFound", "That drive is not locked.");
        }

        switch (_settings.Verify(password))
        {
            case LockSettings.Check.TooManyAttempts:
                return new(false, "tooManyAttempts", $"Too many wrong passwords. Try again in {_settings.RetryAfterSeconds} seconds.");
            case LockSettings.Check.NotSet:
                return new(false, "noPassword", "No Kshatriya password is set.");
            case LockSettings.Check.Wrong:
                return new(false, "wrongPassword", "Wrong password.");
        }

        // Mark it approved first, so the arrival raised by enabling it is not locked again.
        _drives[instanceId] = drive with { State = DriveStates.Approved, Message = null };
        string? problem = _devices.Enable(instanceId);
        if (problem is not null)
        {
            _drives[instanceId] = drive with { Message = problem };
            return new(false, "failed", $"The drive could not be enabled: {problem}");
        }

        return new(true, "none", $"{drive.Name} is unlocked until it is unplugged.");
    }

    /// <summary>Turns the lock on or off. Turning it on needs a password; turning it off enables locked drives.</summary>
    public LockResult Configure(bool enabled)
    {
        if (enabled && !_settings.PasswordSet)
        {
            return new(false, "noPassword", "Set a Kshatriya password first (kshatriya password set).");
        }

        _settings.SetEnabled(enabled);
        if (enabled)
        {
            Start();
            return State == "on"
                ? new(true, "none", "USB drive lock is on. New USB drives stay locked until the Kshatriya password is entered.")
                : new(false, "unavailable", State);
        }

        Stop();
        foreach (DriveEntry drive in _drives.Values.Where(d => d.State == DriveStates.Locked))
        {
            _devices.Enable(drive.Id);
        }

        _drives.Clear();
        return new(true, "none", "USB drive lock is off. Locked drives were enabled again.");
    }

    /// <summary>
    /// Sets the password. An elevated administrator may always set it (also to reset a forgotten one); anyone
    /// else must give the current password, and only once one exists.
    /// </summary>
    public LockResult SetPassword(string newPassword, string? currentPassword, bool isAdmin)
    {
        if (LockSettings.Validate(newPassword) is { } problem)
        {
            return new(false, "weakPassword", problem);
        }

        if (!isAdmin)
        {
            if (!_settings.PasswordSet)
            {
                return new(false, "accessDenied", "Setting the first Kshatriya password requires an elevated administrator.");
            }

            if (currentPassword is null)
            {
                return new(false, "currentPasswordRequired", "Enter the current Kshatriya password.");
            }

            switch (_settings.Verify(currentPassword))
            {
                case LockSettings.Check.TooManyAttempts:
                    return new(false, "tooManyAttempts", $"Too many wrong passwords. Try again in {_settings.RetryAfterSeconds} seconds.");
                case LockSettings.Check.Wrong or LockSettings.Check.NotSet:
                    return new(false, "wrongPassword", "The current password is wrong.");
            }
        }

        _settings.SetPassword(newPassword);
        return new(true, "none", "The Kshatriya password was set.");
    }

    /// <summary>When the service stops, drives it locked are enabled again: nothing stays disabled without it.</summary>
    public void Dispose()
    {
        Stop();
        foreach (DriveEntry drive in _drives.Values.Where(d => d.State == DriveStates.Locked))
        {
            _devices.Enable(drive.Id);
        }

        _drives.Clear();
        _devices.Dispose();
    }
}
