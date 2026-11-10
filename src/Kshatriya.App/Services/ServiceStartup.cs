using Kshatriya.Runtime.Ipc;

namespace Kshatriya.App.Services;

/// <summary>
/// Tells "still starting" apart from "not running". The installed service uses a delayed automatic start,
/// so for a minute or two after Windows starts it is stopped and the app, which starts at sign-in, cannot
/// reach it yet.
/// </summary>
public static class ServiceStartup
{
    private const uint Stopped = 1;
    private const uint StartPending = 2;

    /// <summary>How long after Windows starts a stopped service is still expected to start by itself.</summary>
    public static TimeSpan DelayedStartWindow { get; } = TimeSpan.FromMinutes(5);

    public static bool IsStarting(string serviceName) =>
        IsStarting(PipeNative.QueryServiceState(serviceName), TimeSpan.FromMilliseconds(Environment.TickCount64));

    /// <summary>True when the service is starting, or stopped soon after Windows started (delayed start).</summary>
    public static bool IsStarting(uint? state, TimeSpan sinceWindowsStarted) =>
        state == StartPending || (state == Stopped && sinceWindowsStarted < DelayedStartWindow);
}
