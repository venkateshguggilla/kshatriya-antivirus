using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;
using Kshatriya.Core;
using Kshatriya.Posture;
using Kshatriya.Service.RealTime;
using Microsoft.Extensions.Logging;

namespace Kshatriya.Service.Posture;

/// <summary>
/// Runs the security check on request and watches for changes since the baseline (ADR 0022). Checks only read.
/// Changes are recorded as suspicious findings and never trigger an action.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class PostureService : IDisposable
{
    private static readonly TimeSpan s_startupInterval = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan s_networkInterval = TimeSpan.FromHours(6);
    private static readonly TimeSpan s_networkDebounce = TimeSpan.FromSeconds(30);

    private readonly IPostureSource _source;
    private readonly Func<IReadOnlySet<string>> _applied;
    private readonly Func<(bool? Enabled, bool? PasswordSet)> _lock;
    private readonly string _baselineFile;
    private readonly bool _production;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly SemaphoreSlim _networkChanged = new(0, 1);

    public PostureService(
        IPostureSource source,
        Func<IReadOnlySet<string>> applied,
        Func<(bool? Enabled, bool? PasswordSet)> lockState,
        string stateDirectory,
        bool production,
        TimeProvider time,
        ILogger logger)
    {
        _source = source;
        _applied = applied;
        _lock = lockState;
        _baselineFile = Path.Combine(stateDirectory, "posture-baseline.json");
        _production = production;
        _time = time;
        _logger = logger;
    }

    /// <summary>Called with each change found (the service adds it to the detection history).</summary>
    public event Action<PostureChange>? Changed;

    /// <summary>
    /// Runs every check. Other users' startup entries and installer policies are included only for an
    /// administrator (<paramref name="isAdmin"/>); otherwise only the machine and <paramref name="callerSid"/>.
    /// </summary>
    public IReadOnlyList<PostureCheck> Evaluate(string? callerSid, bool isAdmin)
    {
        IReadOnlySet<string> applied = _applied();
        (bool? lockEnabled, bool? passwordSet) = _lock();
        var checks = new List<PostureCheck>();
        checks.AddRange(WindowsRules.Defender(_source.ReadDefender(), _time.GetUtcNow(), applied));
        checks.AddRange(WindowsRules.Installs(_source.ReadInstalls(callerSid), applied));
        checks.AddRange(WindowsRules.Usb(new UsbSnapshot(_source.ReadAutoRunPolicy(), lockEnabled, passwordSet), applied));
        checks.AddRange(NetworkRules.Evaluate(_source.ReadNetwork(), applied));
        IReadOnlySet<string>? users = isAdmin ? null : callerSid is null ? new HashSet<string>() : new HashSet<string>(StringComparer.Ordinal) { callerSid };
        checks.AddRange(StartupRules.Evaluate(_source.ReadStartup(users)));
        return [.. checks.OrderBy(c => c.Area).ThenByDescending(c => c.State == PostureState.Unknown ? -1 : (int)c.State)];
    }

    /// <summary>Compares the current state with the baseline once and stores the new baseline.</summary>
    public async Task<IReadOnlyList<PostureChange>> RefreshBaselineAsync(bool network, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            PostureBaseline? baseline = Load();
            IReadOnlyList<GatewayObservation> gateways = network ? _source.ReadGateways() : [];
            IReadOnlyList<string> dns = network ? DnsServers() : baseline?.DnsServers ?? [];
            var observation = new PostureObservation(gateways, dns, _source.ReadStartup(userSids: null));
            (IReadOnlyList<PostureChange> changes, PostureBaseline updated) = BaselineComparer.Compare(baseline, observation);
            if (!network && baseline is not null)
            {
                // Gateways were not read this time: keep the remembered ones.
                foreach ((string key, string mac) in baseline.Gateways)
                {
                    updated.Gateways.TryAdd(key, mac);
                }
            }

            Save(updated);
            foreach (PostureChange change in changes)
            {
                Log.PostureChange(_logger, change.Title, change.Detail);
                Changed?.Invoke(change);
            }

            return changes;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Watches until cancelled: startup entries every 30 minutes, the network on change and every 6 hours.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        try
        {
            await Task.Delay(TimeSpan.FromMinutes(1), _time, cancellationToken);
            DateTimeOffset lastNetwork = DateTimeOffset.MinValue;
            while (!cancellationToken.IsCancellationRequested)
            {
                bool network = _time.GetUtcNow() - lastNetwork >= s_networkInterval;
                try
                {
                    await Task.Run(() => RefreshBaselineAsync(network, cancellationToken), cancellationToken);
                    if (network)
                    {
                        lastNetwork = _time.GetUtcNow();
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
                {
                    Log.PostureProblem(_logger, ex.Message);
                }

                // Wake early when the network changes (after a short quiet period), otherwise every 30 minutes.
                if (await _networkChanged.WaitAsync(s_startupInterval, cancellationToken))
                {
                    await Task.Delay(s_networkDebounce, _time, cancellationToken);
                    lastNetwork = DateTimeOffset.MinValue;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Shutdown.
        }
        finally
        {
            NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        }
    }

    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        if (_networkChanged.CurrentCount == 0)
        {
            try
            {
                _networkChanged.Release();
            }
            catch (SemaphoreFullException)
            {
                // Already signalled.
            }
        }
    }

    private static List<string> DnsServers()
    {
        var servers = new List<string>();
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            servers.AddRange(nic.GetIPProperties().DnsAddresses
                .Where(a => !a.IsIPv6SiteLocal && !a.IsIPv6LinkLocal)
                .Select(a => a.ToString()));
        }

        return servers;
    }

    private PostureBaseline? Load()
    {
        if (!File.Exists(_baselineFile))
        {
            return null;
        }

        try
        {
            var info = new FileInfo(_baselineFile);
            if (info.Length > 16 << 20)
            {
                return null; // implausibly large: start a new baseline
            }

            return JsonSerializer.Deserialize(File.ReadAllBytes(_baselineFile), PostureJsonContext.Default.PostureBaseline);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private void Save(PostureBaseline baseline) =>
        SecureStorage.WriteProtectedFile(_baselineFile, JsonSerializer.Serialize(baseline, PostureJsonContext.Default.PostureBaseline), _production);

    public void Dispose()
    {
        _gate.Dispose();
        _networkChanged.Dispose();
    }

    /// <summary>A detection-history record for a change (suspicious, alert only).</summary>
    public static DetectionRecord ToRecord(PostureChange change, DateTimeOffset now) =>
        new(now, "security check", change.Path ?? change.Title, ScanStatus.Suspicious, [change.Title], "alert only (no automatic action)");
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = false, MaxDepth = 8)]
[JsonSerializable(typeof(PostureBaseline))]
internal sealed partial class PostureJsonContext : JsonSerializerContext
{
}
