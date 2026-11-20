namespace Kshatriya.Posture;

/// <summary>The default gateway of a connected network and its hardware (MAC) address.</summary>
public sealed record GatewayObservation(string Network, string Address, string HardwareAddress);

/// <summary>What the service sees now, compared with the stored baseline.</summary>
public sealed record PostureObservation(
    IReadOnlyList<GatewayObservation> Gateways,
    IReadOnlyList<string> DnsServers,
    IReadOnlyList<StartupEntry> Startup);

/// <summary>
/// The remembered state (ADR 0022): gateway hardware address per network and gateway address, DNS servers, and
/// startup entries (key to command). Stored by the service in its data folder.
/// </summary>
public sealed class PostureBaseline
{
    public Dictionary<string, string> Gateways { get; init; } = new(StringComparer.Ordinal);

    public List<string> DnsServers { get; init; } = [];

    public Dictionary<string, string> Startup { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Bounds keep a hostile or broken environment from growing the file without limit.</summary>
    public const int MaxStartupEntries = 20_000;

    public const int MaxGateways = 256;
}

/// <summary>A change since the baseline, reported as a suspicious finding.</summary>
public sealed record PostureChange(string Kind, string Title, string Detail, string? Path = null);

public static class PostureChangeKinds
{
    public const string Gateway = "gateway";
    public const string Dns = "dns";
    public const string Startup = "startup";
}

/// <summary>Compares observations with the baseline. Pure; the caller stores the returned baseline.</summary>
public static class BaselineComparer
{
    public static (IReadOnlyList<PostureChange> Changes, PostureBaseline Updated) Compare(PostureBaseline? baseline, PostureObservation now)
    {
        var changes = new List<PostureChange>();
        var updated = new PostureBaseline();

        foreach (GatewayObservation gateway in now.Gateways.Take(PostureBaseline.MaxGateways))
        {
            string key = $"{gateway.Network}|{gateway.Address}";
            string mac = gateway.HardwareAddress.ToUpperInvariant();
            updated.Gateways[key] = mac;
            if (baseline is not null && baseline.Gateways.TryGetValue(key, out string? before) && before != mac)
            {
                changes.Add(new(PostureChangeKinds.Gateway, $"The router's hardware address changed on '{gateway.Network}'",
                    $"Gateway {gateway.Address} was {before} and is now {mac}. This happens when the router is replaced, but it is also a sign of an attacker on the network intercepting traffic (ARP spoofing)."));
            }
        }

        // Gateways not seen now are kept, so moving between networks does not forget them.
        if (baseline is not null)
        {
            foreach ((string key, string mac) in baseline.Gateways)
            {
                if (updated.Gateways.Count >= PostureBaseline.MaxGateways)
                {
                    break;
                }

                updated.Gateways.TryAdd(key, mac);
            }
        }

        updated.DnsServers.AddRange(now.DnsServers.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).Take(64));
        if (baseline is { DnsServers.Count: > 0 })
        {
            var added = updated.DnsServers.Except(baseline.DnsServers, StringComparer.OrdinalIgnoreCase).ToList();
            if (added.Count > 0)
            {
                changes.Add(new(PostureChangeKinds.Dns, "The DNS servers changed",
                    $"Now: {string.Join(", ", updated.DnsServers)}; before: {string.Join(", ", baseline.DnsServers)}. Connecting to another network or a VPN does this; an unexpected change can send you to fake sites."));
            }
        }

        foreach (StartupEntry entry in now.Startup.Take(PostureBaseline.MaxStartupEntries))
        {
            updated.Startup[entry.Key] = entry.Command;
            if (baseline is null)
            {
                continue;
            }

            if (!baseline.Startup.TryGetValue(entry.Key, out string? command))
            {
                changes.Add(new(PostureChangeKinds.Startup, $"New startup entry: {entry.Name}",
                    $"{StartupRules.Describe(entry)} now runs {entry.Command}. Fine if you just installed something; otherwise check it.", entry.ImagePath));
            }
            else if (!string.Equals(command, entry.Command, StringComparison.Ordinal))
            {
                changes.Add(new(PostureChangeKinds.Startup, $"Startup entry changed: {entry.Name}",
                    $"{StartupRules.Describe(entry)} now runs {entry.Command} (was {command}).", entry.ImagePath));
            }
        }

        return (changes, updated);
    }
}
