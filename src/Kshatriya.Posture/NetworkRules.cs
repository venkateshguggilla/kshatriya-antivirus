using System.Net;

namespace Kshatriya.Posture;

public sealed record FirewallProfile(string Name, bool? Enabled, bool? DefaultInboundAllow);

/// <summary>A connected network: its name and category ("public", "private" or "domain").</summary>
public sealed record ConnectedNetwork(string Name, string Category, string? InterfaceAlias);

/// <summary>A listening socket and the program behind it.</summary>
public sealed record Listener(string Protocol, string Address, int Port, string? Program);

/// <summary>An active line of the hosts file.</summary>
public sealed record HostsEntry(string Address, string Host);

/// <summary>Wi-Fi security of the connected network, read by the desktop app (location consent).</summary>
public sealed record WifiSnapshot(string Ssid, string Authentication, string Encryption);

/// <summary>What the service read about the network. Null values could not be read.</summary>
public sealed record NetworkSnapshot(
    IReadOnlyList<FirewallProfile> Firewall,
    IReadOnlyList<ConnectedNetwork> Networks,
    bool? Smb1Enabled,
    IReadOnlyList<Listener> Listeners,
    bool? RemoteDesktopEnabled,
    bool? RemoteDesktopNla,
    int? LlmnrPolicy,
    int NetBiosAdapters,
    IReadOnlyList<string> DnsServers,
    IReadOnlyList<HostsEntry> Hosts,
    bool? RouterAdminOverHttp,
    string? DefaultGateway);

/// <summary>Turns a network snapshot into checks (ADR 0022). Every check is read-only.</summary>
public static class NetworkRules
{
    /// <summary>Ports that should not be reachable from other machines on a home PC unless the user chose so.</summary>
    private static readonly Dictionary<int, string> s_exposedPorts = new()
    {
        [21] = "FTP",
        [23] = "Telnet",
        [445] = "file sharing (SMB)",
        [3389] = "Remote Desktop",
        [5900] = "VNC remote control",
        [5985] = "PowerShell remoting (HTTP)",
        [5986] = "PowerShell remoting (HTTPS)",
    };

    /// <summary>Domains whose redirection in the hosts file breaks security updates or enables phishing.</summary>
    private static readonly string[] s_protectedDomains =
    [
        "microsoft.com", "windowsupdate.com", "windows.com", "live.com", "office.com", "msftconnecttest.com",
        "google.com", "apple.com", "github.com", "paypal.com", "amazon.com", "facebook.com",
    ];

    public static IEnumerable<PostureCheck> Evaluate(NetworkSnapshot snapshot, IReadOnlySet<string> applied, WifiSnapshot? wifi = null)
    {
        const PostureArea area = PostureArea.Network;

        if (snapshot.Firewall.Count == 0)
        {
            yield return new("network.firewall", area, PostureState.Unknown, "Windows Firewall", "Could not be read.");
        }

        foreach (FirewallProfile profile in snapshot.Firewall)
        {
            string id = "network.firewall." + profile.Name.ToLowerInvariant();
            yield return profile.Enabled switch
            {
                false => new(id, area, PostureState.Risk, $"Firewall is off for {profile.Name} networks",
                    "Turn it on in Windows Security > Firewall & network protection, unless another firewall product protects this PC."),
                true when profile.DefaultInboundAllow == true => new(id, area, PostureState.Attention, $"Firewall lets everything in on {profile.Name} networks",
                    "The default for incoming connections is Allow. Set it back to Block in Windows Defender Firewall settings."),
                true => new(id, area, PostureState.Ok, $"Firewall is on for {profile.Name} networks", "Unrequested incoming connections are blocked."),
                null => new(id, area, PostureState.Unknown, $"Firewall for {profile.Name} networks", "Could not be read."),
            };
        }

        foreach (ConnectedNetwork network in snapshot.Networks)
        {
            yield return string.Equals(network.Category, "private", StringComparison.OrdinalIgnoreCase)
                ? new("network.category." + Slug(network.Name), area, PostureState.Info, $"'{network.Name}' is a private network",
                    "This PC can be found, and its shared folders reached, by other devices on it. If this is a café, hotel or other shared network, set it to Public in Settings > Network & internet.")
                : new("network.category." + Slug(network.Name), area, PostureState.Ok, $"'{network.Name}' is a {network.Category.ToLowerInvariant()} network",
                    "Network discovery follows that setting.");
        }

        yield return snapshot.Smb1Enabled switch
        {
            true => new("network.smb1", area, PostureState.Risk, "SMBv1 file sharing is enabled",
                "SMBv1 is an outdated protocol used by WannaCry and other worms. Turn it off in 'Turn Windows features on or off' > SMB 1.0/CIFS File Sharing Support."),
            false => new("network.smb1", area, PostureState.Ok, "SMBv1 is off", "The outdated file-sharing protocol is not available."),
            null => new("network.smb1", area, PostureState.Unknown, "SMBv1", "Could not be read."),
        };

        if (snapshot.RemoteDesktopEnabled == true)
        {
            yield return snapshot.RemoteDesktopNla == false
                ? new("network.rdp", area, PostureState.Risk, "Remote Desktop is on without sign-in first",
                    "Network Level Authentication is off, so anyone can reach the sign-in screen. Turn NLA on, or Remote Desktop off, in Settings > System > Remote Desktop.")
                : new("network.rdp", area, PostureState.Attention, "Remote Desktop is on",
                    "Other machines can try to sign in to this PC. Turn it off in Settings > System > Remote Desktop if you do not use it, and use a strong password.");
        }
        else if (snapshot.RemoteDesktopEnabled == false)
        {
            yield return new("network.rdp", area, PostureState.Ok, "Remote Desktop is off", "Nobody can sign in to this PC over the network with Remote Desktop.");
        }

        bool llmnrMine = applied.Contains(Fixes.Llmnr);
        yield return snapshot.LlmnrPolicy == 0
            ? new("network.llmnr", area, PostureState.Ok, "LLMNR name answers are off", "Attackers on the network cannot use them to capture passwords.", Fixes.Llmnr, llmnrMine)
            : new("network.llmnr", area, PostureState.Attention, "LLMNR name answers are on",
                "An attacker on the same network can answer name lookups and capture password hashes. Turn it off unless an old device needs it.", Fixes.Llmnr, llmnrMine);

        if (snapshot.NetBiosAdapters > 0)
        {
            yield return new("network.netbios", area, PostureState.Info, "NetBIOS over TCP/IP is on",
                $"{snapshot.NetBiosAdapters} network adapter(s) answer NetBIOS name queries, which can be abused like LLMNR. It can be turned off in the adapter's IPv4 > Advanced > WINS settings.");
        }

        foreach (PostureCheck check in Listeners(snapshot.Listeners))
        {
            yield return check;
        }

        foreach (PostureCheck check in HostsChecks(snapshot.Hosts))
        {
            yield return check;
        }

        if (snapshot.DnsServers.Count > 0)
        {
            yield return new("network.dns", area, PostureState.Info, "DNS servers",
                string.Join(", ", snapshot.DnsServers) + ". Kshatriya alerts you if these change unexpectedly.");
        }

        if (snapshot.RouterAdminOverHttp == true)
        {
            yield return new("network.router", area, PostureState.Attention, "Your router's admin page uses plain HTTP",
                $"The page at {snapshot.DefaultGateway} can be reached without encryption on this network. Change the router's default password, keep its firmware updated and turn off remote administration.");
        }

        if (wifi is not null)
        {
            yield return Wifi(wifi);
        }
    }

    /// <summary>Wi-Fi security: open, WEP or TKIP networks can be read or impersonated by anyone nearby.</summary>
    public static PostureCheck Wifi(WifiSnapshot wifi)
    {
        const PostureArea area = PostureArea.Network;
        string auth = wifi.Authentication.ToUpperInvariant();
        string enc = wifi.Encryption.ToUpperInvariant();
        if (auth.Contains("OPEN", StringComparison.Ordinal) || auth == "NONE" || enc == "NONE")
        {
            return new("network.wifi", area, PostureState.Risk, $"'{wifi.Ssid}' is an open Wi-Fi network",
                "Anyone nearby can see unencrypted traffic and set up a look-alike network. Use a VPN or a trusted network.");
        }

        if (enc.Contains("WEP", StringComparison.Ordinal) || enc.Contains("TKIP", StringComparison.Ordinal) || auth is "WPA" or "WPAPSK" or "SHAREDKEY")
        {
            return new("network.wifi", area, PostureState.Risk, $"'{wifi.Ssid}' uses outdated Wi-Fi security",
                $"{wifi.Authentication}/{wifi.Encryption} can be broken. Switch the router to WPA2 (AES) or WPA3.");
        }

        return new("network.wifi", area, PostureState.Ok, $"'{wifi.Ssid}' uses {wifi.Authentication}", "The Wi-Fi connection is encrypted.");
    }

    private static IEnumerable<PostureCheck> Listeners(IReadOnlyList<Listener> listeners)
    {
        const PostureArea area = PostureArea.Network;
        var external = listeners.Where(l => !IsLoopback(l.Address)).ToList();
        foreach (IGrouping<int, Listener> group in external.Where(l => s_exposedPorts.ContainsKey(l.Port)).GroupBy(l => l.Port).OrderBy(g => g.Key))
        {
            string program = group.Select(l => l.Program).FirstOrDefault(p => p is not null) ?? "unknown program";
            yield return new($"network.port.{group.Key}", area, PostureState.Attention,
                $"Port {group.Key} ({s_exposedPorts[group.Key]}) is open to the network",
                $"{program} accepts connections from other machines. Turn the feature off if you do not use it; the firewall decides who can actually reach it.");
        }

        int others = external.Count(l => !s_exposedPorts.ContainsKey(l.Port));
        if (others > 0)
        {
            string programs = string.Join(", ", external.Where(l => !s_exposedPorts.ContainsKey(l.Port))
                .Select(l => l.Program ?? "unknown").Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).Take(6));
            yield return new("network.listeners", area, PostureState.Info, $"{others} other program port(s) accept network connections",
                $"Programs: {programs}. The firewall decides which of them other machines can reach.");
        }
    }

    private static bool IsLoopback(string address) =>
        IPAddress.TryParse(address, out IPAddress? ip) && IPAddress.IsLoopback(ip);

    /// <summary>Checks the active hosts file entries.</summary>
    public static IEnumerable<PostureCheck> HostsChecks(IReadOnlyList<HostsEntry> entries)
    {
        const PostureArea area = PostureArea.Network;
        var redirected = entries.Where(e => IsProtected(e.Host) && !IsLocalhostName(e.Host)).ToList();
        if (redirected.Count > 0)
        {
            string sample = string.Join(", ", redirected.Take(4).Select(e => $"{e.Host} → {e.Address}"));
            bool blocking = redirected.All(e => IsBlackhole(e.Address));
            yield return new("network.hosts", area, PostureState.Risk,
                blocking ? "The hosts file blocks important sites" : "The hosts file redirects important sites",
                (blocking
                    ? "Security updates or sign-in may be blocked: "
                    : "Traffic for these sites may go to an attacker: ") + sample + ". Check %SystemRoot%\\System32\\drivers\\etc\\hosts.");
            yield break;
        }

        int custom = entries.Count(e => !IsLocalhostName(e.Host));
        yield return custom == 0
            ? new("network.hosts", area, PostureState.Ok, "The hosts file is clean", "No sites are redirected.")
            : new("network.hosts", area, PostureState.Info, $"The hosts file has {custom} custom entr{(custom == 1 ? "y" : "ies")}",
                "None of them redirect well-known sites. Ad blockers and development tools add entries like these.");
    }

    private static bool IsProtected(string host)
    {
        string h = host.TrimEnd('.').ToLowerInvariant();
        return s_protectedDomains.Any(d => h == d || h.EndsWith("." + d, StringComparison.Ordinal));
    }

    private static bool IsLocalhostName(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.Equals("localhost.localdomain", StringComparison.OrdinalIgnoreCase);

    private static bool IsBlackhole(string address) =>
        address is "0.0.0.0" or "::" or "::1" || address.StartsWith("127.", StringComparison.Ordinal);

    /// <summary>Parses hosts file text: active lines only, at most <paramref name="max"/> entries.</summary>
    public static IReadOnlyList<HostsEntry> ParseHosts(string text, int max = 10_000)
    {
        var entries = new List<HostsEntry>();
        foreach (string raw in text.Split('\n'))
        {
            int hash = raw.IndexOf('#', StringComparison.Ordinal);
            string line = (hash >= 0 ? raw[..hash] : raw).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            string[] parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !IPAddress.TryParse(parts[0], out _))
            {
                continue;
            }

            for (int i = 1; i < parts.Length && entries.Count < max; i++)
            {
                entries.Add(new HostsEntry(parts[0], parts[i]));
            }

            if (entries.Count >= max)
            {
                break;
            }
        }

        return entries;
    }

    internal static string Slug(string name)
    {
        var chars = name.ToLowerInvariant().Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray();
        string slug = new string(chars).Trim('-');
        return slug.Length == 0 ? "network" : slug[..Math.Min(slug.Length, 40)];
    }
}
