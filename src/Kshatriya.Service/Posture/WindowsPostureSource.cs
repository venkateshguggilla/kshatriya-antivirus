using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Xml;
using Kshatriya.Posture;
using Kshatriya.Scanning;
using Microsoft.Win32;

namespace Kshatriya.Service.Posture;

/// <summary>Reads the system settings the security check needs (ADR 0022). Every method only reads.</summary>
public interface IPostureSource
{
    DefenderSnapshot ReadDefender();

    /// <summary>UAC and installer settings; <paramref name="userSid"/> selects whose user policy is read.</summary>
    InstallSnapshot ReadInstalls(string? userSid);

    int? ReadAutoRunPolicy();

    NetworkSnapshot ReadNetwork();

    IReadOnlyList<GatewayObservation> ReadGateways();

    /// <summary>Startup entries for the machine and the given users (null: every loaded user profile).</summary>
    IReadOnlyList<StartupEntry> ReadStartup(IReadOnlySet<string>? userSids);
}

/// <summary>Reads settings from the registry, WMI and IP Helper as the service (LocalSystem).</summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class WindowsPostureSource : IPostureSource
{
    private const string UacKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string InstallerPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows\Installer";
    private const string ExplorerPolicyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    private const string DnsClientPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const int MaxTaskFileBytes = 1 << 20;
    private const int MaxHostsBytes = 4 << 20;
    private const int MaxEntriesPerSource = 5_000;

    public DefenderSnapshot ReadDefender()
    {
        const string scope = @"root\Microsoft\Windows\Defender";
        try
        {
            ManagementBaseObject? status = Wmi.First(scope, "SELECT AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureLastUpdated, AMRunningMode FROM MSFT_MpComputerStatus");
            if (status is null)
            {
                return new DefenderSnapshot(false, null, null, null, null, new Dictionary<string, int>(), "Defender did not report its status.");
            }

            string mode = status["AMRunningMode"] as string ?? "Normal";
            if (status["AntivirusEnabled"] is false || !mode.Equals("Normal", StringComparison.OrdinalIgnoreCase))
            {
                return new DefenderSnapshot(false, null, null, null, null, new Dictionary<string, int>(),
                    $"Microsoft Defender Antivirus is in '{mode}' mode, so another antivirus is probably active.");
            }

            ManagementBaseObject? prefs = Wmi.First(scope, "SELECT MAPSReporting, AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions FROM MSFT_MpPreference");
            var asr = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (prefs?["AttackSurfaceReductionRules_Ids"] is string[] ids && prefs["AttackSurfaceReductionRules_Actions"] is Array actions)
            {
                for (int i = 0; i < ids.Length && i < actions.Length; i++)
                {
                    asr[ids[i].Trim().ToLowerInvariant()] = Convert.ToInt32(actions.GetValue(i), CultureInfo.InvariantCulture);
                }
            }

            bool? cloud = prefs?["MAPSReporting"] is { } maps ? Convert.ToInt32(maps, CultureInfo.InvariantCulture) != 0 : null;
            DateTimeOffset? updated = status["AntivirusSignatureLastUpdated"] is string cim ? new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(cim)) : null;
            return new DefenderSnapshot(true, status["RealTimeProtectionEnabled"] as bool?, status["IsTamperProtected"] as bool?, cloud, updated?.ToUniversalTime(), asr);
        }
        catch (Exception ex) when (Wmi.IsExpected(ex))
        {
            return new DefenderSnapshot(false, null, null, null, null, new Dictionary<string, int>(), $"Defender status could not be read: {ex.Message}");
        }
    }

    public InstallSnapshot ReadInstalls(string? userSid)
    {
        using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        int? lua = Reg.Int(machine, UacKey, "EnableLUA");
        int? consent = Reg.Int(machine, UacKey, "ConsentPromptBehaviorAdmin");
        int? secure = Reg.Int(machine, UacKey, "PromptOnSecureDesktop");
        int? aieMachine = Reg.Int(machine, InstallerPolicyKey, "AlwaysInstallElevated");
        int? aieUser = null;
        if (userSid is not null && Reg.IsUserSid(userSid))
        {
            using RegistryKey users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
            aieUser = Reg.Int(users, $@"{userSid}\{InstallerPolicyKey}", "AlwaysInstallElevated");
        }

        // Administrator protection exists on Windows 11 24H2 (build 26100) and later. The policy's registry value
        // is not documented on the pages reviewed; TypeOfAdminApprovalMode=2 is reported as on, anything else
        // as available. This only changes an informational line, never a fix.
        bool? adminProtection = Environment.OSVersion.Version.Build >= 26100
            ? Reg.Int(machine, UacKey, "TypeOfAdminApprovalMode") == 2
            : null;
        return new InstallSnapshot(lua, consent, secure, aieMachine, aieUser, adminProtection);
    }

    public int? ReadAutoRunPolicy()
    {
        using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        return Reg.Int(machine, ExplorerPolicyKey, "NoDriveTypeAutoRun");
    }

    public NetworkSnapshot ReadNetwork()
    {
        const string cimv2 = @"root\StandardCimv2";
        var firewall = new List<FirewallProfile>();
        foreach (ManagementBaseObject p in Wmi.Query(cimv2, "SELECT Name, Enabled, DefaultInboundAction FROM MSFT_NetFirewallProfile", activeStore: true))
        {
            // Enabled: 0 false, 1 true, 2 not configured (on by default). DefaultInboundAction: 2 allow, 4 block, 0 not configured (block).
            int enabled = Wmi.Int(p["Enabled"]) ?? 2;
            int inbound = Wmi.Int(p["DefaultInboundAction"]) ?? 0;
            firewall.Add(new FirewallProfile(p["Name"] as string ?? "?", enabled != 0, inbound == 2));
        }

        var networks = new List<ConnectedNetwork>();
        foreach (ManagementBaseObject n in Wmi.Query(cimv2, "SELECT Name, NetworkCategory, InterfaceAlias FROM MSFT_NetConnectionProfile"))
        {
            string category = (Wmi.Int(n["NetworkCategory"]) ?? 0) switch { 1 => "Private", 2 => "Domain", _ => "Public" };
            networks.Add(new ConnectedNetwork(n["Name"] as string ?? "network", category, n["InterfaceAlias"] as string));
        }

        bool? smb1 = ReadSmb1();
        var listeners = ReadListeners();

        using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        const string tsPolicy = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
        int? deny = Reg.Int(machine, tsPolicy, "fDenyTSConnections") ?? Reg.Int(machine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
        int? nla = Reg.Int(machine, tsPolicy, "UserAuthentication") ?? Reg.Int(machine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
        int? llmnr = Reg.Int(machine, DnsClientPolicyKey, "EnableMulticast");

        int netbios = 0;
        var dns = new List<string>();
        string? gateway = null;
        foreach (ManagementBaseObject a in Wmi.Query(@"root\cimv2", "SELECT TcpipNetbiosOptions, DNSServerSearchOrder, DefaultIPGateway FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"))
        {
            if ((Wmi.Int(a["TcpipNetbiosOptions"]) ?? 0) != 2)
            {
                netbios++;
            }

            if (a["DNSServerSearchOrder"] is string[] servers)
            {
                dns.AddRange(servers);
            }

            if (gateway is null && a["DefaultIPGateway"] is string[] gateways)
            {
                gateway = gateways.FirstOrDefault(g => IPAddress.TryParse(g, out IPAddress? ip) && ip.AddressFamily == AddressFamily.InterNetwork);
            }
        }

        return new NetworkSnapshot(
            firewall,
            networks,
            smb1,
            listeners,
            deny is null ? null : deny == 0,
            nla is null ? (deny == 0 ? true : null) : nla != 0,
            llmnr,
            netbios,
            [.. dns.Distinct(StringComparer.OrdinalIgnoreCase)],
            ReadHosts(),
            gateway is null ? null : RouterAnswersHttp(gateway),
            gateway);
    }

    public IReadOnlyList<GatewayObservation> ReadGateways()
    {
        var result = new List<GatewayObservation>();
        var names = new Dictionary<uint, string>();
        foreach (ManagementBaseObject n in Wmi.Query(@"root\StandardCimv2", "SELECT Name, InterfaceIndex FROM MSFT_NetConnectionProfile"))
        {
            if (n["InterfaceIndex"] is uint index)
            {
                names[index] = n["Name"] as string ?? "network";
            }
        }

        foreach (ManagementBaseObject a in Wmi.Query(@"root\cimv2", "SELECT InterfaceIndex, DefaultIPGateway FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"))
        {
            if (a["DefaultIPGateway"] is not string[] gateways || a["InterfaceIndex"] is not uint index)
            {
                continue;
            }

            foreach (string gw in gateways.Where(g => IPAddress.TryParse(g, out IPAddress? ip) && ip.AddressFamily == AddressFamily.InterNetwork))
            {
                ManagementBaseObject? neighbor = Wmi.First(@"root\StandardCimv2",
                    $"SELECT LinkLayerAddress FROM MSFT_NetNeighbor WHERE IPAddress = '{gw}' AND InterfaceIndex = {index}");
                if (neighbor?["LinkLayerAddress"] is string mac && mac.Length > 0 && mac != "00-00-00-00-00-00")
                {
                    result.Add(new GatewayObservation(names.TryGetValue(index, out string? name) ? name : "network", gw, mac));
                }
            }
        }

        return result;
    }

    public IReadOnlyList<StartupEntry> ReadStartup(IReadOnlySet<string>? userSids)
    {
        var entries = new List<StartupEntry>();
        using RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        foreach (string key in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" })
        {
            AddRunKey(entries, machine, key, "HKLM\\" + key, StartupKinds.RunKey, "machine");
        }

        foreach (string key in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" })
        {
            AddRunKey(entries, machine, key, "HKLM\\" + key, StartupKinds.RunOnceKey, "machine");
        }

        using RegistryKey users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        foreach (string sid in users.GetSubKeyNames().Where(Reg.IsUserSid).Where(s => userSids is null || userSids.Contains(s)))
        {
            AddRunKey(entries, users, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Run", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", StartupKinds.RunKey, sid);
            AddRunKey(entries, users, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\RunOnce", @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", StartupKinds.RunOnceKey, sid);
            if (Reg.String(machine, $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}", "ProfileImagePath") is { } profile)
            {
                AddFolder(entries, Path.Combine(Environment.ExpandEnvironmentVariables(profile), @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), sid);
            }
        }

        AddFolder(entries, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\StartUp"), "machine");
        AddServices(entries, machine);
        AddTasks(entries);
        AddWmiConsumers(entries);
        return entries;
    }

    private static void AddRunKey(List<StartupEntry> entries, RegistryKey root, string path, string display, string kind, string scope)
    {
        using RegistryKey? key = Reg.Open(root, path);
        if (key is null)
        {
            return;
        }

        foreach (string name in key.GetValueNames().Take(MaxEntriesPerSource))
        {
            if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string command)
            {
                entries.Add(new StartupEntry(kind, scope, display, name.Length == 0 ? "(default)" : name, command));
            }
        }
    }

    private static void AddFolder(List<StartupEntry> entries, string folder, string scope)
    {
        if (!Directory.Exists(folder))
        {
            return;
        }

        // Names only: shortcut contents are not opened. Links are not followed (SafeFileEnumerator).
        foreach (WalkEntry entry in SafeFileEnumerator.Walk(folder).Where(e => e.IsCandidate).Take(MaxEntriesPerSource))
        {
            string name = Path.GetFileName(entry.Path);
            if (!name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
            {
                entries.Add(new StartupEntry(StartupKinds.StartupFolder, scope, folder, name, entry.Path));
            }
        }
    }

    private static void AddServices(List<StartupEntry> entries, RegistryKey machine)
    {
        using RegistryKey? services = Reg.Open(machine, @"SYSTEM\CurrentControlSet\Services");
        if (services is null)
        {
            return;
        }

        foreach (string name in services.GetSubKeyNames().Take(MaxEntriesPerSource))
        {
            using RegistryKey? service = Reg.Open(services, name);
            if (service is null)
            {
                continue;
            }

            // Win32 services (own or shared process) that start automatically; drivers are out of scope here.
            int type = service.GetValue("Type") is int t ? t : 0;
            int start = service.GetValue("Start") is int s ? s : 4;
            if ((type & 0x30) == 0 || start > 2 || service.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string image)
            {
                continue;
            }

            using RegistryKey? parameters = Reg.Open(service, "Parameters");
            string command = parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string dll ? $"{image} ({dll})" : image;
            entries.Add(new StartupEntry(StartupKinds.Service, "machine", @"HKLM\SYSTEM\CurrentControlSet\Services", name, command));
        }
    }

    private static void AddTasks(List<StartupEntry> entries)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
        if (!Directory.Exists(root))
        {
            return;
        }

        int count = 0;
        foreach (WalkEntry file in SafeFileEnumerator.Walk(root).Where(e => e.IsCandidate && e.Length <= MaxTaskFileBytes))
        {
            if (++count > MaxEntriesPerSource)
            {
                break;
            }

            string? xml = ReadText(file.Path, MaxTaskFileBytes);
            if (xml is null)
            {
                continue;
            }

            foreach (string command in TaskCommands(xml))
            {
                entries.Add(new StartupEntry(StartupKinds.ScheduledTask, "machine", file.Path[root.Length..].Replace('\\', '/'), Path.GetFileName(file.Path), command));
            }
        }
    }

    /// <summary>The Exec actions of a task definition (Command plus Arguments). Untrusted XML: no DTDs, bounded.</summary>
    internal static IEnumerable<string> TaskCommands(string xml)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaxTaskFileBytes };
        var commands = new List<string>();
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            string? command = null;
            reader.Read();
            while (!reader.EOF)
            {
                // ReadElementContentAsString already moves to the next node, so it must not be followed by Read().
                if (reader.NodeType == XmlNodeType.Element && reader.LocalName == "Command")
                {
                    if (command is not null)
                    {
                        commands.Add(command);
                    }

                    command = reader.ReadElementContentAsString().Trim();
                }
                else if (reader.NodeType == XmlNodeType.Element && reader.LocalName == "Arguments" && command is not null)
                {
                    commands.Add($"{command} {reader.ReadElementContentAsString().Trim()}");
                    command = null;
                }
                else
                {
                    reader.Read();
                }
            }

            if (command is not null)
            {
                commands.Add(command);
            }
        }
        catch (XmlException)
        {
            // Not a task definition; ignored.
        }

        return commands.Take(32);
    }

    private static void AddWmiConsumers(List<StartupEntry> entries)
    {
        foreach (ManagementBaseObject c in Wmi.Query(@"root\subscription", "SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer").Take(MaxEntriesPerSource))
        {
            string command = c["CommandLineTemplate"] as string ?? c["ExecutablePath"] as string ?? "(no command)";
            entries.Add(new StartupEntry(StartupKinds.WmiSubscription, "machine", @"root\subscription", c["Name"] as string ?? "?", command));
        }

        foreach (ManagementBaseObject c in Wmi.Query(@"root\subscription", "SELECT Name, ScriptFileName, ScriptingEngine FROM ActiveScriptEventConsumer").Take(MaxEntriesPerSource))
        {
            string command = c["ScriptFileName"] as string is { Length: > 0 } file ? file : $"(inline {c["ScriptingEngine"] as string ?? "script"})";
            entries.Add(new StartupEntry(StartupKinds.WmiSubscription, "machine", @"root\subscription", c["Name"] as string ?? "?", command));
        }
    }

    private static bool? ReadSmb1()
    {
        ManagementBaseObject? feature = Wmi.First(@"root\cimv2", "SELECT InstallState FROM Win32_OptionalFeature WHERE Name = 'SMB1Protocol'");
        if (feature is not null && Wmi.Int(feature["InstallState"]) != 1)
        {
            return false;
        }

        ManagementBaseObject? config = Wmi.First(@"root\Microsoft\Windows\SMB", "SELECT EnableSMB1Protocol FROM MSFT_SmbServerConfiguration");
        return config?["EnableSMB1Protocol"] as bool? ?? (feature is null ? null : true);
    }

    private static List<Listener> ReadListeners()
    {
        var listeners = new List<Listener>();
        var names = new Dictionary<uint, string?>();
        foreach (ManagementBaseObject c in Wmi.Query(@"root\StandardCimv2", "SELECT LocalAddress, LocalPort, OwningProcess FROM MSFT_NetTCPConnection WHERE State = 2").Take(MaxEntriesPerSource))
        {
            uint pid = c["OwningProcess"] is uint p ? p : 0;
            if (!names.TryGetValue(pid, out string? program))
            {
                program = ProcessName(pid);
                names[pid] = program;
            }

            listeners.Add(new Listener("tcp", c["LocalAddress"] as string ?? "?", Wmi.Int(c["LocalPort"]) ?? 0, program));
        }

        return listeners;
    }

    private static string? ProcessName(uint pid)
    {
        if (pid == 0)
        {
            return null;
        }

        if (pid == 4)
        {
            return "System";
        }

        try
        {
            using var process = Process.GetProcessById((int)pid);
            return process.ProcessName + ".exe";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    private static IReadOnlyList<HostsEntry> ReadHosts()
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
        string? text = ReadText(path, MaxHostsBytes);
        return text is null ? [] : NetworkRules.ParseHosts(text);
    }

    /// <summary>Reads a small text file read-only, without following links, up to <paramref name="max"/> bytes.</summary>
    private static string? ReadText(string path, int max)
    {
        OpenResult open = SafeFileOpener.Open(path);
        if (!open.Success)
        {
            return null;
        }

        using var stream = new FileStream(open.Handle!, FileAccess.Read);
        if (stream.Length > max)
        {
            return null;
        }

        using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    /// <summary>One TCP connection to a private-address gateway on port 80, 1 second timeout. Nothing is sent.</summary>
    private static bool? RouterAnswersHttp(string gateway)
    {
        if (!IPAddress.TryParse(gateway, out IPAddress? ip) || !IsPrivate(ip))
        {
            return null;
        }

        try
        {
            using var client = new TcpClient();
            return client.ConnectAsync(ip, 80).Wait(TimeSpan.FromSeconds(1)) && client.Connected;
        }
        catch (Exception ex) when (ex is SocketException or AggregateException)
        {
            return false;
        }
    }

    private static bool IsPrivate(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        return ip.AddressFamily == AddressFamily.InterNetwork
            && (b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168));
    }

    private static class Reg
    {
        public static RegistryKey? Open(RegistryKey root, string path)
        {
            try
            {
                return root.OpenSubKey(path, writable: false);
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                return null;
            }
        }

        public static int? Int(RegistryKey root, string path, string name)
        {
            using RegistryKey? key = Open(root, path);
            return key?.GetValue(name) switch
            {
                int i => i,
                long l => (int)l,
                string s when int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out int v) => v,
                _ => null,
            };
        }

        public static string? String(RegistryKey root, string path, string name)
        {
            using RegistryKey? key = Open(root, path);
            return key?.GetValue(name) as string;
        }

        /// <summary>Interactive user SIDs (S-1-5-21-...), excluding the *_Classes hives.</summary>
        public static bool IsUserSid(string sid) =>
            sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !sid.EndsWith("_Classes", StringComparison.Ordinal);
    }
}

/// <summary>Small WMI helpers: every failure becomes "no result", never an exception.</summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
internal static class Wmi
{
    public static bool IsExpected(Exception ex) =>
        ex is ManagementException or COMException or UnauthorizedAccessException or InvalidCastException or ArgumentException;

    public static List<ManagementBaseObject> Query(string scope, string wql, bool activeStore = false)
    {
        try
        {
            var options = new System.Management.EnumerationOptions { ReturnImmediately = false, Timeout = TimeSpan.FromSeconds(20) };
            if (activeStore)
            {
                // Effective settings (local plus Group Policy), not only the local store.
                options.Context = new ManagementNamedValueCollection { { "PolicyStore", "ActiveStore" } };
            }

            using var searcher = new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(wql), options);
            return [.. searcher.Get().Cast<ManagementBaseObject>()];
        }
        catch (Exception ex) when (IsExpected(ex))
        {
            return [];
        }
    }

    public static ManagementBaseObject? First(string scope, string wql) => Query(scope, wql).FirstOrDefault();

    public static int? Int(object? value) => value switch
    {
        null => null,
        IConvertible c => Convert.ToInt32(c, CultureInfo.InvariantCulture),
        _ => null,
    };
}
