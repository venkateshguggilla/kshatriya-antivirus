using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace Sentinel.Service.Net;

/// <summary>One blocked address or range.</summary>
public sealed record BlockEntry(IPAddress Address, int PrefixLength, string Name)
{
    public bool IsIPv4 => Address.AddressFamily == AddressFamily.InterNetwork;

    public override string ToString() => $"{Address}/{PrefixLength}";
}

/// <summary>
/// Parses network blocklists delivered as signed content (<c>*.netblock</c>, header <c># sentinel-netblock v1</c>,
/// then <c>address[/prefix] name</c> per line). Guardrails refuse entries that could cut a machine off:
/// unspecified, loopback, link-local and multicast addresses, and ranges broader than /16 (IPv4) or /48 (IPv6).
/// Any invalid line rejects the whole list.
/// </summary>
public static class NetBlockList
{
    public const string Header = "# sentinel-netblock v1";
    public const int MaxEntries = 10_000;

    public static IReadOnlyList<BlockEntry> Parse(string text, string origin)
    {
        ArgumentNullException.ThrowIfNull(text);
        string[] lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (lines.Length == 0 || lines[0].Trim() != Header)
        {
            throw new FormatException($"{origin}: the first line must be '{Header}'.");
        }

        var entries = new List<BlockEntry>();
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            string[] parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            BlockEntry entry = ParseEntry(parts[0], parts.Length > 1 ? parts[1] : "unnamed", $"{origin} line {i + 1}");
            entries.Add(entry);
            if (entries.Count > MaxEntries)
            {
                throw new FormatException($"{origin}: more than {MaxEntries} entries.");
            }
        }

        return entries;
    }

    private static BlockEntry ParseEntry(string value, string name, string where)
    {
        string[] split = value.Split('/');
        if (split.Length > 2 || !IPAddress.TryParse(split[0], out IPAddress? address) || !SameAddress(address, split[0]))
        {
            throw new FormatException($"{where}: '{value}' is not an IP address or CIDR range.");
        }

        bool v4 = address.AddressFamily == AddressFamily.InterNetwork;
        int max = v4 ? 32 : 128;
        int prefix = max;
        if (split.Length == 2 && (!int.TryParse(split[1], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) || prefix < 0 || prefix > max))
        {
            throw new FormatException($"{where}: invalid prefix length in '{value}'.");
        }

        if (prefix < (v4 ? 16 : 48))
        {
            throw new FormatException($"{where}: '{value}' is broader than /{(v4 ? 16 : 48)}; such ranges are refused.");
        }

        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6Multicast
            || (v4 && ((bytesOf(address)[0] == 169 && bytesOf(address)[1] == 254) || bytesOf(address)[0] >= 224)))
        {
            throw new FormatException($"{where}: '{value}' is a loopback, link-local, multicast or unspecified address; it cannot be blocked.");
        }

        return new BlockEntry(address, prefix, name.Length > 80 ? name[..80] : name);

        static byte[] bytesOf(IPAddress a) => a.GetAddressBytes();
    }

    private static bool SameAddress(IPAddress parsed, string text) =>
        // IPAddress.TryParse accepts forms like "1" or "1.2"; require the canonical dotted or colon form.
        parsed.AddressFamily == AddressFamily.InterNetworkV6 ? text.Contains(':', StringComparison.Ordinal) : text.Count(c => c == '.') == 3;
}

/// <summary>
/// Blocks outbound connections with Windows Filtering Platform filters at the ALE connect layers, in a
/// <em>dynamic</em> session: every filter disappears automatically when the session closes (service stop,
/// crash), so a failure never leaves the machine blocked. Requires administrator or SYSTEM rights.
/// </summary>
public sealed partial class WfpBlocker : IDisposable
{
    // Values from the Windows SDK (fwpmu.h, fwpmtypes.h, fwptypes.h, 10.0.26100.0).
    private static readonly Guid s_layerConnectV4 = new(0xc38d57d1, 0x05a7, 0x4c33, 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82);
    private static readonly Guid s_layerConnectV6 = new(0x4a72393b, 0x319f, 0x44bc, 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4);
    private static readonly Guid s_conditionRemoteAddress = new(0xb235ae9a, 0x1d64, 0x49b8, 0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45);
    private static readonly Guid s_conditionRemotePort = new(0xc35a604d, 0xd22b, 0x4e1a, 0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b);
    private const uint RpcAuthnWinNt = 10;
    private const uint SessionFlagDynamic = 0x1;
    private const uint ActionBlock = 0x1001;
    private const uint MatchEqual = 0;
    private const uint TypeUInt16 = 2;
    private const uint TypeUInt32 = 3;
    private const uint TypeByteArray16 = 11;
    private const uint TypeV4AddrMask = 0x100;
    private const uint TypeV6AddrMask = 0x101;

    private readonly IntPtr _engine;
    private readonly List<ulong> _filters = [];

    private WfpBlocker(IntPtr engine) => _engine = engine;

    public int FilterCount => _filters.Count;

    /// <summary>Native struct sizes, checked by tests against the x64 layouts in the Windows SDK headers.</summary>
    internal static unsafe (int Session, int Filter, int Condition, int V6Mask) StructSizes =>
        (sizeof(Session), sizeof(Filter), sizeof(FilterCondition), sizeof(V6AddrAndMask));

    /// <summary>Opens a dynamic WFP session. Throws <see cref="UnauthorizedAccessException"/> without the required rights.</summary>
    public static unsafe WfpBlocker Open()
    {
        fixed (char* name = "Sentinel network protection")
        {
            var session = new Session { DisplayName = (IntPtr)name, Flags = SessionFlagDynamic };
            uint result = FwpmEngineOpen0(IntPtr.Zero, RpcAuthnWinNt, IntPtr.Zero, &session, out IntPtr engine);
            ThrowIfFailed(result, "open the filtering engine");
            return new WfpBlocker(engine);
        }
    }

    /// <summary>Replaces all filters of this session with blocks for <paramref name="entries"/>, atomically.</summary>
    public void Replace(IReadOnlyList<BlockEntry> entries, ushort? remotePort = null)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ThrowIfFailed(FwpmTransactionBegin0(_engine, 0), "begin a transaction");
        var added = new List<ulong>();
        try
        {
            foreach (ulong id in _filters)
            {
                ThrowIfFailed(FwpmFilterDeleteById0(_engine, id), "remove a filter");
            }

            foreach (BlockEntry entry in entries)
            {
                added.Add(AddFilter(entry, remotePort));
            }

            ThrowIfFailed(FwpmTransactionCommit0(_engine), "commit the filters");
        }
        catch
        {
            _ = FwpmTransactionAbort0(_engine);
            throw;
        }

        _filters.Clear();
        _filters.AddRange(added);
    }

    public void Dispose() => _ = FwpmEngineClose0(_engine);

    private unsafe ulong AddFilter(BlockEntry entry, ushort? remotePort)
    {
        byte[] bytes = entry.Address.GetAddressBytes();
        var v4Mask = new V4AddrAndMask();
        var v6Mask = new V6AddrAndMask();
        var array16 = new ByteArray16();
        var conditions = stackalloc FilterCondition[2];
        conditions[0].FieldKey = s_conditionRemoteAddress;
        conditions[0].MatchType = MatchEqual;
        if (entry.IsIPv4)
        {
            uint address = BinaryPrimitives.ReadUInt32BigEndian(bytes); // host byte order value
            if (entry.PrefixLength == 32)
            {
                conditions[0].Value = new Value { Type = TypeUInt32, Data = address };
            }
            else
            {
                v4Mask.Address = address;
                v4Mask.Mask = entry.PrefixLength == 0 ? 0 : uint.MaxValue << (32 - entry.PrefixLength);
                conditions[0].Value = new Value { Type = TypeV4AddrMask, Data = (ulong)&v4Mask };
            }
        }
        else if (entry.PrefixLength == 128)
        {
            bytes.CopyTo(new Span<byte>(array16.Bytes, 16));
            conditions[0].Value = new Value { Type = TypeByteArray16, Data = (ulong)&array16 };
        }
        else
        {
            bytes.CopyTo(new Span<byte>(v6Mask.Address, 16));
            v6Mask.PrefixLength = (byte)entry.PrefixLength;
            conditions[0].Value = new Value { Type = TypeV6AddrMask, Data = (ulong)&v6Mask };
        }

        uint count = 1;
        if (remotePort is ushort port)
        {
            conditions[1].FieldKey = s_conditionRemotePort;
            conditions[1].MatchType = MatchEqual;
            conditions[1].Value = new Value { Type = TypeUInt16, Data = port };
            count = 2;
        }

        fixed (char* name = $"Sentinel block {entry} ({entry.Name})")
        {
            var filter = new Filter
            {
                DisplayName = (IntPtr)name,
                LayerKey = entry.IsIPv4 ? s_layerConnectV4 : s_layerConnectV6,
                NumFilterConditions = count,
                FilterCondition = (IntPtr)conditions,
                ActionType = ActionBlock,
            };
            ThrowIfFailed(FwpmFilterAdd0(_engine, &filter, IntPtr.Zero, out ulong id), $"add a filter for {entry}");
            return id;
        }
    }

    private static void ThrowIfFailed(uint result, string what)
    {
        if (result == 0)
        {
            return;
        }

        if (result == 5) // ERROR_ACCESS_DENIED
        {
            throw new UnauthorizedAccessException($"Could not {what}: administrator rights are required (0x{result:X8}).");
        }

        throw new InvalidOperationException($"Could not {what} (WFP error 0x{result:X8}).");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Session
    {
        public Guid SessionKey;
        public IntPtr DisplayName;
        public IntPtr DisplayDescription;
        public uint Flags;
        public uint TxnWaitTimeoutInMSec;
        public uint ProcessId;
        public IntPtr Sid;
        public IntPtr Username;
        public int KernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Value
    {
        public uint Type;
        public ulong Data; // union: values up to 64 bits or a pointer
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FilterCondition
    {
        public Guid FieldKey;
        public uint MatchType;
        public Value Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Filter
    {
        public Guid FilterKey;
        public IntPtr DisplayName;
        public IntPtr DisplayDescription;
        public uint Flags;
        public IntPtr ProviderKey;
        public uint ProviderDataSize;
        public IntPtr ProviderData;
        public Guid LayerKey;
        public Guid SubLayerKey;
        public Value Weight;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;
        public uint ActionType;
        public Guid ActionFilterType;
        public ulong ContextLow;   // union { UINT64 rawContext; GUID providerContextKey } (8-byte aligned)
        public ulong ContextHigh;
        public IntPtr Reserved;
        public ulong FilterId;
        public Value EffectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct V4AddrAndMask
    {
        public uint Address;
        public uint Mask;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct V6AddrAndMask
    {
        public fixed byte Address[16];
        public byte PrefixLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct ByteArray16
    {
        public fixed byte Bytes[16];
    }

    [LibraryImport("fwpuclnt.dll")]
    private static unsafe partial uint FwpmEngineOpen0(IntPtr serverName, uint authnService, IntPtr authIdentity, Session* session, out IntPtr engine);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmEngineClose0(IntPtr engine);

    [LibraryImport("fwpuclnt.dll")]
    private static unsafe partial uint FwpmFilterAdd0(IntPtr engine, Filter* filter, IntPtr securityDescriptor, out ulong id);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmFilterDeleteById0(IntPtr engine, ulong id);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmTransactionBegin0(IntPtr engine, uint flags);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmTransactionCommit0(IntPtr engine);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmTransactionAbort0(IntPtr engine);
}

/// <summary>Keeps the WFP filters in line with the blocklists of the active content.</summary>
public sealed class NetworkProtection : IDisposable
{
    private readonly ILogger _logger;
    private readonly Lock _gate = new();
    private WfpBlocker? _blocker;

    public NetworkProtection(ILogger logger) => _logger = logger;

    public string State { get; private set; } = "off";

    public int Blocked { get; private set; }

    /// <summary>Applies the given blocklist; failures are reported in <see cref="State"/>, never thrown (fail open).</summary>
    public void Apply(IReadOnlyList<BlockEntry> entries)
    {
        lock (_gate)
        {
            try
            {
                _blocker ??= WfpBlocker.Open();
                _blocker.Replace(entries);
                Blocked = entries.Count;
                State = entries.Count == 0 ? "on (no blocklist installed)" : $"blocking {entries.Count} address range(s)";
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or DllNotFoundException)
            {
                State = $"unavailable: {ex.Message}";
                Log.RealTimeProblem(_logger, $"Network protection is unavailable: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _blocker?.Dispose();
            _blocker = null;
        }
    }
}
