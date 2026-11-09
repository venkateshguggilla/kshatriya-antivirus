using System.Collections.Concurrent;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Kshatriya.Core;
using static Kshatriya.Engines.Yara.YaraNative;

namespace Kshatriya.Engines.Yara;

/// <summary>A YARA rule source and where it came from (shown in compile errors).</summary>
public sealed record YaraSource(string Text, string Origin);

/// <summary>Options for <see cref="YaraEngine"/>.</summary>
public sealed record YaraEngineOptions
{
    /// <summary>Per-scan time limit enforced inside YARA-X.</summary>
    public TimeSpan ScanTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Content larger than this is not scanned by YARA (the item is then reported incomplete).</summary>
    public long MaxScanBytes { get; init; } = 256L * 1024 * 1024;
}

/// <summary>Raised when YARA sources fail to compile.</summary>
public sealed class YaraCompileException : Exception
{
    public YaraCompileException()
    {
    }

    public YaraCompileException(string message)
        : base(message)
    {
    }

    public YaraCompileException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Pattern-rule engine backed by YARA-X. Compiled rules are shared; each concurrent scan rents its own
/// native scanner. <c>include</c> statements are disabled so rules cannot read arbitrary files.
/// </summary>
public sealed class YaraEngine : IDetectionEngine, IDisposable
{
    public const string EngineId = "yara";
    public const string BuiltInRulesResource = "Kshatriya.Engines.Yara.Rules.kshatriya-builtin.yar";

    private readonly YaraEngineOptions _options;
    private readonly ConcurrentBag<IntPtr> _scanners = [];
    private readonly Lock _lifetime = new();
    private IntPtr _rules;
    private int _activeScans;
    private bool _disposed;

    private YaraEngine(IntPtr rules, int ruleCount, string contentVersion, YaraEngineOptions options)
    {
        _rules = rules;
        _options = options;
        RuleCount = ruleCount;
        Descriptor = new EngineDescriptor(EngineId, $"yara-x-{NativeVersion}", contentVersion);
    }

    /// <summary>Version of the native YARA-X library this build targets.</summary>
    public static string NativeVersion => "1.22.1";

    public EngineDescriptor Descriptor { get; }

    public int RuleCount { get; }

    /// <summary>Returns true if the native YARA-X library can be loaded; otherwise explains why not.</summary>
    public static bool IsAvailable(out string? reason)
    {
        if (!Environment.Is64BitProcess || RuntimeInformation.ProcessArchitecture != Architecture.X64 || !OperatingSystem.IsWindows())
        {
            reason = "The YARA-X engine is currently supported on Windows x64 only.";
            return false;
        }

        if (NativeLibrary.TryLoad(Library, typeof(YaraEngine).Assembly, DllImportSearchPath.AssemblyDirectory, out IntPtr handle))
        {
            NativeLibrary.Free(handle);
            reason = null;
            return true;
        }

        reason = $"{Library}.dll was not found next to the application. Run scripts/Get-YaraX.ps1 and rebuild.";
        return false;
    }

    /// <summary>Loads the rules compiled into Kshatriya.</summary>
    public static YaraSource BuiltInRules()
    {
        using Stream stream = typeof(YaraEngine).Assembly.GetManifestResourceStream(BuiltInRulesResource)
            ?? throw new InvalidOperationException("Built-in YARA rules are missing from the assembly.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return new YaraSource(reader.ReadToEnd(), "builtin:kshatriya-builtin.yar");
    }

    /// <summary>Compiles the given sources. Throws <see cref="YaraCompileException"/> with the compiler's message on error.</summary>
    public static YaraEngine Create(IEnumerable<YaraSource> sources, YaraEngineOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(sources);
        if (!IsAvailable(out string? reason))
        {
            throw new DllNotFoundException(reason);
        }

        Check(CompilerCreate(DisableIncludes, out IntPtr compiler), "create the YARA compiler");
        try
        {
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (YaraSource source in sources)
            {
                if (CompilerAddSource(compiler, source.Text, source.Origin) != Success)
                {
                    throw new YaraCompileException($"YARA rules from '{source.Origin}' failed to compile: {LastErrorMessage()}");
                }

                digest.AppendData(Encoding.UTF8.GetBytes(source.Origin + "\n" + source.Text + "\n"));
            }

            IntPtr rules = CompilerBuild(compiler);
            if (rules == IntPtr.Zero)
            {
                throw new YaraCompileException($"YARA rules could not be built: {LastErrorMessage()}");
            }

            int count = RulesCount(rules);
            string version = string.Create(CultureInfo.InvariantCulture, $"{count}-{Convert.ToHexStringLower(digest.GetHashAndReset())[..12]}");
            return new YaraEngine(rules, count, version, options ?? new YaraEngineOptions());
        }
        finally
        {
            CompilerDestroy(compiler);
        }
    }

    public async ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subject);
        if (subject.Length > _options.MaxScanBytes)
        {
            throw new InvalidOperationException($"Content exceeds the YARA scan limit of {_options.MaxScanBytes} bytes.");
        }

        byte[] data = GC.AllocateUninitializedArray<byte>((int)subject.Length);
        subject.Content.Position = 0;
        await subject.Content.ReadExactlyAsync(data, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return Scan(data);
    }

    /// <summary>Scans a buffer synchronously.</summary>
    public unsafe IReadOnlyList<Detection> Scan(ReadOnlySpan<byte> data)
    {
        IntPtr scanner = RentScanner();
        var collector = new MatchCollector();
        GCHandle handle = GCHandle.Alloc(collector);
        try
        {
            Check(ScannerOnMatchingRule(scanner, &OnMatchingRule, GCHandle.ToIntPtr(handle)), "register the match callback");
            int result;
            fixed (byte* p = data)
            {
                result = ScannerScan(scanner, p, (nuint)data.Length);
            }

            if (result == ScanTimeout)
            {
                throw new EngineTimeoutException($"YARA scan exceeded {_options.ScanTimeout.TotalSeconds:F0}s.");
            }

            Check(result, "scan");
            if (collector.Error is not null)
            {
                throw new InvalidOperationException($"Failed to read a matching rule: {collector.Error}");
            }

            return collector.Detections;
        }
        finally
        {
            handle.Free();
            ReturnScanner(scanner);
        }
    }

    public void Dispose()
    {
        lock (_lifetime)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_activeScans > 0)
            {
                throw new InvalidOperationException("YaraEngine disposed while scans are in progress.");
            }

            while (_scanners.TryTake(out IntPtr scanner))
            {
                ScannerDestroy(scanner);
            }

            // Scanners must be destroyed before the rules they reference.
            RulesDestroy(_rules);
            _rules = IntPtr.Zero;
        }
    }

    private IntPtr RentScanner()
    {
        lock (_lifetime)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _activeScans++;
        }

        if (_scanners.TryTake(out IntPtr scanner))
        {
            return scanner;
        }

        try
        {
            Check(ScannerCreate(_rules, out scanner), "create a YARA scanner");
            ulong seconds = (ulong)Math.Max(1, Math.Ceiling(_options.ScanTimeout.TotalSeconds));
            Check(ScannerSetTimeout(scanner, seconds), "set the scan timeout");
            return scanner;
        }
        catch
        {
            lock (_lifetime)
            {
                _activeScans--;
            }

            throw;
        }
    }

    private void ReturnScanner(IntPtr scanner)
    {
        lock (_lifetime)
        {
            _activeScans--;
            if (_disposed)
            {
                ScannerDestroy(scanner);
                return;
            }
        }

        _scanners.Add(scanner);
    }

    private static void Check(int result, string action)
    {
        if (result != Success)
        {
            throw new InvalidOperationException($"YARA-X failed to {action} (code {result}): {LastErrorMessage()}");
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnMatchingRule(IntPtr rule, IntPtr userData)
    {
        var collector = (MatchCollector)GCHandle.FromIntPtr(userData).Target!;
        try
        {
            collector.Detections.Add(ReadRule(rule));
        }
        catch (Exception ex)
        {
            // Exceptions must never cross the native boundary.
            collector.Error ??= ex.Message;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe void OnMetadata(Metadata* metadata, IntPtr userData)
    {
        var values = (Dictionary<string, string>)GCHandle.FromIntPtr(userData).Target!;
        try
        {
            string? key = Utf8Z(metadata->Identifier);
            if (key is null || values.Count >= 32)
            {
                return;
            }

            string? value = metadata->ValueType switch
            {
                MetaString => Utf8Z(metadata->String),
                MetaI64 => metadata->I64.ToString(CultureInfo.InvariantCulture),
                MetaBoolean => metadata->Boolean != 0 ? "true" : "false",
                MetaF64 => metadata->F64.ToString(CultureInfo.InvariantCulture),
                _ => null,
            };

            if (value is not null)
            {
                values[key] = value.Length > 512 ? value[..512] : value;
            }
        }
        catch (Exception)
        {
            // Ignore unreadable metadata; defaults apply.
        }
    }

    private static unsafe Detection ReadRule(IntPtr rule)
    {
        string identifier = RuleIdentifier(rule, out byte* id, out nuint idLength) == Success ? Utf8(id, idLength) : "unknown";
        string ns = RuleNamespace(rule, out byte* nsPtr, out nuint nsLength) == Success ? Utf8(nsPtr, nsLength) : "default";

        var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        GCHandle handle = GCHandle.Alloc(meta);
        try
        {
            _ = RuleIterMetadata(rule, &OnMetadata, GCHandle.ToIntPtr(handle));
        }
        finally
        {
            handle.Free();
        }

        return RuleMapping.ToDetection(ns, identifier, meta);
    }

    private sealed class MatchCollector
    {
        public List<Detection> Detections { get; } = [];

        public string? Error { get; set; }
    }
}

/// <summary>Maps YARA rule identity and metadata onto a Kshatriya detection, validating every value.</summary>
public static class RuleMapping
{
    public static Detection ToDetection(string ruleNamespace, string identifier, IReadOnlyDictionary<string, string> meta)
    {
        ArgumentNullException.ThrowIfNull(meta);
        string fallback = ruleNamespace is "" or "default" ? identifier : $"{ruleNamespace}.{identifier}";
        string name = meta.TryGetValue("name", out string? n) && IsValidName(n) ? n : SanitizeName(fallback);

        DetectionCategory category = (meta.GetValueOrDefault("category") ?? "").ToLowerInvariant() switch
        {
            "malware" => DetectionCategory.Malware,
            "pua" => DetectionCategory.PotentiallyUnwanted,
            "test" => DetectionCategory.TestFile,
            _ => DetectionCategory.Suspicious,
        };

        DetectionConfidence confidence = (meta.GetValueOrDefault("confidence") ?? "").ToLowerInvariant() switch
        {
            "high" => DetectionConfidence.High,
            "low" => DetectionConfidence.Low,
            _ => DetectionConfidence.Medium,
        };

        string description = meta.TryGetValue("description", out string? d) && d.Length > 0
            ? d
            : $"Matched YARA rule {fallback}.";

        return new Detection(YaraEngine.EngineId, name, category, confidence, description);
    }

    private static bool IsValidName(string value) =>
        value.Length is > 0 and <= 128 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '/' or ':');

    private static string SanitizeName(string value)
    {
        var sb = new StringBuilder();
        foreach (char c in value)
        {
            if (sb.Length >= 128)
            {
                break;
            }

            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '/' or ':' ? c : '_');
        }

        return sb.Length == 0 ? "Yara.Unnamed" : sb.ToString();
    }
}
