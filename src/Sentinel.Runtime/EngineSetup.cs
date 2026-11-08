using System.Text;
using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Engines.Hash;
using Sentinel.Engines.Pe;
using Sentinel.Engines.Yara;
using Sentinel.Protocol;
using Sentinel.Scanning;

namespace Sentinel.Runtime;

/// <summary>Signature or rule text plus where it came from (for error messages).</summary>
public sealed record TextSource(string Origin, string Text);

/// <summary>
/// Everything needed to build the detection engines. It carries file <i>contents</i>, not paths, so
/// that sandboxed workers can build engines without opening any file.
/// </summary>
public sealed record EngineConfiguration
{
    public IReadOnlyList<TextSource> HashDatabases { get; init; } = [];

    public IReadOnlyList<TextSource> YaraRules { get; init; } = [];

    /// <summary>Machine-learning models (JSON). Empty means the ML engine is off.</summary>
    public IReadOnlyList<TextSource> Models { get; init; } = [];

    /// <summary>When true, a missing YARA engine is an error rather than a warning (set when custom rules are supplied).</summary>
    public bool YaraRequired { get; init; }

    public bool Heuristics { get; init; } = true;

    public bool HeuristicsIncludeSigned { get; init; }

    public long MaxScanBytes { get; init; } = new ScanLimits().MaxFileSizeBytes;

    public ArchiveLimits Archives { get; init; } = new();

    /// <summary>Reads signature databases and rule files. Called by the broker (CLI or service), never by a worker.</summary>
    public static EngineConfiguration FromFiles(IEnumerable<string> signatureFiles, IEnumerable<string> ruleFiles)
    {
        ArgumentNullException.ThrowIfNull(signatureFiles);
        ArgumentNullException.ThrowIfNull(ruleFiles);
        TextSource[] rules = [.. ruleFiles.Select(f => new TextSource(Path.GetFileName(f), File.ReadAllText(f, Encoding.UTF8)))];
        return new EngineConfiguration
        {
            HashDatabases = [.. signatureFiles.Select(f => new TextSource(f, File.ReadAllText(f, Encoding.UTF8)))],
            YaraRules = rules,
            YaraRequired = rules.Length > 0,
        };
    }

    public EngineConfigDto ToDto() => new()
    {
        HashDatabases = [.. HashDatabases.Select(s => new TextSourceDto { Origin = s.Origin, Text = s.Text })],
        YaraRules = [.. YaraRules.Select(s => new TextSourceDto { Origin = s.Origin, Text = s.Text })],
        Models = [.. Models.Select(s => new TextSourceDto { Origin = s.Origin, Text = s.Text })],
        YaraRequired = YaraRequired,
        Heuristics = Heuristics,
        HeuristicsIncludeSigned = HeuristicsIncludeSigned,
        MaxScanBytes = MaxScanBytes,
        Archives = Archives.ToDto(),
    };

    public static EngineConfiguration FromDto(EngineConfigDto dto)
    {
        ArgumentNullException.ThrowIfNull(dto);
        return new EngineConfiguration
        {
            HashDatabases = [.. dto.HashDatabases.Select(s => new TextSource(s.Origin, s.Text))],
            YaraRules = [.. dto.YaraRules.Select(s => new TextSource(s.Origin, s.Text))],
            Models = [.. dto.Models.Select(s => new TextSource(s.Origin, s.Text))],
            YaraRequired = dto.YaraRequired,
            Heuristics = dto.Heuristics,
            HeuristicsIncludeSigned = dto.HeuristicsIncludeSigned,
            MaxScanBytes = dto.MaxScanBytes,
            Archives = dto.Archives.ToDomain(),
        };
    }
}

/// <summary>Raised when engines cannot be built (bad signature database, rule compile error, missing YARA).</summary>
public sealed class EngineSetupException : Exception
{
    public EngineSetupException()
    {
    }

    public EngineSetupException(string message)
        : base(message)
    {
    }

    public EngineSetupException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>A built set of engines. Disposing it releases native resources (YARA).</summary>
public sealed class EngineSet : IDisposable
{
    private readonly YaraEngine? _yara;

    internal EngineSet(IReadOnlyList<IDetectionEngine> engines, IReadOnlyList<string> warnings, YaraEngine? yara)
    {
        Engines = engines;
        Warnings = warnings;
        _yara = yara;
    }

    public IReadOnlyList<IDetectionEngine> Engines { get; }

    public IReadOnlyList<string> Warnings { get; }

    public void Dispose() => _yara?.Dispose();
}

/// <summary>Builds engines from an <see cref="EngineConfiguration"/>.</summary>
public static class EngineSetup
{
    public static EngineSet Build(EngineConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var engines = new List<IDetectionEngine>();
        var warnings = new List<string>();
        YaraEngine? yara = null;
        try
        {
            engines.Add(HashEngine.CreateDefault(configuration.HashDatabases.Select(s => HashSignatureDatabase.Parse(s.Text, s.Origin))));

            if (YaraEngine.IsAvailable(out string? unavailable))
            {
                var sources = new List<YaraSource> { YaraEngine.BuiltInRules() };
                sources.AddRange(configuration.YaraRules.Select(r => new YaraSource(r.Text, r.Origin)));
                yara = YaraEngine.Create(sources, new YaraEngineOptions { MaxScanBytes = configuration.MaxScanBytes });
                engines.Add(yara);
            }
            else if (configuration.YaraRequired)
            {
                throw new EngineSetupException($"Custom rules require the YARA engine, which is unavailable: {unavailable}");
            }
            else
            {
                warnings.Add($"YARA engine unavailable ({unavailable}). Scanning without YARA rules.");
            }

            if (configuration.Heuristics)
            {
                engines.Add(new PeHeuristicEngine(new PeHeuristicOptions { SkipValidlySigned = !configuration.HeuristicsIncludeSigned }));
            }

            foreach (TextSource model in configuration.Models)
            {
                try
                {
                    engines.Add(new MlEngine(MlModel.Parse(model.Text)));
                }
                catch (FormatException ex)
                {
                    throw new EngineSetupException($"Could not load model '{model.Origin}': {ex.Message}", ex);
                }
            }

            return new EngineSet(engines, warnings, yara);
        }
        catch (FormatException ex)
        {
            yara?.Dispose();
            throw new EngineSetupException($"Could not load signatures: {ex.Message}", ex);
        }
        catch (YaraCompileException ex)
        {
            yara?.Dispose();
            throw new EngineSetupException(ex.Message, ex);
        }
        catch
        {
            yara?.Dispose();
            throw;
        }
    }

    /// <summary>Builds an in-process analyzer and the engine set it depends on.</summary>
    public static (InProcessAnalyzer Analyzer, EngineSet Engines) BuildInProcess(EngineConfiguration configuration)
    {
        EngineSet set = Build(configuration);
        return (new InProcessAnalyzer(set.Engines, configuration.Archives, configuration.MaxScanBytes), set);
    }
}
