using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Kshatriya.Core;

namespace Kshatriya.Engines.Pe;

/// <summary>
/// EMBER-style static features of a PE file (feature set "pe-v1", 296 values): a normalised byte
/// histogram (256), a histogram of 1 KiB window entropies (16) and 24 header, section and import facts.
/// Extraction only uses the bounds-checked <see cref="PeImage"/> and the raw bytes; it never executes anything.
/// </summary>
public static class PeFeatures
{
    public const string FeatureSet = "pe-v1";
    public const int Count = 256 + 16 + 24;

    private static readonly HashSet<string> s_standardSections = new(StringComparer.Ordinal)
    {
        ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".idata", ".edata", ".tls", ".bss", ".CRT", ".didat", ".gfids", ".00cfg",
    };

    public static float[] Extract(ReadOnlySpan<byte> data, PeImage image, FileTrust? trust)
    {
        ArgumentNullException.ThrowIfNull(image);
        var f = new float[Count];
        if (data.Length > 0)
        {
            Span<long> counts = stackalloc long[256];
            foreach (byte b in data)
            {
                counts[b]++;
            }

            for (int i = 0; i < 256; i++)
            {
                f[i] = (float)counts[i] / data.Length;
            }

            int windows = 0;
            for (int offset = 0; offset + 1024 <= data.Length && windows < 65_536; offset += 1024, windows++)
            {
                double e = Entropy.Shannon(data.Slice(offset, 1024));
                f[256 + Math.Min(15, (int)(e * 2))]++;
            }

            for (int i = 256; i < 272 && windows > 0; i++)
            {
                f[i] /= windows;
            }
        }

        IReadOnlyList<PeSection> sections = image.Sections;
        PeSection? entry = image.SectionForRva(image.EntryPointRva);
        int g = 272;
        f[g++] = (float)Math.Log2(image.FileSize + 1.0);
        f[g++] = image.Is64Bit ? 1 : 0;
        f[g++] = image.IsDll ? 1 : 0;
        f[g++] = image.IsDotNet ? 1 : 0;
        f[g++] = image.HasCertificateTable ? 1 : 0;
        f[g++] = trust?.IsValid == true ? 1 : 0;
        f[g++] = sections.Count;
        f[g++] = sections.Count(s => s.IsExecutable);
        f[g++] = sections.Count(s => s.IsExecutable && s.IsWritable);
        f[g++] = sections.Count == 0 ? 0 : (float)sections.Max(s => s.Entropy);
        f[g++] = sections.Count == 0 ? 0 : (float)sections.Average(s => s.Entropy);
        f[g++] = entry?.IsExecutable == true ? 1 : 0;
        f[g++] = entry is not null && sections.Count > 0 && ReferenceEquals(entry, sections[^1]) ? 1 : 0;
        f[g++] = (float)(entry?.Entropy ?? 0);
        f[g++] = image.Imports.Select(i => i.Library).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        f[g++] = image.Imports.Count;
        f[g++] = image.ImportsTruncated ? 1 : 0;
        f[g++] = image.FileSize == 0 ? 0 : (float)image.OverlaySize / image.FileSize;
        f[g++] = (float)image.OverlayEntropy;
        f[g++] = image.FileSize == 0 ? 0 : (float)Math.Min(100.0, (double)image.SizeOfImage / image.FileSize);
        f[g++] = image.Subsystem == 2 ? 1 : 0;
        f[g++] = image.Subsystem == 3 ? 1 : 0;
        f[g++] = sections.Count(s => !s_standardSections.Contains(s.Name));
        f[g++] = sections.Count(s => s.IsExecutable && s.RawSize == 0);
        return f;
    }
}

/// <summary>
/// A scoring model delivered as signed content: logistic regression or a gradient-boosted tree ensemble
/// (as exported from LightGBM/XGBoost), evaluated in pure managed code. The score is
/// <c>sigmoid(bias + Σ)</c>; at or above <see cref="Threshold"/> a file is reported as suspicious.
/// Parsing is strict and bounded: trees are acyclic by construction (children always follow their parent).
/// </summary>
public sealed class MlModel
{
    public const int MaxTrees = 5000;
    public const int MaxNodesPerTree = 8192;

    private readonly float[] _weights;
    private readonly Node[][] _trees;

    private MlModel(string name, string detectionName, double bias, double threshold, float[] weights, Node[][] trees, string contentHash)
    {
        Name = name;
        DetectionName = detectionName;
        Bias = bias;
        Threshold = threshold;
        _weights = weights;
        _trees = trees;
        ContentHash = contentHash;
    }

    public string Name { get; }

    public string DetectionName { get; }

    public double Bias { get; }

    public double Threshold { get; }

    /// <summary>First 12 hex digits of the model text's SHA-256 (part of the engine's content version).</summary>
    public string ContentHash { get; }

    public double Score(ReadOnlySpan<float> features)
    {
        if (features.Length != PeFeatures.Count)
        {
            throw new ArgumentException("Wrong feature vector length.", nameof(features));
        }

        double sum = Bias;
        for (int i = 0; i < _weights.Length; i++)
        {
            sum += _weights[i] * features[i];
        }

        foreach (Node[] tree in _trees)
        {
            int n = 0;
            while (tree[n].Feature >= 0)
            {
                n = features[tree[n].Feature] <= tree[n].Threshold ? tree[n].Left : tree[n].Right;
            }

            sum += tree[n].Value;
        }

        return 1.0 / (1.0 + Math.Exp(-sum));
    }

    /// <summary>Parses and validates a model. Throws <see cref="FormatException"/> on anything unexpected.</summary>
    public static MlModel Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        ModelDto dto;
        try
        {
            dto = JsonSerializer.Deserialize(json, ModelJsonContext.Default.ModelDto) ?? throw new FormatException("Empty model.");
        }
        catch (JsonException ex)
        {
            throw new FormatException($"Model is not valid JSON: {ex.Message}", ex);
        }

        if (dto.SchemaVersion != 1 || dto.FeatureSet != PeFeatures.FeatureSet || dto.FeatureCount != PeFeatures.Count)
        {
            throw new FormatException($"Model must be schemaVersion 1 for feature set {PeFeatures.FeatureSet} with {PeFeatures.Count} features.");
        }

        if (string.IsNullOrWhiteSpace(dto.Name) || dto.Name.Length > 64 || !dto.DetectionName.StartsWith("Kshatriya.ML.", StringComparison.Ordinal) || dto.DetectionName.Length > 96)
        {
            throw new FormatException("Model name must be 1-64 characters and detectionName must start with 'Kshatriya.ML.'.");
        }

        if (!double.IsFinite(dto.Bias) || !(dto.Threshold > 0 && dto.Threshold < 1))
        {
            throw new FormatException("Bias must be finite and threshold between 0 and 1.");
        }

        float[] weights = dto.Kind switch
        {
            "logistic" when dto.Weights is { Count: PeFeatures.Count } w && dto.Trees is null => [.. w.Select(Finite)],
            "trees" when dto.Weights is null && dto.Trees is { Count: > 0 and <= MaxTrees } => [],
            _ => throw new FormatException("A model is either 'logistic' with one weight per feature, or 'trees' with 1-5000 trees."),
        };

        Node[][] trees = [.. (dto.Trees ?? []).Select(ParseTree)];
        string hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)))[..12];
        return new MlModel(dto.Name, dto.DetectionName, dto.Bias, dto.Threshold, weights, trees, hash);
    }

    private static Node[] ParseTree(List<List<double>> nodes)
    {
        if (nodes.Count is 0 or > MaxNodesPerTree)
        {
            throw new FormatException($"Each tree needs 1-{MaxNodesPerTree} nodes.");
        }

        var result = new Node[nodes.Count];
        for (int i = 0; i < nodes.Count; i++)
        {
            List<double> n = nodes[i];
            if (n.Count == 1)
            {
                result[i] = new Node(-1, 0, 0, 0, Finite(n[0]));
                continue;
            }

            // [feature, threshold, left, right]; children must come after the parent, so evaluation always terminates.
            if (n.Count != 4 || n[0] != Math.Floor(n[0]) || n[0] < 0 || n[0] >= PeFeatures.Count
                || n[2] != Math.Floor(n[2]) || n[3] != Math.Floor(n[3]) || n[2] <= i || n[3] <= i || n[2] >= nodes.Count || n[3] >= nodes.Count)
            {
                throw new FormatException($"Invalid tree node {i}.");
            }

            result[i] = new Node((int)n[0], Finite(n[1]), (int)n[2], (int)n[3], 0);
        }

        return result;
    }

    private static float Finite(double value) =>
        double.IsFinite(value) && Math.Abs(value) < 1e9 ? (float)value : throw new FormatException("Model values must be finite.");

    private readonly record struct Node(int Feature, float Threshold, int Left, int Right, float Value);
}

/// <summary>
/// Scores PE files with a content-delivered model. Off unless a model is installed and enabled. Results
/// are always <see cref="DetectionCategory.Suspicious"/> (never "malware"), validly signed files are
/// skipped, and nothing here touches the file system: it runs inside the sandboxed worker.
/// </summary>
public sealed class MlEngine : IDetectionEngine
{
    public const string EngineId = "ml";
    public const string EngineVersion = "1.0.0";
    private const long MaxImageBytes = 64L * 1024 * 1024;
    private readonly MlModel _model;

    public MlEngine(MlModel model)
    {
        ArgumentNullException.ThrowIfNull(model);
        _model = model;
        Descriptor = new EngineDescriptor(EngineId, EngineVersion, $"{model.Name}-{model.ContentHash};{PeFeatures.FeatureSet}");
    }

    public EngineDescriptor Descriptor { get; }

    public async ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subject);
        if (subject.Length < 64 || subject.Length > MaxImageBytes || subject.Trust?.IsValid == true)
        {
            return [];
        }

        if (subject.Memory is { } memory)
        {
            // A mapped file is examined in place.
            cancellationToken.ThrowIfCancellationRequested();
            return Evaluate(memory.Prefix(), subject.Trust);
        }

        byte[] data = GC.AllocateUninitializedArray<byte>((int)subject.Length);
        subject.Content.Position = 0;
        await subject.Content.ReadExactlyAsync(data, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return Evaluate(data, subject.Trust);
    }

    private IReadOnlyList<Detection> Evaluate(ReadOnlySpan<byte> data, FileTrust? trust)
    {
        if (data.Length < 2 || data[0] != 'M' || data[1] != 'Z' || !PeImage.TryParse(data, out PeImage? image, out _))
        {
            return [];
        }

        double score = _model.Score(PeFeatures.Extract(data, image!, trust));
        if (score < _model.Threshold)
        {
            return [];
        }

        DetectionConfidence confidence = score >= 0.95 ? DetectionConfidence.Medium : DetectionConfidence.Low;
        return [new Detection(EngineId, _model.DetectionName, DetectionCategory.Suspicious, confidence,
            string.Create(CultureInfo.InvariantCulture, $"Model '{_model.Name}' score {score:F3} (threshold {_model.Threshold:F2}). Machine-learning results are probabilistic; review before acting."))];
    }
}

internal sealed class ModelDto
{
    public required int SchemaVersion { get; init; }

    public required string Name { get; init; }

    public required string DetectionName { get; init; }

    public required string FeatureSet { get; init; }

    public required int FeatureCount { get; init; }

    public required string Kind { get; init; }

    public required double Bias { get; init; }

    public required double Threshold { get; init; }

    public List<double>? Weights { get; init; }

    /// <summary>Each tree is a list of nodes: [value] for a leaf, or [feature, threshold, left, right].</summary>
    public List<List<List<double>>>? Trees { get; init; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectNullableAnnotations = true,
    MaxDepth = 8)]
[JsonSerializable(typeof(ModelDto))]
internal sealed partial class ModelJsonContext : JsonSerializerContext
{
}
