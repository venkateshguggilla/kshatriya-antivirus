using System.Globalization;
using Kshatriya.Core;

namespace Kshatriya.Engines.Pe;

/// <summary>Options for the PE heuristic engine.</summary>
public sealed record PeHeuristicOptions
{
    /// <summary>Minimum total score that produces a finding.</summary>
    public int ReportThreshold { get; init; } = 50;

    /// <summary>Score at or above which the finding is reported with medium (instead of low) confidence.</summary>
    public int MediumConfidenceThreshold { get; init; } = 70;

    /// <summary>Images larger than this are not analysed by heuristics.</summary>
    public long MaxImageBytes { get; init; } = 64L * 1024 * 1024;

    /// <summary>
    /// When true (default), files with a valid Authenticode signature are not scored. Signature and rule
    /// engines still examine them. This trades some coverage (signed malware) for far fewer false positives.
    /// </summary>
    public bool SkipValidlySigned { get; init; } = true;
}

/// <summary>Static PE heuristics. Produces at most one <see cref="DetectionCategory.Suspicious"/> finding per image.</summary>
public sealed class PeHeuristicEngine : IDetectionEngine
{
    public const string EngineId = "pe-heuristics";
    public const string EngineVersion = "1.0.0";
    public const string DetectionName = "Kshatriya.Heuristic.SuspiciousPE";

    private readonly PeHeuristicOptions _options;

    public PeHeuristicEngine(PeHeuristicOptions? options = null)
    {
        _options = options ?? new PeHeuristicOptions();
        Descriptor = new EngineDescriptor(EngineId, EngineVersion, string.Create(CultureInfo.InvariantCulture, $"threshold-{_options.ReportThreshold};signed-{(_options.SkipValidlySigned ? "skip" : "scored")}"));
    }

    public EngineDescriptor Descriptor { get; }

    public async ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subject);
        if (subject.Length < 64 || subject.Length > _options.MaxImageBytes || (_options.SkipValidlySigned && subject.Trust?.IsValid == true))
        {
            return [];
        }

        byte[] header = new byte[2];
        subject.Content.Position = 0;
        if (await subject.Content.ReadAtLeastAsync(header, 2, throwOnEndOfStream: false, cancellationToken) < 2 || header[0] != 'M' || header[1] != 'Z')
        {
            return [];
        }

        byte[] data = GC.AllocateUninitializedArray<byte>((int)subject.Length);
        subject.Content.Position = 0;
        await subject.Content.ReadExactlyAsync(data, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        if (!PeImage.TryParse(data, out PeImage? image, out _))
        {
            return []; // Not a well-formed PE; other engines still examine the bytes.
        }

        IReadOnlyList<PeIndicator> indicators = PeHeuristics.Evaluate(image!);
        int score = indicators.Sum(i => i.Weight);
        if (score < _options.ReportThreshold)
        {
            return [];
        }

        DetectionConfidence confidence = score >= _options.MediumConfidenceThreshold ? DetectionConfidence.Medium : DetectionConfidence.Low;
        string description = string.Create(
            CultureInfo.InvariantCulture,
            $"Heuristic score {score}: {string.Join("; ", indicators.Select(i => i.Description))}");

        return [new Detection(EngineId, DetectionName, DetectionCategory.Suspicious, confidence, description)];
    }
}
