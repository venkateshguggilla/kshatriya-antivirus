using Sentinel.Core;

namespace Sentinel.Engines;

/// <summary>Identifies an engine and the version of the content (signatures, rules, model) it is using.</summary>
public sealed record EngineDescriptor(string Id, string Version, string ContentVersion)
{
    public EngineInfo ToInfo() => new(Id, Version, ContentVersion);
}

/// <summary>
/// The content an engine is asked to examine. The scan pipeline has already read the content once
/// to compute <see cref="Sha256"/>; engines that need the bytes must rewind <see cref="Content"/>.
/// </summary>
public sealed class ScanSubject
{
    public ScanSubject(string displayPath, long length, string sha256, Stream content)
    {
        ArgumentException.ThrowIfNullOrEmpty(displayPath);
        ArgumentException.ThrowIfNullOrEmpty(sha256);
        ArgumentNullException.ThrowIfNull(content);
        if (!content.CanSeek || !content.CanRead)
        {
            throw new ArgumentException("Content must be a readable, seekable stream.", nameof(content));
        }

        DisplayPath = displayPath;
        Length = length;
        Sha256 = sha256;
        Content = content;
    }

    /// <summary>Path or name used only for reporting. Engines must not open this path themselves.</summary>
    public string DisplayPath { get; }

    public long Length { get; }

    /// <summary>Lower-case hexadecimal SHA-256 of the full content.</summary>
    public string Sha256 { get; }

    /// <summary>Read-only, seekable view of the content. Engines must not write to or dispose it.</summary>
    public Stream Content { get; }
}

/// <summary>
/// A detection engine. Engines are pure: they examine the supplied content and return findings.
/// They must not touch the file system, the network, or any global state, and must honour cancellation
/// promptly because the pipeline enforces per-item time limits through the token.
/// </summary>
public interface IDetectionEngine
{
    EngineDescriptor Descriptor { get; }

    ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken);
}
