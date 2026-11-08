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
    public ScanSubject(string displayPath, long length, string sha256, Stream content, FileTrust? trust = null, string? location = null)
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
        Trust = trust;
        Location = location;
    }

    /// <summary>Path or name used only for reporting. Engines must not open this path themselves.</summary>
    public string DisplayPath { get; }

    public long Length { get; }

    /// <summary>Lower-case hexadecimal SHA-256 of the full content.</summary>
    public string Sha256 { get; }

    /// <summary>Read-only, seekable view of the content. Engines must not write to or dispose it.</summary>
    public Stream Content { get; }

    /// <summary>Authenticode result for the top-level file, when it was checked. Null for archive entries and streams.</summary>
    public FileTrust? Trust { get; }

    /// <summary>Path inside a container, or null for a top-level item.</summary>
    public string? Location { get; }
}

/// <summary>
/// Thrown by an engine when its own time budget elapsed. The pipeline reports the item as
/// <see cref="ScanReason.Timeout"/> rather than as an engine failure.
/// </summary>
public sealed class EngineTimeoutException : Exception
{
    public EngineTimeoutException()
    {
    }

    public EngineTimeoutException(string message)
        : base(message)
    {
    }

    public EngineTimeoutException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
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
