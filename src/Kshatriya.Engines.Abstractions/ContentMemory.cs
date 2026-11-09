namespace Kshatriya.Engines;

/// <summary>
/// Read-only content that is already in memory as one contiguous block, typically a mapped view of the file
/// being scanned. Lets engines examine files of any size without copying them; the owner keeps the memory
/// valid until the engines have finished.
/// </summary>
public sealed unsafe class ContentMemory
{
    /// <summary>Largest span .NET can address; engines that need a span get at most this prefix.</summary>
    public const int MaxSpanLength = int.MaxValue;

    public ContentMemory(byte* start, long length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        if (start is null && length > 0)
        {
            throw new ArgumentNullException(nameof(start));
        }

        Start = start;
        Length = length;
    }

    /// <summary>First byte of the content. Engines must not write through it.</summary>
    public byte* Start { get; }

    public long Length { get; }

    /// <summary>The first <paramref name="maxLength"/> bytes (or all of them) as a span.</summary>
    public ReadOnlySpan<byte> Prefix(int maxLength = MaxSpanLength) =>
        new(Start, (int)Math.Min(Length, Math.Max(0, maxLength)));
}
