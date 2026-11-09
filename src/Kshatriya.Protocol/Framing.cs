using System.Buffers;
using System.Buffers.Binary;

namespace Kshatriya.Protocol;

/// <summary>Raised when a peer sends something that violates the protocol. The connection must be dropped.</summary>
public sealed class ProtocolException : Exception
{
    public ProtocolException()
    {
    }

    public ProtocolException(string message)
        : base(message)
    {
    }

    public ProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>One decoded frame: a message type, a JSON header and an optional binary tail.</summary>
public sealed class Frame
{
    private readonly byte[] _buffer;
    private readonly int _jsonLength;
    private readonly int _length;

    internal Frame(byte type, byte[] buffer, int jsonLength, int length)
    {
        Type = type;
        _buffer = buffer;
        _jsonLength = jsonLength;
        _length = length;
    }

    public byte Type { get; }

    public ReadOnlyMemory<byte> Json => _buffer.AsMemory(0, _jsonLength);

    public ReadOnlyMemory<byte> Binary => _buffer.AsMemory(_jsonLength, _length - _jsonLength);

    /// <summary>The binary tail as a read-only, seekable stream without copying.</summary>
    public MemoryStream OpenBinary() => new(_buffer, _jsonLength, _length - _jsonLength, writable: false, publiclyVisible: false);
}

/// <summary>Limits applied when reading frames from an untrusted peer.</summary>
/// <param name="MaxFrameBytes">Largest accepted frame (type + header + binary tail).</param>
/// <param name="MaxJsonBytes">Largest accepted JSON header.</param>
public sealed record FrameLimits(int MaxFrameBytes, int MaxJsonBytes)
{
    /// <summary>Control messages only (no binary content).</summary>
    public static FrameLimits Control { get; } = new(1024 * 1024, 1024 * 1024);
}

/// <summary>
/// Length-prefixed framing used for every Kshatriya pipe:
/// <c>u32 length | u8 type | u32 jsonLength | json | binary</c>, little-endian, where <c>length</c>
/// counts everything after itself. Readers enforce limits before allocating.
/// </summary>
public static class FrameIO
{
    private const int PrefixBytes = 4;
    private const int FixedBodyBytes = 1 + 4;

    /// <summary>Largest frame any Kshatriya peer will ever produce or accept (1 GiB + headers).</summary>
    public const int AbsoluteMaxFrameBytes = (1 << 30) + (2 << 20);

    public static async Task WriteAsync(
        Stream stream,
        byte type,
        ReadOnlyMemory<byte> json,
        Stream? binary = null,
        long binaryLength = 0,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegative(binaryLength);
        if (binary is null && binaryLength != 0)
        {
            throw new ArgumentException("A binary length requires a binary stream.", nameof(binaryLength));
        }

        long total = FixedBodyBytes + (long)json.Length + binaryLength;
        if (total > AbsoluteMaxFrameBytes)
        {
            throw new ProtocolException($"Frame of {total} bytes exceeds the protocol maximum.");
        }

        // Small frames (most files) go out in a single write: one system call instead of three or more.
        int headerBytes = PrefixBytes + FixedBodyBytes;
        bool coalesce = headerBytes + total <= CoalesceLimit;
        int capacity = coalesce ? (int)(PrefixBytes + total) : Math.Max(headerBytes + json.Length, 128 * 1024);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(capacity);
        try
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, (uint)total);
            buffer[4] = type;
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(5), (uint)json.Length);
            json.Span.CopyTo(buffer.AsSpan(headerBytes));
            int used = headerBytes + json.Length;

            if (coalesce)
            {
                if (binary is not null && binaryLength > 0)
                {
                    await ReadContentAsync(binary, buffer.AsMemory(used, (int)binaryLength), cancellationToken);
                    used += (int)binaryLength;
                }

                await stream.WriteAsync(buffer.AsMemory(0, used), cancellationToken);
            }
            else
            {
                await stream.WriteAsync(buffer.AsMemory(0, used), cancellationToken);
                long remaining = binaryLength;
                while (binary is not null && remaining > 0)
                {
                    int chunk = (int)Math.Min(buffer.Length, remaining);
                    await ReadContentAsync(binary, buffer.AsMemory(0, chunk), cancellationToken);
                    await stream.WriteAsync(buffer.AsMemory(0, chunk), cancellationToken);
                    remaining -= chunk;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        await stream.FlushAsync(cancellationToken);
    }

    private const int CoalesceLimit = 256 * 1024;

    private static async Task ReadContentAsync(Stream content, Memory<byte> destination, CancellationToken cancellationToken)
    {
        int read = await content.ReadAtLeastAsync(destination, destination.Length, throwOnEndOfStream: false, cancellationToken);
        if (read < destination.Length)
        {
            // The frame is now unusable: the peer expects more bytes. Callers drop the connection.
            throw new IOException("Content ended before the announced length (the file changed while it was read).");
        }
    }

    /// <summary>Reads one frame. Returns null on a clean end of stream at a frame boundary.</summary>
    public static async Task<Frame?> ReadAsync(Stream stream, FrameLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(limits);

        byte[] prefix = new byte[PrefixBytes + FixedBodyBytes];
        int got = await stream.ReadAtLeastAsync(prefix.AsMemory(0, PrefixBytes), PrefixBytes, throwOnEndOfStream: false, cancellationToken);
        if (got == 0)
        {
            return null;
        }

        if (got < PrefixBytes)
        {
            throw new ProtocolException("Connection closed inside a frame header.");
        }

        uint length = BinaryPrimitives.ReadUInt32LittleEndian(prefix);
        if (length < FixedBodyBytes || length > (uint)Math.Min(limits.MaxFrameBytes, AbsoluteMaxFrameBytes))
        {
            throw new ProtocolException($"Frame length {length} is outside the accepted range.");
        }

        await ReadExactlyAsync(stream, prefix.AsMemory(PrefixBytes, FixedBodyBytes), cancellationToken);
        byte type = prefix[PrefixBytes];
        uint jsonLength = BinaryPrimitives.ReadUInt32LittleEndian(prefix.AsSpan(PrefixBytes + 1));
        int bodyLength = (int)length - FixedBodyBytes;
        if (jsonLength > (uint)bodyLength || jsonLength > (uint)limits.MaxJsonBytes)
        {
            throw new ProtocolException($"JSON header length {jsonLength} is invalid.");
        }

        byte[] body = GC.AllocateUninitializedArray<byte>(bodyLength);
        await ReadExactlyAsync(stream, body, cancellationToken);
        return new Frame(type, body, (int)jsonLength, bodyLength);
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int got = await stream.ReadAtLeastAsync(buffer, buffer.Length, throwOnEndOfStream: false, cancellationToken);
        if (got < buffer.Length)
        {
            throw new ProtocolException("Connection closed inside a frame.");
        }
    }
}
