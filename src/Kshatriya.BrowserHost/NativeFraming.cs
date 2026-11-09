using System.Buffers.Binary;

namespace Kshatriya.BrowserHost;

/// <summary>Why a native-messaging frame was rejected.</summary>
internal enum FrameError
{
    None,
    /// <summary>The stream ended in the middle of a frame.</summary>
    Truncated,
    /// <summary>The announced length is zero or larger than the limit (checked before allocating).</summary>
    BadLength,
}

/// <summary>
/// Browser native-messaging framing: a 32-bit length in native (little-endian on Windows) byte order,
/// then that many bytes of UTF-8 JSON.
/// </summary>
internal static class NativeFraming
{
    /// <summary>Largest request the host accepts. Requests are a type and one path.</summary>
    public const int MaxRequestBytes = 64 * 1024;

    /// <summary>Largest reply a browser accepts from a native host (1 MB).</summary>
    public const int MaxReplyBytes = 1024 * 1024;

    /// <summary>Reads one frame. Returns null with <see cref="FrameError.None"/> at a clean end of stream.</summary>
    public static async Task<(byte[]? Message, FrameError Error)> ReadAsync(Stream input, int maxBytes, CancellationToken cancellationToken)
    {
        byte[] header = new byte[4];
        int read = await ReadFullyAsync(input, header, cancellationToken);
        if (read == 0)
        {
            return (null, FrameError.None);
        }

        if (read < header.Length)
        {
            return (null, FrameError.Truncated);
        }

        uint length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length == 0 || length > (uint)maxBytes)
        {
            return (null, FrameError.BadLength);
        }

        byte[] body = new byte[length];
        return await ReadFullyAsync(input, body, cancellationToken) == body.Length ? (body, FrameError.None) : (null, FrameError.Truncated);
    }

    public static async Task WriteAsync(Stream output, ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        if (message.Length is 0 or > MaxReplyBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(message), "Reply must be between 1 byte and 1 MB.");
        }

        byte[] header = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(header, (uint)message.Length);
        await output.WriteAsync(header, cancellationToken);
        await output.WriteAsync(message, cancellationToken);
        await output.FlushAsync(cancellationToken);
    }

    private static async Task<int> ReadFullyAsync(Stream input, byte[] buffer, CancellationToken cancellationToken)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = await input.ReadAsync(buffer.AsMemory(total), cancellationToken);
            if (n == 0)
            {
                break;
            }

            total += n;
        }

        return total;
    }
}
