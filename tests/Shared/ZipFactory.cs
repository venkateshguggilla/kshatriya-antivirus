using System.Buffers.Binary;
using System.IO.Compression;

namespace Kshatriya.Tests.Shared;

/// <summary>Builds ZIP archives in memory for tests.</summary>
internal static class ZipFactory
{
    public static byte[] Create(params (string Name, byte[] Content)[] entries) => Create(CompressionLevel.Optimal, entries);

    public static byte[] Create(CompressionLevel level, params (string Name, byte[] Content)[] entries)
    {
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                ZipArchiveEntry entry = zip.CreateEntry(name, level);
                using Stream s = entry.Open();
                s.Write(content);
            }
        }

        return buffer.ToArray();
    }

    /// <summary>Sets the "encrypted" general-purpose flag on every entry (local and central headers).</summary>
    public static byte[] MarkAllEncrypted(byte[] zip)
    {
        byte[] copy = (byte[])zip.Clone();
        for (int i = 0; i + 4 <= copy.Length; i++)
        {
            uint sig = BinaryPrimitives.ReadUInt32LittleEndian(copy.AsSpan(i));
            if (sig == 0x04034b50 && i + 8 <= copy.Length)
            {
                copy[i + 6] |= 0x01;
            }
            else if (sig == 0x02014b50 && i + 10 <= copy.Length)
            {
                copy[i + 8] |= 0x01;
            }
        }

        return copy;
    }
}
