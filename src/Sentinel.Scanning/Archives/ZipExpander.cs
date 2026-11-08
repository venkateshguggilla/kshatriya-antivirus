using System.Buffers;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Sentinel.Core;

namespace Sentinel.Scanning.Archives;

/// <summary>Mutable per-item budget shared by all nested archives of one top-level item.</summary>
internal sealed class ArchiveBudget(ArchiveLimits limits)
{
    public ArchiveLimits Limits { get; } = limits;

    public int EntriesRemaining { get; set; } = limits.MaxEntries;

    public long BytesRemaining { get; set; } = limits.MaxTotalBytes;
}

/// <summary>A decompressed archive entry, held in memory.</summary>
internal sealed record ArchiveEntryContent(string Location, MemoryStream Content, string Sha256);

/// <summary>
/// Expands ZIP archives (including Office Open XML, JAR and similar ZIP-based formats) entirely in memory.
/// Entry names are used for display only and are never turned into file-system paths, so path-traversal
/// names ("zip slip") cannot cause writes. Declared sizes are not trusted: decompression is metered.
/// </summary>
internal static class ZipExpander
{
    private const long RatioCheckThreshold = 1024 * 1024;

    /// <summary>True when the content starts with a ZIP local-file or end-of-central-directory signature.</summary>
    public static bool LooksLikeZip(Stream content)
    {
        if (content.Length < 22)
        {
            return false;
        }

        Span<byte> magic = stackalloc byte[4];
        content.Position = 0;
        int read = content.ReadAtLeast(magic, 4, throwOnEndOfStream: false);
        content.Position = 0;
        return read == 4 && magic[0] == 0x50 && magic[1] == 0x4B
            && ((magic[2] == 0x03 && magic[3] == 0x04) || (magic[2] == 0x05 && magic[3] == 0x06));
    }

    /// <summary>
    /// Enumerates and decompresses entries, invoking <paramref name="onEntry"/> for each. Returns the first
    /// limiting reason encountered (or <see cref="ScanReason.None"/>) and an explanatory message.
    /// </summary>
    public static async Task<(ScanReason Reason, string? Message)> ExpandAsync(
        Stream content,
        string? parentLocation,
        ArchiveBudget budget,
        Func<ArchiveEntryContent, Task> onEntry,
        CancellationToken cancellationToken)
    {
        content.Position = 0;
        ZipArchive archive;
        try
        {
            archive = new ZipArchive(content, ZipArchiveMode.Read, leaveOpen: true, entryNameEncoding: Encoding.UTF8);
        }
        catch (InvalidDataException ex)
        {
            return (ScanReason.ArchiveError, $"Archive could not be read: {ex.Message}");
        }

        using (archive)
        {
            ScanReason reason = ScanReason.None;
            string? message = null;

            void Note(ScanReason r, string m)
            {
                if (reason == ScanReason.None)
                {
                    reason = r;
                    message = m;
                }
            }

            IReadOnlyCollection<ZipArchiveEntry> entries;
            try
            {
                entries = archive.Entries;
            }
            catch (InvalidDataException ex)
            {
                return (ScanReason.ArchiveError, $"Archive directory is corrupt: {ex.Message}");
            }

            foreach (ZipArchiveEntry entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                bool isDirectory = entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\');
                if (isDirectory && entry.Length == 0)
                {
                    continue;
                }

                string location = Combine(parentLocation, SanitizeName(entry.FullName));

                if (budget.EntriesRemaining <= 0)
                {
                    Note(ScanReason.ArchiveLimit, $"Entry limit ({budget.Limits.MaxEntries}) reached; remaining entries were not inspected.");
                    break;
                }

                budget.EntriesRemaining--;

                if (entry.IsEncrypted)
                {
                    Note(ScanReason.ArchiveEncrypted, $"Encrypted entry could not be inspected: {location}");
                    continue;
                }

                if (entry.Length > budget.Limits.MaxEntryBytes)
                {
                    Note(ScanReason.ArchiveLimit, $"Entry exceeds the {budget.Limits.MaxEntryBytes}-byte entry limit: {location}");
                    continue;
                }

                if (entry.Length > RatioCheckThreshold
                    && (entry.CompressedLength == 0 || entry.Length / Math.Max(entry.CompressedLength, 1) > budget.Limits.MaxCompressionRatio))
                {
                    Note(ScanReason.ArchiveLimit, $"Entry compression ratio exceeds {budget.Limits.MaxCompressionRatio}:1 (possible archive bomb): {location}");
                    continue;
                }

                if (entry.Length > budget.BytesRemaining)
                {
                    Note(ScanReason.ArchiveLimit, $"Total decompressed size limit ({budget.Limits.MaxTotalBytes} bytes) reached.");
                    break;
                }

                long cap = Math.Min(budget.Limits.MaxEntryBytes, budget.BytesRemaining);
                (MemoryStream? data, ScanReason readFailure, string? readMessage) = await ReadEntryAsync(entry, cap, location, cancellationToken);
                if (data is null)
                {
                    Note(readFailure, readMessage!);
                    if (readFailure == ScanReason.ArchiveLimit && budget.BytesRemaining <= cap)
                    {
                        break;
                    }

                    continue;
                }

                using (data)
                {
                    budget.BytesRemaining -= data.Length;
                    data.Position = 0;
                    string sha256 = Convert.ToHexStringLower(await SHA256.HashDataAsync(data, cancellationToken));
                    data.Position = 0;
                    await onEntry(new ArchiveEntryContent(location, data, sha256));
                }
            }

            return (reason, message);
        }
    }

    private static async Task<(MemoryStream? Data, ScanReason Reason, string? Message)> ReadEntryAsync(
        ZipArchiveEntry entry, long cap, string location, CancellationToken cancellationToken)
    {
        var buffer = new MemoryStream(capacity: (int)Math.Min(Math.Max(entry.Length, 0), 1024 * 1024));
        byte[] chunk = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            await using Stream stream = entry.Open();
            int read;
            while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
            {
                if (buffer.Length + read > cap)
                {
                    await buffer.DisposeAsync();
                    return (null, ScanReason.ArchiveLimit, $"Entry decompressed beyond the {cap}-byte limit (declared size was {entry.Length}): {location}");
                }

                buffer.Write(chunk, 0, read);
            }

            return (buffer, ScanReason.None, null);
        }
        catch (InvalidDataException ex)
        {
            await buffer.DisposeAsync();
            return (null, ScanReason.ArchiveError, $"Entry is corrupt or uses an unsupported method ({ex.Message}): {location}");
        }
        catch (NotSupportedException ex)
        {
            await buffer.DisposeAsync();
            return (null, ScanReason.ArchiveError, $"Entry uses an unsupported feature ({ex.Message}): {location}");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(chunk);
        }
    }

    private static string Combine(string? parent, string name) => parent is null ? name : parent + ">" + name;

    /// <summary>Makes an entry name safe to display: no control characters, bounded length.</summary>
    internal static string SanitizeName(string name)
    {
        var sb = new StringBuilder(Math.Min(name.Length, 260));
        foreach (char c in name)
        {
            if (sb.Length >= 260)
            {
                sb.Append('…');
                break;
            }

            sb.Append(char.IsControl(c) ? '?' : c);
        }

        return sb.Length == 0 ? "?" : sb.ToString();
    }
}
