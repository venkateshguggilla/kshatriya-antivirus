using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kshatriya.Response;

/// <summary>Stable action names written to the audit log.</summary>
public static class AuditActions
{
    public const string Quarantine = "quarantine";
    public const string Restore = "restore";
    public const string Delete = "delete";
    public const string ExclusionAdd = "exclusionAdd";
    public const string ExclusionRemove = "exclusionRemove";
    public const string AuditRead = "auditRead";
}

/// <summary>Stable outcome names written to the audit log.</summary>
public static class AuditOutcomes
{
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    public const string Denied = "denied";
}

/// <summary>One audit record as stored.</summary>
public sealed record AuditRecord(
    long Sequence,
    DateTimeOffset TimeUtc,
    string ActorSid,
    string ActorName,
    string Action,
    string Target,
    string Outcome,
    string? Detail,
    string? QuarantineId,
    string Previous,
    string Hash);

/// <summary>Result of checking the hash chain.</summary>
public sealed record AuditVerification(bool Valid, long Records, string? Problem);

/// <summary>
/// Append-only, hash-chained audit log (JSON Lines). Each line is <c>{"entry":{...},"hash":"..."}</c>,
/// where the hash is SHA-256 over the exact entry text and every entry names the previous hash.
/// This makes edits, deletions and reordering <em>detectable</em>; it does not prevent an administrator
/// from rewriting the whole file, so it is tamper-evident, not tamper-proof. Appends are serialised
/// across processes with a lock file and flushed to disk. The log rotates once (audit.1.jsonl) at 8 MiB.
/// </summary>
public sealed class AuditLog
{
    public const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";
    private const int MaxFieldLength = 2048;
    private readonly string _current;
    private readonly string _previous;
    private readonly string _lock;
    private readonly long _rotateBytes;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();

    private AuditLog(string directory, long rotateBytes, TimeProvider time)
    {
        Directory = directory;
        _current = Path.Combine(directory, "audit.jsonl");
        _previous = Path.Combine(directory, "audit.1.jsonl");
        _lock = Path.Combine(directory, "audit.lock");
        _rotateBytes = rotateBytes;
        _time = time;
    }

    public string Directory { get; }

    public static AuditLog Open(string directory, StorageAccess access, TimeProvider? time = null, long rotateBytes = 8L << 20)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        string full = Path.GetFullPath(directory);
        ProtectedDirectory.Ensure(full, access);
        return new AuditLog(full, rotateBytes, time ?? TimeProvider.System);
    }

    public AuditRecord Append(Actor actor, string action, string target, string outcome, string? detail = null, string? quarantineId = null)
    {
        ArgumentNullException.ThrowIfNull(actor);
        lock (_gate)
        {
            using FileStream guard = AcquireLock();
            (long lastSequence, string lastHash) = LastRecord(_current) ?? LastRecord(_previous) ?? (0, Genesis);
            if (File.Exists(_current) && new FileInfo(_current).Length >= _rotateBytes)
            {
                File.Move(_current, _previous, overwrite: true);
            }

            var entry = new AuditEntryDto
            {
                Seq = lastSequence + 1,
                Time = _time.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
                ActorSid = Clip(actor.Sid),
                ActorName = Clip(actor.Name),
                Action = action,
                Target = Clip(target),
                Outcome = outcome,
                Detail = detail is null ? null : Clip(detail),
                QuarantineId = quarantineId,
                Prev = lastHash,
            };
            string entryJson = JsonSerializer.Serialize(entry, AuditJsonContext.Default.AuditEntryDto);
            string hash = HashOf(entryJson);
            string line = $"{{\"entry\":{entryJson},\"hash\":\"{hash}\"}}\n";
            using (var stream = new FileStream(_current, FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                stream.Write(Encoding.UTF8.GetBytes(line));
                stream.Flush(flushToDisk: true);
            }

            return ToRecord(entry, hash);
        }
    }

    /// <summary>Returns up to <paramref name="max"/> most recent records, newest first.</summary>
    public IReadOnlyList<AuditRecord> ReadRecent(int max)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(max);
        var records = new List<AuditRecord>();
        foreach (string file in new[] { _current, _previous })
        {
            if (!File.Exists(file))
            {
                continue;
            }

            string[] lines = ReadLines(file);
            for (int i = lines.Length - 1; i >= 0 && records.Count < max; i--)
            {
                if (TryParse(lines[i], out AuditEntryDto? entry, out string? hash, out _))
                {
                    records.Add(ToRecord(entry!, hash!));
                }
            }
        }

        return records;
    }

    /// <summary>Checks every hash and link in the current file (anchored to the rotated file if present).</summary>
    public AuditVerification Verify()
    {
        if (!File.Exists(_current))
        {
            return new AuditVerification(true, 0, null);
        }

        (long Sequence, string Hash)? anchor = LastRecord(_previous);
        string expectedPrev = anchor?.Hash ?? Genesis;
        long expectedSeq = (anchor?.Sequence ?? 0) + 1;
        string[] lines = ReadLines(_current);
        for (int i = 0; i < lines.Length; i++)
        {
            if (!TryParse(lines[i], out AuditEntryDto? entry, out string? hash, out string? raw))
            {
                return new AuditVerification(false, i, $"Line {i + 1} is not a valid audit record.");
            }

            if (HashOf(raw!) != hash)
            {
                return new AuditVerification(false, i, $"Line {i + 1} does not match its hash (modified).");
            }

            // The first record after a lost rotation has no anchor to compare with.
            bool firstWithoutAnchor = i == 0 && anchor is null;
            if (!firstWithoutAnchor && (entry!.Prev != expectedPrev || entry.Seq != expectedSeq))
            {
                return new AuditVerification(false, i, $"Line {i + 1} does not follow the previous record (removed or reordered records).");
            }

            expectedPrev = hash!;
            expectedSeq = entry!.Seq + 1;
        }

        return new AuditVerification(true, lines.Length, null);
    }

    private static string HashOf(string entryJson) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(entryJson)));

    private static string Clip(string value) => value.Length <= MaxFieldLength ? value : value[..MaxFieldLength] + "…";

    private static string[] ReadLines(string file)
    {
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
    }

    private static (long Sequence, string Hash)? LastRecord(string file)
    {
        if (!File.Exists(file))
        {
            return null;
        }

        string[] lines = ReadLines(file);
        for (int i = lines.Length - 1; i >= 0; i--)
        {
            if (TryParse(lines[i], out AuditEntryDto? entry, out string? hash, out _))
            {
                return (entry!.Seq, hash!);
            }
        }

        return null;
    }

    private static bool TryParse(string line, out AuditEntryDto? entry, out string? hash, out string? raw)
    {
        entry = null;
        hash = null;
        raw = null;
        try
        {
            using JsonDocument doc = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
            JsonElement root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("entry", out JsonElement e)
                || !root.TryGetProperty("hash", out JsonElement h)
                || h.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            raw = e.GetRawText();
            hash = h.GetString();
            entry = JsonSerializer.Deserialize(raw, AuditJsonContext.Default.AuditEntryDto);
            return entry is not null && hash is { Length: 64 };
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static AuditRecord ToRecord(AuditEntryDto e, string hash) => new(
        e.Seq,
        DateTimeOffset.TryParse(e.Time, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset t) ? t : DateTimeOffset.MinValue,
        e.ActorSid,
        e.ActorName,
        e.Action,
        e.Target,
        e.Outcome,
        e.Detail,
        e.QuarantineId,
        e.Prev,
        hash);

    private FileStream AcquireLock()
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                return new FileStream(_lock, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (attempt < 100)
            {
                Thread.Sleep(20);
            }
        }
    }
}

internal sealed class AuditEntryDto
{
    public required long Seq { get; init; }

    public required string Time { get; init; }

    public required string ActorSid { get; init; }

    public required string ActorName { get; init; }

    public required string Action { get; init; }

    public required string Target { get; init; }

    public required string Outcome { get; init; }

    public string? Detail { get; init; }

    public string? QuarantineId { get; init; }

    public required string Prev { get; init; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectNullableAnnotations = true,
    MaxDepth = 8)]
[JsonSerializable(typeof(AuditEntryDto))]
internal sealed partial class AuditJsonContext : JsonSerializerContext
{
}
