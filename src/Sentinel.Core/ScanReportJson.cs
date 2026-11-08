using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Sentinel.Core;

/// <summary>
/// Reads and writes the versioned JSON scan report (docs/schemas/scan-report.v3.schema.json).
/// Wire names come from <see cref="WireNames"/>; the reader is strict and throws
/// <see cref="FormatException"/> for anything that does not match the schema's required shape.
/// </summary>
public static class ScanReportJson
{
    public const int SchemaVersion = 3;

    /// <summary>Oldest schema version <see cref="Read"/> accepts (v2 reports simply have no actions).</summary>
    public const int MinReadableSchemaVersion = 2;

    public static string Write(ScanReport report, string toolVersion)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(toolVersion);
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            json.WriteStartObject();
            json.WriteNumber("schemaVersion", SchemaVersion);
            json.WriteStartObject("tool");
            json.WriteString("name", "Sentinel");
            json.WriteString("version", toolVersion);
            json.WriteEndObject();
            json.WriteString("startedUtc", report.StartedUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            json.WriteString("finishedUtc", report.FinishedUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            json.WriteNumber("durationMs", (long)report.Duration.TotalMilliseconds);
            json.WriteBoolean("complete", report.IsComplete);
            json.WriteBoolean("cleanItemsIncluded", report.CleanItemsIncluded);

            json.WriteStartArray("targets");
            foreach (string target in report.Targets)
            {
                json.WriteStringValue(target);
            }

            json.WriteEndArray();

            json.WriteStartArray("engines");
            foreach (EngineInfo engine in report.Engines)
            {
                json.WriteStartObject();
                json.WriteString("id", engine.Id);
                json.WriteString("version", engine.Version);
                json.WriteString("contentVersion", engine.ContentVersion);
                json.WriteEndObject();
            }

            json.WriteEndArray();

            ScanSummary s = report.Summary;
            json.WriteStartObject("summary");
            json.WriteNumber("itemsSeen", s.ItemsSeen);
            json.WriteNumber("filesScanned", s.FilesScanned);
            json.WriteNumber("detected", s.Detected);
            json.WriteNumber("suspicious", s.Suspicious);
            json.WriteNumber("partial", s.Partial);
            json.WriteNumber("skipped", s.Skipped);
            json.WriteNumber("notScanned", s.NotScanned);
            json.WriteNumber("bytesScanned", s.BytesScanned);
            json.WriteNumber("quarantined", s.Quarantined);
            json.WriteNumber("quarantineFailed", s.QuarantineFailed);
            json.WriteEndObject();

            json.WriteStartArray("items");
            foreach (ScanItemResult item in report.Items)
            {
                WriteItem(json, item);
            }

            json.WriteEndArray();
            json.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>Writes one detection object (shared with the IPC protocols).</summary>
    public static void WriteDetection(Utf8JsonWriter json, Detection d)
    {
        ArgumentNullException.ThrowIfNull(json);
        ArgumentNullException.ThrowIfNull(d);
        json.WriteStartObject();
        json.WriteString("engine", d.EngineId);
        json.WriteString("name", d.Name);
        json.WriteString("category", WireNames.Of(d.Category));
        json.WriteString("confidence", WireNames.Of(d.Confidence));
        if (d.Description is not null)
        {
            json.WriteString("description", d.Description);
        }

        if (d.Location is not null)
        {
            json.WriteString("location", d.Location);
        }

        json.WriteEndObject();
    }

    public static ScanReport Read(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        try
        {
            using JsonDocument doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 16 });
            JsonElement root = Object(doc.RootElement, "report");
            int version = Int(root, "schemaVersion");
            if (version < MinReadableSchemaVersion || version > SchemaVersion)
            {
                throw new FormatException($"Unsupported report schema version {version}; expected {MinReadableSchemaVersion} to {SchemaVersion}.");
            }

            bool v3 = version >= 3;

            JsonElement summary = Object(Required(root, "summary"), "summary");
            return new ScanReport
            {
                Targets = [.. Array(root, "targets").EnumerateArray().Select(t => StringValue(t, "targets[]"))],
                StartedUtc = Timestamp(root, "startedUtc"),
                FinishedUtc = Timestamp(root, "finishedUtc"),
                Engines = [.. Array(root, "engines").EnumerateArray().Select(e => new EngineInfo(Str(e, "id"), Str(e, "version"), Str(e, "contentVersion")))],
                Summary = new ScanSummary
                {
                    ItemsSeen = Long(summary, "itemsSeen"),
                    FilesScanned = Long(summary, "filesScanned"),
                    Detected = Long(summary, "detected"),
                    Suspicious = Long(summary, "suspicious"),
                    Partial = Long(summary, "partial"),
                    Skipped = Long(summary, "skipped"),
                    NotScanned = Long(summary, "notScanned"),
                    BytesScanned = Long(summary, "bytesScanned"),
                    Quarantined = v3 ? Long(summary, "quarantined") : 0,
                    QuarantineFailed = v3 ? Long(summary, "quarantineFailed") : 0,
                },
                Items = [.. Array(root, "items").EnumerateArray().Select(i => ReadItem(i, v3))],
                CleanItemsIncluded = Bool(root, "cleanItemsIncluded"),
            };
        }
        catch (JsonException ex)
        {
            throw new FormatException($"Report is not valid JSON: {ex.Message}", ex);
        }
        catch (InvalidOperationException ex)
        {
            throw new FormatException($"Report has an unexpected shape: {ex.Message}", ex);
        }
    }

    /// <summary>Reads one detection object (shared with the IPC protocols).</summary>
    public static Detection ReadDetection(JsonElement e)
    {
        Object(e, "detection");
        return new Detection(
            Str(e, "engine"),
            Str(e, "name"),
            WireNames.ParseCategory(Str(e, "category")),
            WireNames.ParseConfidence(Str(e, "confidence")),
            OptionalStr(e, "description"))
        {
            Location = OptionalStr(e, "location"),
        };
    }

    private static void WriteItem(Utf8JsonWriter json, ScanItemResult item)
    {
        json.WriteStartObject();
        json.WriteString("path", item.Path);
        json.WriteString("kind", WireNames.Of(item.Kind));
        json.WriteString("status", WireNames.Of(item.Status));
        if (item.Reason != ScanReason.None)
        {
            json.WriteString("reason", WireNames.Of(item.Reason));
        }

        if (item.SizeBytes is long size)
        {
            json.WriteNumber("sizeBytes", size);
        }

        if (item.Sha256 is not null)
        {
            json.WriteString("sha256", item.Sha256);
        }

        if (item.Message is not null)
        {
            json.WriteString("message", item.Message);
        }

        json.WriteBoolean("incomplete", item.IsIncomplete);

        if (item.Trust is FileTrust trust)
        {
            json.WriteStartObject("trust");
            json.WriteString("status", WireNames.Of(trust.Status));
            if (trust.Source != TrustSource.None)
            {
                json.WriteString("source", WireNames.Of(trust.Source));
            }

            if (trust.Signer is not null)
            {
                json.WriteString("signer", trust.Signer);
            }

            json.WriteEndObject();
        }

        if (item.Action is ItemAction action)
        {
            json.WriteStartObject("action");
            json.WriteString("kind", "quarantine");
            json.WriteString("outcome", action.Succeeded ? "quarantined" : "failed");
            if (action.QuarantineId is not null)
            {
                json.WriteString("quarantineId", action.QuarantineId);
            }

            if (action.Failure != ActionFailure.None)
            {
                json.WriteString("failure", WireNames.Of(action.Failure));
            }

            if (action.Message is not null)
            {
                json.WriteString("message", action.Message);
            }

            json.WriteEndObject();
        }

        json.WriteStartArray("detections");
        foreach (Detection d in item.Detections)
        {
            WriteDetection(json, d);
        }

        json.WriteEndArray();
        json.WriteEndObject();
    }

    private static ItemAction ReadAction(JsonElement a)
    {
        Object(a, "action");
        if (Str(a, "kind") != "quarantine")
        {
            throw new FormatException("Unknown action kind.");
        }

        string? id = OptionalStr(a, "quarantineId");
        string? failure = OptionalStr(a, "failure");
        var action = new ItemAction(id, failure is null ? ActionFailure.None : WireNames.ParseActionFailure(failure), OptionalStr(a, "message"));
        string outcome = Str(a, "outcome");
        bool consistent = outcome switch
        {
            "quarantined" => id is not null && action.Failure == ActionFailure.None,
            "failed" => id is null && action.Failure != ActionFailure.None,
            _ => false,
        };
        return consistent ? action : throw new FormatException($"Inconsistent action outcome '{outcome}'.");
    }

    private static ScanItemResult ReadItem(JsonElement e, bool v3)
    {
        Object(e, "item");
        FileTrust? trust = null;
        if (e.TryGetProperty("trust", out JsonElement t))
        {
            Object(t, "trust");
            string? source = OptionalStr(t, "source");
            trust = new FileTrust(
                WireNames.ParseTrustStatus(Str(t, "status")),
                source is null ? TrustSource.None : WireNames.ParseTrustSource(source),
                OptionalStr(t, "signer"));
        }

        string? reason = OptionalStr(e, "reason");
        return new ScanItemResult
        {
            Path = Str(e, "path"),
            Kind = WireNames.ParseKind(Str(e, "kind")),
            Status = WireNames.ParseStatus(Str(e, "status")),
            Reason = reason is null ? ScanReason.None : WireNames.ParseReason(reason),
            SizeBytes = e.TryGetProperty("sizeBytes", out JsonElement size) ? NumberValue(size, "sizeBytes") : null,
            Sha256 = OptionalStr(e, "sha256"),
            Message = OptionalStr(e, "message"),
            Trust = trust,
            Action = v3 && e.TryGetProperty("action", out JsonElement a) ? ReadAction(a) : null,
            Detections = [.. Array(e, "detections").EnumerateArray().Select(ReadDetection)],
        };
    }

    private static JsonElement Required(JsonElement e, string name) =>
        e.TryGetProperty(name, out JsonElement value) ? value : throw new FormatException($"Missing required property '{name}'.");

    private static JsonElement Object(JsonElement e, string what) =>
        e.ValueKind == JsonValueKind.Object ? e : throw new FormatException($"Expected an object for '{what}'.");

    private static JsonElement Array(JsonElement e, string name)
    {
        JsonElement value = Required(e, name);
        return value.ValueKind == JsonValueKind.Array ? value : throw new FormatException($"Property '{name}' must be an array.");
    }

    private static string Str(JsonElement e, string name) => StringValue(Required(e, name), name);

    private static string? OptionalStr(JsonElement e, string name) =>
        e.TryGetProperty(name, out JsonElement value) ? StringValue(value, name) : null;

    private static string StringValue(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.String ? value.GetString()! : throw new FormatException($"Property '{name}' must be a string.");

    private static long Long(JsonElement e, string name) => NumberValue(Required(e, name), name);

    private static long NumberValue(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out long n) && n >= 0
            ? n
            : throw new FormatException($"Property '{name}' must be a non-negative integer.");

    private static int Int(JsonElement e, string name)
    {
        long value = Long(e, name);
        return value <= int.MaxValue ? (int)value : throw new FormatException($"Property '{name}' is out of range.");
    }

    private static bool Bool(JsonElement e, string name)
    {
        JsonElement value = Required(e, name);
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new FormatException($"Property '{name}' must be a boolean."),
        };
    }

    private static DateTimeOffset Timestamp(JsonElement e, string name) =>
        DateTimeOffset.TryParse(Str(e, name), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset value)
            ? value
            : throw new FormatException($"Property '{name}' must be an ISO 8601 timestamp.");
}
