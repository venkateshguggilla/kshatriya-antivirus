using System.Globalization;
using System.Text;
using System.Text.Json;
using Sentinel.Core;

namespace Sentinel.Cli;

/// <summary>
/// Writes the versioned JSON report (schema v1). Wire names are mapped explicitly so that renaming
/// a C# enum member can never silently change the public format.
/// </summary>
public static class JsonReportWriter
{
    public const int SchemaVersion = 1;

    public static string Write(ScanReport report, string toolVersion)
    {
        ArgumentNullException.ThrowIfNull(report);
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
            json.WriteNumber("skipped", s.Skipped);
            json.WriteNumber("notScanned", s.NotScanned);
            json.WriteNumber("bytesScanned", s.BytesScanned);
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

    private static void WriteItem(Utf8JsonWriter json, ScanItemResult item)
    {
        json.WriteStartObject();
        json.WriteString("path", item.Path);
        json.WriteString("kind", Wire(item.Kind));
        json.WriteString("status", Wire(item.Status));
        if (item.Reason != ScanReason.None)
        {
            json.WriteString("reason", Wire(item.Reason));
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

        json.WriteStartArray("detections");
        foreach (Detection d in item.Detections)
        {
            json.WriteStartObject();
            json.WriteString("engine", d.EngineId);
            json.WriteString("name", d.Name);
            json.WriteString("category", Wire(d.Category));
            json.WriteString("confidence", Wire(d.Confidence));
            if (d.Description is not null)
            {
                json.WriteString("description", d.Description);
            }

            json.WriteEndObject();
        }

        json.WriteEndArray();
        json.WriteEndObject();
    }

    public static string Wire(ScanItemKind kind) => kind switch
    {
        ScanItemKind.File => "file",
        ScanItemKind.Directory => "directory",
        ScanItemKind.Stream => "stream",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public static string Wire(ScanStatus status) => status switch
    {
        ScanStatus.Clean => "clean",
        ScanStatus.Detected => "detected",
        ScanStatus.Skipped => "skipped",
        ScanStatus.NotScanned => "notScanned",
        _ => throw new ArgumentOutOfRangeException(nameof(status)),
    };

    public static string Wire(ScanReason reason) => reason switch
    {
        ScanReason.None => "none",
        ScanReason.ReparsePoint => "reparsePoint",
        ScanReason.CloudPlaceholder => "cloudPlaceholder",
        ScanReason.LoopDetected => "loopDetected",
        ScanReason.TooLarge => "tooLarge",
        ScanReason.Timeout => "timeout",
        ScanReason.AccessDenied => "accessDenied",
        ScanReason.Locked => "locked",
        ScanReason.NotFound => "notFound",
        ScanReason.IoError => "ioError",
        ScanReason.EngineError => "engineError",
        _ => throw new ArgumentOutOfRangeException(nameof(reason)),
    };

    public static string Wire(DetectionCategory category) => category switch
    {
        DetectionCategory.Malware => "malware",
        DetectionCategory.PotentiallyUnwanted => "pua",
        DetectionCategory.Suspicious => "suspicious",
        DetectionCategory.TestFile => "test",
        _ => throw new ArgumentOutOfRangeException(nameof(category)),
    };

    public static string Wire(DetectionConfidence confidence) => confidence switch
    {
        DetectionConfidence.Low => "low",
        DetectionConfidence.Medium => "medium",
        DetectionConfidence.High => "high",
        _ => throw new ArgumentOutOfRangeException(nameof(confidence)),
    };
}

/// <summary>Plain-text report for people. Calm and factual: what was found, what was not scanned, and why.</summary>
public static class TextReportWriter
{
    public static string Write(ScanReport report, bool quiet)
    {
        ArgumentNullException.ThrowIfNull(report);
        var sb = new StringBuilder();
        ScanSummary s = report.Summary;
        double seconds = Math.Max(report.Duration.TotalSeconds, 0.001);

        if (!quiet)
        {
            foreach (ScanItemResult item in report.Items.Where(i => i.Status == ScanStatus.Detected))
            {
                foreach (Detection d in item.Detections)
                {
                    sb.Append(CultureInfo.InvariantCulture, $"DETECTED  {d.Name} ({JsonReportWriter.Wire(d.Category)}, {JsonReportWriter.Wire(d.Confidence)} confidence)  {item.Path}").AppendLine();
                }
            }

            foreach (ScanItemResult item in report.Items.Where(i => i.Status == ScanStatus.NotScanned))
            {
                sb.Append(CultureInfo.InvariantCulture, $"NOT SCANNED  [{JsonReportWriter.Wire(item.Reason)}]  {item.Path}").AppendLine();
            }

            foreach (ScanItemResult item in report.Items.Where(i => i.Status == ScanStatus.Skipped))
            {
                sb.Append(CultureInfo.InvariantCulture, $"skipped  [{JsonReportWriter.Wire(item.Reason)}]  {item.Path}").AppendLine();
            }

            if (sb.Length > 0)
            {
                sb.AppendLine();
            }
        }

        string verdict = s.Detected > 0
            ? $"{s.Detected} item(s) detected. No files were changed; review the items above."
            : s.NotScanned > 0
                ? $"Nothing detected, but {s.NotScanned} item(s) could not be scanned."
                : "Nothing detected.";

        sb.AppendLine(verdict);
        sb.Append(CultureInfo.InvariantCulture, $"Scanned {s.FilesScanned:N0} file(s), {FormatBytes(s.BytesScanned)} in {seconds:F2}s ({s.FilesScanned / seconds:N0} files/s). ")
          .Append(CultureInfo.InvariantCulture, $"Skipped by policy: {s.Skipped:N0}. Not scanned: {s.NotScanned:N0}.")
          .AppendLine();
        return sb.ToString();
    }

    public static string WriteStreamResult(ScanItemResult item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return item.Status switch
        {
            ScanStatus.Detected => string.Join(Environment.NewLine, item.Detections.Select(d => $"DETECTED  {d.Name}  {item.Path}")) + Environment.NewLine,
            ScanStatus.Clean => $"Nothing detected in {item.Path}." + Environment.NewLine,
            _ => $"NOT SCANNED  [{JsonReportWriter.Wire(item.Reason)}]  {item.Path}" + Environment.NewLine,
        };
    }

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1L << 30 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (double)(1L << 30):F2} GiB"),
        >= 1L << 20 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (double)(1L << 20):F2} MiB"),
        >= 1L << 10 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (double)(1L << 10):F2} KiB"),
        _ => string.Create(CultureInfo.InvariantCulture, $"{bytes} B"),
    };
}
