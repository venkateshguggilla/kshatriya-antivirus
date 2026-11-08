using System.Globalization;
using System.Text;
using Sentinel.Core;

namespace Sentinel.Cli;

/// <summary>Writes the versioned JSON report. The format itself lives in <see cref="ScanReportJson"/>.</summary>
public static class JsonReportWriter
{
    public const int SchemaVersion = ScanReportJson.SchemaVersion;

    public static string Write(ScanReport report, string toolVersion) => ScanReportJson.Write(report, toolVersion);
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
            foreach (ScanItemResult item in report.Items.Where(i => i.Status is ScanStatus.Detected or ScanStatus.Suspicious))
            {
                foreach (Detection d in item.Detections)
                {
                    string label = d.Category == DetectionCategory.Suspicious ? "SUSPICIOUS" : "DETECTED";
                    string where = d.Location is null ? item.Path : $"{item.Path} > {d.Location}";
                    sb.Append(CultureInfo.InvariantCulture, $"{label}  {d.Name} ({WireNames.Of(d.Category)}, {WireNames.Of(d.Confidence)} confidence)  {where}").AppendLine();
                }

                if (item.Reason != ScanReason.None)
                {
                    sb.Append(CultureInfo.InvariantCulture, $"  partially scanned [{WireNames.Of(item.Reason)}]: {item.Message}").AppendLine();
                }

                if (item.Action is { Succeeded: true } done)
                {
                    sb.Append(CultureInfo.InvariantCulture, $"  -> quarantined (id {done.QuarantineId})").AppendLine();
                }
                else if (item.Action is { } failed)
                {
                    sb.Append(CultureInfo.InvariantCulture, $"  -> NOT quarantined [{WireNames.Of(failed.Failure)}]: {failed.Message}").AppendLine();
                }
            }

            foreach (ScanItemResult item in report.Items.Where(i => i.Status == ScanStatus.NotScanned))
            {
                sb.Append(CultureInfo.InvariantCulture, $"NOT SCANNED  [{WireNames.Of(item.Reason)}]  {item.Path}").AppendLine();
            }

            foreach (ScanItemResult item in report.Items.Where(i => i.Status == ScanStatus.Skipped))
            {
                sb.Append(CultureInfo.InvariantCulture, $"skipped  [{WireNames.Of(item.Reason)}]  {item.Path}").AppendLine();
            }

            if (sb.Length > 0)
            {
                sb.AppendLine();
            }
        }

        string verdict = s.Detected > 0 && (s.Quarantined > 0 || s.QuarantineFailed > 0)
            ? $"{s.Detected} item(s) detected: {s.Quarantined} quarantined, {s.QuarantineFailed} could not be quarantined"
              + (s.Detected > s.Quarantined + s.QuarantineFailed ? $", {s.Detected - s.Quarantined - s.QuarantineFailed} not eligible (reported only)." : ".")
            : s.Detected > 0
            ? $"{s.Detected} item(s) detected. No files were changed; review the items above."
            : s.Suspicious > 0
                ? $"{s.Suspicious} item(s) look suspicious but are not confirmed malware. No files were changed; review before acting."
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
            ScanStatus.Detected or ScanStatus.Suspicious => string.Join(Environment.NewLine, item.Detections.Select(d => $"DETECTED  {d.Name}  {item.Path}")) + Environment.NewLine,
            ScanStatus.Clean => $"Nothing detected in {item.Path}." + Environment.NewLine,
            _ => $"NOT SCANNED  [{WireNames.Of(item.Reason)}]  {item.Path}" + Environment.NewLine,
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
