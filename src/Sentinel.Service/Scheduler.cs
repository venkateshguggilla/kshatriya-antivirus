using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Sentinel.Core;
using Sentinel.Response;
using Sentinel.Scanning;

namespace Sentinel.Service;

/// <summary>Pure schedule arithmetic in a given time zone (testable without waiting).</summary>
public static class ScheduleCalculator
{
    /// <summary>The first occurrence strictly after <paramref name="after"/>.</summary>
    public static DateTimeOffset Next(ScheduledScan scan, DateTimeOffset after, TimeZoneInfo zone)
    {
        ArgumentNullException.ThrowIfNull(scan);
        ArgumentNullException.ThrowIfNull(zone);
        DateTime local = TimeZoneInfo.ConvertTime(after, zone).DateTime;
        for (int day = 0; day <= 7; day++)
        {
            DateTime date = local.Date.AddDays(day);
            if (!scan.Days.Contains(date.DayOfWeek))
            {
                continue;
            }

            DateTimeOffset candidate = ToOffset(date + scan.Time.ToTimeSpan(), zone);
            if (candidate > after)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException("A schedule with at least one day always has an occurrence within eight days.");
    }

    /// <summary>The most recent occurrence at or before <paramref name="atOrBefore"/>.</summary>
    public static DateTimeOffset Previous(ScheduledScan scan, DateTimeOffset atOrBefore, TimeZoneInfo zone)
    {
        ArgumentNullException.ThrowIfNull(scan);
        ArgumentNullException.ThrowIfNull(zone);
        DateTime local = TimeZoneInfo.ConvertTime(atOrBefore, zone).DateTime;
        for (int day = 0; day <= 7; day++)
        {
            DateTime date = local.Date.AddDays(-day);
            if (!scan.Days.Contains(date.DayOfWeek))
            {
                continue;
            }

            DateTimeOffset candidate = ToOffset(date + scan.Time.ToTimeSpan(), zone);
            if (candidate <= atOrBefore)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException("A schedule with at least one day always has an occurrence within eight days.");
    }

    /// <summary>
    /// A scan is due when an occurrence has passed since it last ran. A schedule that has never run is
    /// not due: the first run waits for the next occurrence instead of starting the moment it is installed.
    /// </summary>
    public static bool IsDue(ScheduledScan scan, DateTimeOffset? lastRun, DateTimeOffset now, TimeZoneInfo zone) =>
        lastRun is DateTimeOffset last && Previous(scan, now, zone) > last;

    private static DateTimeOffset ToOffset(DateTime local, TimeZoneInfo zone)
    {
        // Times that do not exist (spring-forward gap) run at the first valid minute after the gap.
        while (zone.IsInvalidTime(local))
        {
            local = local.AddMinutes(1);
        }

        return new DateTimeOffset(local, zone.GetUtcOffset(local));
    }
}

/// <summary>Last run time and outcome per schedule, persisted in the state directory.</summary>
public sealed class ScheduleState
{
    private readonly string _file;
    private readonly Dictionary<string, (DateTimeOffset LastRun, string Outcome)> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _gate = new();

    public ScheduleState(string stateDirectory)
    {
        ArgumentException.ThrowIfNullOrEmpty(stateDirectory);
        _file = Path.Combine(stateDirectory, "schedules.json");
        Load();
    }

    public (DateTimeOffset LastRun, string Outcome)? Get(string name)
    {
        lock (_gate)
        {
            return _entries.TryGetValue(name, out var e) ? e : null;
        }
    }

    public void Set(string name, DateTimeOffset lastRun, string outcome)
    {
        lock (_gate)
        {
            _entries[name] = (lastRun, outcome);
            Save();
        }
    }

    private void Load()
    {
        if (!File.Exists(_file))
        {
            return;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(_file));
            foreach (JsonProperty p in doc.RootElement.EnumerateObject())
            {
                if (DateTimeOffset.TryParse(p.Value.GetProperty("lastRunUtc").GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset last))
                {
                    _entries[p.Name] = (last, p.Value.GetProperty("outcome").GetString() ?? "unknown");
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or IOException)
        {
            // Corrupt state only affects catch-up runs; start fresh rather than refuse to run.
            _entries.Clear();
        }
    }

    private void Save()
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            json.WriteStartObject();
            foreach ((string name, (DateTimeOffset last, string outcome)) in _entries)
            {
                json.WriteStartObject(name);
                json.WriteString("lastRunUtc", last.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
                json.WriteString("outcome", outcome);
                json.WriteEndObject();
            }

            json.WriteEndObject();
        }

        string temp = _file + ".tmp";
        File.WriteAllBytes(temp, buffer.ToArray());
        File.Move(temp, _file, overwrite: true);
    }
}

/// <summary>Writes scheduled-scan reports (schema v2 JSON) and keeps only the newest N.</summary>
public sealed class ReportStore(string directory, int retention)
{
    public string Save(ScanReport report, string name, string toolVersion)
    {
        ArgumentNullException.ThrowIfNull(report);
        string stamp = report.StartedUtc.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        string path = Path.Combine(directory, $"scan-{stamp}-{name}.json");
        File.WriteAllText(path, ScanReportJson.Write(report, toolVersion));

        foreach (FileInfo old in new DirectoryInfo(directory).GetFiles("scan-*.json").OrderByDescending(f => f.Name, StringComparer.Ordinal).Skip(retention))
        {
            old.Delete();
        }

        return path;
    }
}

/// <summary>Runs scheduled scans as the service identity, one at a time, without the verdict cache.</summary>
public sealed class Scheduler(ServiceCore core, ScheduleState state, ReportStore reports, TimeProvider time, TimeZoneInfo zone, ILogger logger)
{
    private static readonly TimeSpan s_maxSleep = TimeSpan.FromHours(1);

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<ScheduledScan> scans = core.Settings.ScheduledScans;
        if (scans.Count == 0)
        {
            return;
        }

        DateTimeOffset now = time.GetUtcNow();
        foreach (ScheduledScan scan in scans)
        {
            if (state.Get(scan.Name) is null)
            {
                // Never run: start the clock now so the first run is the next occurrence, not immediately.
                state.Set(scan.Name, now, "pending");
            }
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            await RunDueAsync(cancellationToken);
            now = time.GetUtcNow();
            DateTimeOffset next = scans.Min(s => ScheduleCalculator.Next(s, now, zone));
            TimeSpan sleep = next - now;
            await Task.Delay(sleep < s_maxSleep ? sleep + TimeSpan.FromSeconds(1) : s_maxSleep, time, cancellationToken);
        }
    }

    /// <summary>Runs every scan that is due now. Exposed for tests.</summary>
    public async Task<int> RunDueAsync(CancellationToken cancellationToken)
    {
        int ran = 0;
        foreach (ScheduledScan scan in core.Settings.ScheduledScans)
        {
            DateTimeOffset now = time.GetUtcNow();
            DateTimeOffset? last = state.Get(scan.Name)?.LastRun;
            if (!ScheduleCalculator.IsDue(scan, last, now, zone))
            {
                continue;
            }

            ran++;
            Log.ScheduleStarting(logger, scan.Name, scan.Paths.Count);
            string outcome;
            try
            {
                // Full rescans: the cache is bypassed so that stale cached verdicts are bounded by the schedule.
                IItemResponder? responder = scan.Quarantine ? new QuarantineResponder(core.Quarantine, Actor.System($"schedule '{scan.Name}'")) : null;
                ScanReport report = await core.Coordinator.ScanAsync(scan.Paths, includeClean: false, useCache: false, responder, progress: null, cancellationToken);
                string file = reports.Save(report, scan.Name, ServiceCore.Version);
                core.RecordDetections(report, $"schedule '{scan.Name}'");
                outcome = report.HasDetections ? "detections" : report.HasSuspicious ? "suspicious" : report.IsComplete ? "clean" : "incomplete";
                Log.ScheduleFinished(logger, scan.Name, outcome, file);
            }
            catch (ScanCapacityException)
            {
                Log.SchedulePostponed(logger, scan.Name);
                continue;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                outcome = "failed";
                Log.ScheduleFailed(logger, ex, scan.Name);
            }

            state.Set(scan.Name, now, outcome);
        }

        return ran;
    }
}
