using Kshatriya.Core;

namespace Kshatriya.Mobile;

/// <summary>How a result is shown: a tone and one line of text (for the list and for notifications).</summary>
public enum ResultTone
{
    Ok,
    Info,
    Warn,
    Danger,
}

/// <summary>User-facing wording for scan results on Android.</summary>
public static class MobileText
{
    private static readonly Dictionary<ScanReason, string> s_reasons = new()
    {
        [ScanReason.TooLarge] = "it is larger than the scan size limit",
        [ScanReason.AccessDenied] = "Kshatriya is not allowed to read it",
        [ScanReason.NotFound] = "it was moved or deleted before the scan",
        [ScanReason.IoError] = "it could not be read",
        [ScanReason.EngineError] = "a scan engine failed",
    };

    public static (ResultTone Tone, string Text) Describe(MobileScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        string name = result.Target.DisplayName;
        ScanItemResult item = result.Item;
        switch (item.Status)
        {
            case ScanStatus.Detected:
                Detection first = item.Detections.First(d => d.Category != DetectionCategory.Suspicious);
                string what = first.Category switch
                {
                    DetectionCategory.Malware => "malware",
                    DetectionCategory.PotentiallyUnwanted => "a potentially unwanted app",
                    DetectionCategory.TestFile => "a test file",
                    _ => "a threat",
                };
                return (ResultTone.Danger, $"{name}: {first.Name} ({what})");
            case ScanStatus.Suspicious:
                Detection hint = item.Detections[0];
                return hint.Name.StartsWith("Android.Watchware.", StringComparison.Ordinal) || hint.EngineId == AppIndicatorSet.EngineId
                    ? (ResultTone.Warn, $"{name} may be monitoring software ({hint.Name}). Fine if you installed it on purpose; otherwise review it")
                    : (ResultTone.Warn, $"{name} looks suspicious");
            case ScanStatus.Clean:
                return (ResultTone.Ok, $"{name}: no threats found");
            default:
                string why = s_reasons.TryGetValue(item.Reason, out string? text) ? text : "it could not be scanned";
                return (ResultTone.Info, $"{name} was not scanned because {why}");
        }
    }

    /// <summary>One-line summary of a finished scan.</summary>
    public static string Summary(IReadOnlyCollection<MobileScanResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);
        int detected = results.Count(r => r.Item.Status == ScanStatus.Detected);
        int suspicious = results.Count(r => r.Item.Status == ScanStatus.Suspicious);
        int notScanned = results.Count(r => r.Item.Status is ScanStatus.NotScanned or ScanStatus.Skipped);
        string threats = detected == 0 && suspicious == 0 ? "no threats found"
            : string.Join(", ", new[] { detected > 0 ? $"{detected} threat(s)" : null, suspicious > 0 ? $"{suspicious} suspicious" : null }.Where(s => s is not null));
        return $"Scanned {results.Count - notScanned} of {results.Count}: {threats}." + (notScanned > 0 ? $" {notScanned} could not be scanned." : string.Empty);
    }
}
