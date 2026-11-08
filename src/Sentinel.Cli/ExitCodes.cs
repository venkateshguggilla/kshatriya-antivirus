namespace Sentinel.Cli;

/// <summary>Documented process exit codes. Detections take precedence over incompleteness.</summary>
public static class ExitCodes
{
    /// <summary>Everything in scope was scanned and nothing was detected.</summary>
    public const int Clean = 0;

    /// <summary>At least one detection.</summary>
    public const int Detections = 1;

    /// <summary>No detections, but at least one item could not be scanned (locked, denied, too large, timed out, error) or the scan was cancelled.</summary>
    public const int Incomplete = 2;

    /// <summary>Invalid command line.</summary>
    public const int Usage = 3;

    /// <summary>The scan could not run (for example an invalid signature database or unwritable output file).</summary>
    public const int Fatal = 4;

    /// <summary>No confirmed detections, but at least one heuristic (suspicious) finding. Takes precedence over 2.</summary>
    public const int Suspicious = 5;
}
