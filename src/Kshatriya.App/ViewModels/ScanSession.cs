using System.Diagnostics;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.Core;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;

/// <summary>Where the current user scan is.</summary>
public enum ScanState
{
    Idle,
    Running,
    Completed,
    Cancelled,
    Failed,
}

/// <summary>
/// The app-level owner of the user's current scan (ADR 0021, section 3): its state, live counters and result.
/// The Scan page, the shell's "scan running" strip and the notification area all read it, so a scan stays
/// visible when the user moves to another page. Closing the app still cancels it (ADR 0016).
/// </summary>
public sealed class ScanSession : ObservableObject, IDisposable
{
    private readonly Func<TimeSpan> _elapsed;
    private CancellationTokenSource? _cancel;
    private ScanState _state;
    private string _label = string.Empty;
    private long _itemsChecked;
    private long _findings;
    private double _mibRead;
    private string _elapsedText = "0:00";
    private ScanReport? _report;

    public ScanSession(Func<TimeSpan>? elapsedSource = null)
    {
        var clock = new Stopwatch();
        _elapsed = elapsedSource ?? (() => clock.Elapsed);
        _clock = clock;
    }

    private readonly Stopwatch _clock;

    public ScanState State
    {
        get => _state;
        private set
        {
            if (Set(ref _state, value))
            {
                OnPropertyChanged(nameof(IsRunning));
            }
        }
    }

    public bool IsRunning => State == ScanState.Running;

    /// <summary>"Quick scan", "Full scan", "Custom scan", …</summary>
    public string Label { get => _label; private set => Set(ref _label, value); }

    public long ItemsChecked { get => _itemsChecked; private set => Set(ref _itemsChecked, value); }

    public long Findings { get => _findings; private set => Set(ref _findings, value); }

    public double MiBRead { get => _mibRead; private set => Set(ref _mibRead, value); }

    /// <summary>Elapsed time as m:ss or h:mm:ss, updated with each progress report.</summary>
    public string ElapsedText { get => _elapsedText; private set => Set(ref _elapsedText, value); }

    /// <summary>One line for the shell strip and the notification-area tooltip.</summary>
    public string StatusLine => IsRunning
        ? $"{Label}: {ItemsChecked.ToString("N0", CultureInfo.CurrentCulture)} items checked, {Findings.ToString("N0", CultureInfo.CurrentCulture)} finding(s), {ElapsedText}"
        : string.Empty;

    /// <summary>The finished scan's report (null while running, after a cancel or failure).</summary>
    public ScanReport? Report { get => _report; private set => Set(ref _report, value); }

    /// <summary>Raised on the UI thread when a scan completes, is cancelled or fails.</summary>
    public event Action<ScanSession>? Finished;

    /// <summary>Runs one scan. Only one runs at a time; a second call while running returns at once.</summary>
    public async Task<ScanReport?> RunAsync(string label, Func<IProgress<ScanProgressDto>, CancellationToken, Task<ScanReport>> start)
    {
        ArgumentNullException.ThrowIfNull(start);
        if (IsRunning)
        {
            return null;
        }

        _cancel = new CancellationTokenSource();
        Label = label;
        (ItemsChecked, Findings, MiBRead, Report) = (0, 0, 0, null);
        _clock.Restart();
        ElapsedText = Format(TimeSpan.Zero);
        State = ScanState.Running;
        OnPropertyChanged(nameof(StatusLine));
        try
        {
            var progress = new Progress<ScanProgressDto>(p =>
            {
                ItemsChecked = p.ItemsCompleted;
                Findings = p.Detected;
                MiBRead = p.BytesScanned / (1024.0 * 1024);
                ElapsedText = Format(_elapsed());
                OnPropertyChanged(nameof(StatusLine));
            });
            ScanReport report = await start(progress, _cancel.Token);
            Report = report;
            ItemsChecked = Math.Max(ItemsChecked, report.Summary.ItemsSeen);
            Findings = report.Summary.Detected + report.Summary.Suspicious;
            State = ScanState.Completed;
            return report;
        }
        catch (OperationCanceledException)
        {
            State = ScanState.Cancelled;
            return null;
        }
        catch
        {
            State = ScanState.Failed;
            throw;
        }
        finally
        {
            _clock.Stop();
            ElapsedText = Format(_elapsed());
            OnPropertyChanged(nameof(StatusLine));
            _cancel.Dispose();
            _cancel = null;
            Finished?.Invoke(this);
        }
    }

    /// <summary>Title, text and whether it is a warning, for the "scan finished" notification.</summary>
    public (string Title, string Message, bool Warning) Outcome()
    {
        if (State == ScanState.Cancelled)
        {
            return ($"{Label} stopped", "The scan was cancelled. Results are incomplete.", false);
        }

        if (State == ScanState.Failed || Report is null)
        {
            return ($"{Label} did not finish", "Open Kshatriya to see why.", true);
        }

        ScanSummary s = Report.Summary;
        string files = $"{s.FilesScanned.ToString("N0", CultureInfo.CurrentCulture)} file(s) in {ElapsedText}.";
        return s.Detected > 0
            ? ($"{Label} found {s.Detected} threat(s)", $"{s.Quarantined} quarantined. {files} Open Kshatriya to review.", true)
            : s.Suspicious > 0
                ? ($"{Label}: {s.Suspicious} item(s) to review", $"Suspicious, not confirmed; nothing was changed. {files}", true)
                : ($"{Label} finished", $"No threats found. {files}" + (s.NotScanned > 0 ? $" {s.NotScanned} item(s) could not be scanned." : string.Empty), false);
    }

    public void Cancel() => _cancel?.Cancel();

    public void Dispose() => _cancel?.Dispose();

    internal static string Format(TimeSpan t) => t.TotalHours >= 1
        ? t.ToString(@"h\:mm\:ss", CultureInfo.InvariantCulture)
        : t.ToString(@"m\:ss", CultureInfo.InvariantCulture);
}
