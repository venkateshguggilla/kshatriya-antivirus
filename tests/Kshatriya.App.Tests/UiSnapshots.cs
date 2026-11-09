using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Kshatriya.App.ViewModels;
using Kshatriya.Core;

namespace Kshatriya.App.Tests;

/// <summary>
/// Design review aid: renders every page with sample data to PNG files, at a desktop and a narrow window
/// size. Runs only when KSHATRIYA_UI_SNAPSHOTS names an output folder, for example:
/// <c>$env:KSHATRIYA_UI_SNAPSHOTS = 'C:\temp\ui'; dotnet test tests/Kshatriya.App.Tests --filter UiSnapshots</c>.
/// </summary>
public class UiSnapshots
{
    [Fact]
    public void Render_every_page_to_png()
    {
        string? folder = Environment.GetEnvironmentVariable("KSHATRIYA_UI_SNAPSHOTS");
        if (string.IsNullOrWhiteSpace(folder))
        {
            return;
        }

        Directory.CreateDirectory(folder);
        UiThread.Run(() => RenderAll(folder));
    }

    private static void RenderAll(string folder)
    {
        int pages = new MainViewModel(Gateway(), new FakeDialogs(), new FakeHost()).Pages.Count;
        foreach ((int width, int height, string size) in new[] { (1180, 780, "desktop"), (760, 900, "narrow") })
        {
            for (int index = 0; index < pages; index++)
            {
                // A fresh window per page: its first frame already shows the page with its data loaded.
                var main = new MainViewModel(Gateway(), new FakeDialogs(), new FakeHost());
                PageViewModel page = main.Pages[index];
                main.Current = page;
                page.RefreshCommand.Execute(null); // the first page is already current, so selecting it does not refresh
                if (page is ScanViewModel scan)
                {
                    scan.AddTargets([@"C:\Users\alice\Downloads"]);
                    scan.StartCommand.Execute(null);
                }

                Pump(TimeSpan.FromMilliseconds(200));
                var window = new MainWindow { DataContext = main, ShowInTaskbar = false, WindowStartupLocation = WindowStartupLocation.Manual, Left = -20000, Top = 0, Width = width, Height = height };
                window.Show();
                Pump(TimeSpan.FromMilliseconds(300));
                Save((FrameworkElement)window.Content, window.Background ?? Brushes.White, width, height, Path.Combine(folder, $"{size}-{index}-{page.Title}.png"));
                window.Hide(); // closing windows of an Application that was never run shuts it down
            }
        }
    }

    private static FakeGateway Gateway() => new()
    {
        NextReport = SampleReport(),
        Quarantine = { new Kshatriya.Protocol.QuarantineItemDto { Id = new string('a', 32), OriginalPath = @"C:\Users\alice\Downloads\setup-crack.exe", QuarantinedUtc = "2026-11-09T09:12:00Z", Detections = ["Kshatriya.Test.EICAR"], Sha256 = new string('0', 64), SizeBytes = 68, User = @"HOST\alice", Origin = "scan" } },
    };

    private static ScanReport SampleReport() => new()
    {
        Targets = [@"C:\Users\alice\Downloads"],
        StartedUtc = DateTimeOffset.UtcNow,
        FinishedUtc = DateTimeOffset.UtcNow,
        Engines = [],
        Summary = new ScanSummary { ItemsSeen = 1204, FilesScanned = 1201, Detected = 1, Suspicious = 1, NotScanned = 1 },
        Items =
        [
            new ScanItemResult { Path = @"C:\Users\alice\Downloads\setup-crack.exe", Kind = ScanItemKind.File, Status = ScanStatus.Detected, Detections = [new Detection("hash", "Kshatriya.Test.EICAR", DetectionCategory.TestFile, DetectionConfidence.High)] },
            new ScanItemResult { Path = @"C:\Users\alice\Downloads\tool.exe", Kind = ScanItemKind.File, Status = ScanStatus.Suspicious, Detections = [new Detection("pe-heuristics", "Kshatriya.Heuristic.SuspiciousPE", DetectionCategory.Suspicious, DetectionConfidence.Medium)] },
            ScanItemResult.Fail(@"C:\Users\alice\Downloads\movie.iso", ScanItemKind.File, ScanReason.Locked, "in use"),
        ],
    };

    /// <summary>Runs queued dispatcher work (bindings, layout, async continuations) for about <paramref name="duration"/>.</summary>
    private static void Pump(TimeSpan duration)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        do
        {
            var frame = new DispatcherFrame();
            Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new DispatcherOperationCallback(f =>
            {
                ((DispatcherFrame)f!).Continue = false;
                return null;
            }), frame);
            Dispatcher.PushFrame(frame);
            Thread.Sleep(10);
        }
        while (clock.Elapsed < duration);
    }

    private static void Save(FrameworkElement root, Brush background, int width, int height, string path)
    {
        root.Measure(new Size(width, height));
        root.Arrange(new Rect(0, 0, width, height));
        root.UpdateLayout();
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        var fill = new DrawingVisual();
        using (DrawingContext dc = fill.RenderOpen())
        {
            dc.DrawRectangle(background, null, new Rect(0, 0, width, height));
        }

        bitmap.Render(fill);
        bitmap.Render(root);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using FileStream file = File.Create(path);
        encoder.Save(file);
    }
}
