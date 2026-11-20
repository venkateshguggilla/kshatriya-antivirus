using Kshatriya.App.Services;
using Kshatriya.App.ViewModels;
using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.Tests;

/// <summary>The shared status store, critical state alerts and the tray's level icons (ADR 0021, slice 5).</summary>
public class StatusStoreTests
{
    [Fact]
    public async Task One_refresh_fetches_status_findings_and_quarantine_together()
    {
        var gateway = new FakeGateway();
        var store = new StatusStore(gateway);
        int refreshed = 0;
        store.Refreshed += _ => refreshed++;

        await store.RefreshAsync();

        Assert.True(store.Connected);
        Assert.NotNull(store.Status);
        Assert.Single(store.Detections);
        Assert.Equal(1, refreshed);
    }

    [Fact]
    public async Task An_unreachable_service_is_reported_not_thrown()
    {
        var store = new StatusStore(new FakeGateway { Failure = new TimeoutException() });

        await store.RefreshAsync();

        Assert.False(store.Connected);
        Assert.IsType<TimeoutException>(store.Error);
    }

    [Fact]
    public async Task Home_reads_the_store_it_shares()
    {
        var gateway = new FakeGateway { Detections = [] };
        var store = new StatusStore(gateway);
        var home = new HomeViewModel(gateway, new FakeHost(), store) { AntivirusSource = () => AntivirusHealth.Good, FolderAccessSource = () => 1 };

        await home.RefreshCommand.ExecuteAsync(null);

        Assert.Same(store, home.Store);
        Assert.True(store.Connected);
        Assert.True(home.IsConnected);
    }

    [Fact]
    public void The_service_stopping_is_a_critical_alert_but_not_while_it_starts_or_the_app_exits()
    {
        var alerts = new StatusAlerts();
        Assert.Empty(alerts.Observe(connected: false, auditValid: null, starting: true, exiting: false)); // first: starting point
        Assert.Empty(alerts.Observe(connected: true, auditValid: true, starting: false, exiting: false));

        StatusAlert stopped = Assert.Single(alerts.Observe(connected: false, auditValid: null, starting: false, exiting: false));
        Assert.Equal(NotificationCategory.ServiceStopped, stopped.Category);
        Assert.Equal(NotificationImportance.Critical, NotificationPolicy.ImportanceOf(stopped.Category));

        Assert.Empty(alerts.Observe(connected: false, auditValid: null, starting: false, exiting: false)); // said once
        Assert.Empty(alerts.Observe(connected: true, auditValid: true, starting: false, exiting: false));
        Assert.Empty(alerts.Observe(connected: false, auditValid: null, starting: false, exiting: true));
    }

    [Fact]
    public void A_failing_audit_check_is_announced_once()
    {
        var alerts = new StatusAlerts();
        alerts.Observe(connected: true, auditValid: true, starting: false, exiting: false);

        Assert.Equal(NotificationCategory.AuditFailure, Assert.Single(alerts.Observe(true, false, false, false)).Category);
        Assert.Empty(alerts.Observe(true, false, false, false));
    }

    [Fact]
    public void A_failing_audit_check_seen_first_is_not_announced()
    {
        var alerts = new StatusAlerts();

        Assert.Empty(alerts.Observe(true, false, false, false)); // Home already shows it on start
    }

    [Fact]
    public void Findings_observed_from_the_store_follow_the_watcher_rules()
    {
        var watcher = new DetectionWatcher(new FakeGateway());
        DetectionRecordDto Finding(string time, string source = "real-time (file)") => new()
        {
            TimeUtc = time,
            Source = source,
            Path = @"C:\Users\alice\x.exe",
            Status = "detected",
            Names = ["Test.Sample"],
            Action = "reported",
        };

        Assert.Empty(watcher.Observe([Finding("2026-11-21T10:00:00Z")])); // starting point
        IReadOnlyList<DetectionRecordDto> fresh = watcher.Observe([Finding("2026-11-21T10:00:00Z"), Finding("2026-11-21T10:01:00Z"), Finding("2026-11-21T10:02:00Z", "scan")]);

        Assert.Equal("2026-11-21T10:01:00Z", Assert.Single(fresh).TimeUtc);
    }

    [Fact]
    public void The_tray_dot_is_drawn_on_a_copy_of_the_icon() => UiThread.Run(() =>
    {
        using System.Drawing.Icon source = TrayIcon.LoadIcon();
        using System.Drawing.Icon dotted = TrayIcon.WithDot(source, System.Drawing.Color.Red);
        using System.Drawing.Bitmap bitmap = dotted.ToBitmap();

        Assert.Equal(source.Width, dotted.Width);
        System.Drawing.Color corner = bitmap.GetPixel(bitmap.Width * 3 / 4, bitmap.Height * 3 / 4);
        Assert.True(corner.R > 200 && corner.G < 80, $"expected a red dot, got {corner}");
    });
}
