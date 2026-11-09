using Kshatriya.App.Services;
using Kshatriya.Protocol;
using Kshatriya.Tests.Shared;

namespace Kshatriya.App.Tests;

public class NotificationTests
{
    private static DetectionRecordDto Finding(string time, string source = "real-time (file)", string status = "detected", string path = @"C:\Users\alice\Downloads\x.exe", string action = "reported", string name = "Test.Sample") =>
        new() { TimeUtc = time, Source = source, Path = path, Status = status, Names = [name], Action = action };

    [Fact]
    public async Task Findings_from_before_the_app_started_are_not_announced()
    {
        var gateway = new FakeGateway { Detections = [Finding("2026-11-09T10:00:00Z")] };
        var watcher = new DetectionWatcher(gateway);

        Assert.Empty(await watcher.PollAsync(CancellationToken.None));
        Assert.Empty(await watcher.PollAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Only_new_background_findings_are_announced_once()
    {
        var gateway = new FakeGateway { Detections = [Finding("2026-11-09T10:00:00Z")] };
        var watcher = new DetectionWatcher(gateway);
        await watcher.PollAsync(CancellationToken.None);

        gateway.Detections.Add(Finding("2026-11-09T10:01:00Z", path: @"C:\Users\alice\new.exe"));
        gateway.Detections.Add(Finding("2026-11-09T10:01:05Z", source: "scan", path: @"C:\Users\alice\scanned.exe"));
        gateway.Detections.Add(Finding("2026-11-09T10:01:10Z", source: "behaviour", status: "suspicious", path: @"C:\Users\alice\Documents", action: "alert only (no automatic action)", name: "Kshatriya.Behaviour.MassChange"));

        IReadOnlyList<DetectionRecordDto> fresh = await watcher.PollAsync(CancellationToken.None);

        Assert.Equal([@"C:\Users\alice\new.exe", @"C:\Users\alice\Documents"], fresh.Select(f => f.Path));
        Assert.Empty(await watcher.PollAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Findings_after_a_service_restart_are_still_announced()
    {
        var gateway = new FakeGateway { Detections = [Finding("2026-11-09T10:00:00Z")] };
        var watcher = new DetectionWatcher(gateway);
        await watcher.PollAsync(CancellationToken.None);

        gateway.Detections = [Finding("2026-11-09T11:00:00Z", source: "schedule 'nightly'")]; // the service's history starts empty again

        Assert.Single(await watcher.PollAsync(CancellationToken.None));
    }

    [Fact]
    public async Task An_unreachable_service_is_reported_quietly_and_polling_recovers()
    {
        var gateway = new FakeGateway { Failure = new TimeoutException("no service") };
        var watcher = new DetectionWatcher(gateway);

        Assert.Empty(await watcher.PollAsync(CancellationToken.None));
        Assert.False(watcher.ServiceReachable);

        gateway.Failure = null;
        gateway.Detections = [];
        Assert.Empty(await watcher.PollAsync(CancellationToken.None)); // first reachable poll: starting point
        Assert.True(watcher.ServiceReachable);
        gateway.Detections.Add(Finding("2026-11-09T12:00:00Z"));
        Assert.Single(await watcher.PollAsync(CancellationToken.None));
    }

    [Fact]
    public void Notifications_say_what_was_found_and_what_was_done()
    {
        FindingNotice threat = DetectionWatcher.Describe([Finding("2026-11-09T10:00:00Z")]);
        Assert.Equal("Threat found", threat.Title);
        Assert.Equal("x.exe: Test.Sample. Reported only; nothing was changed.", threat.Message);
        Assert.True(threat.IsThreat);

        FindingNotice quarantined = DetectionWatcher.Describe([Finding("2026-11-09T10:00:00Z", action: "quarantined (abc)")]);
        Assert.Contains("Moved to quarantine", quarantined.Message, StringComparison.Ordinal);

        FindingNotice behaviour = DetectionWatcher.Describe([Finding("2026-11-09T10:00:00Z", source: "behaviour", status: "suspicious", action: "alert only (no automatic action)")]);
        Assert.Equal("Possible ransomware activity", behaviour.Title);
        Assert.False(behaviour.IsThreat);

        FindingNotice many = DetectionWatcher.Describe([Finding("2026-11-09T10:00:00Z", status: "suspicious"), Finding("2026-11-09T10:00:01Z", path: @"C:\b.dll")]);
        Assert.Equal("2 new findings", many.Title);
        Assert.StartsWith("Latest: b.dll", many.Message, StringComparison.Ordinal);
        Assert.True(many.IsThreat);

        FindingNotice longName = DetectionWatcher.Describe([Finding("2026-11-09T10:00:00Z", name: new string('n', 500))]);
        Assert.True(longName.Message.Length <= 240);
    }

    [Fact]
    public void The_notification_preference_is_kept_per_user()
    {
        using var temp = new TempDirectory();
        string file = Path.Combine(temp.Path, "Kshatriya", "app-settings.json");

        Assert.True(new AppPreferences(file).Notifications);
        new AppPreferences(file).SetNotifications(false);
        Assert.False(new AppPreferences(file).Notifications);
        File.WriteAllText(file, "not json");
        Assert.True(new AppPreferences(file).Notifications);
    }
}
