using Kshatriya.Presentation;

namespace Kshatriya.Presentation.Tests;

public class DesktopStatusEvaluatorTests
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    private static DesktopStatusInputs Healthy() => new()
    {
        ServiceReachable = true,
        WindowsAntivirus = WindowsAntivirusState.Good,
        RealTimeEnabled = true,
        ContentSequence = 42,
        ContentExpiresUtc = s_now.AddDays(30),
        Now = s_now,
    };

    [Fact]
    public void Everything_on_is_protected_with_quick_scan_as_the_action()
    {
        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(Healthy());

        Assert.Equal(ProtectionLevel.Protected, s.Level);
        Assert.Equal("All checks passed", s.Headline);
        Assert.Contains("Microsoft Defender", s.Detail, StringComparison.Ordinal);
        Assert.Equal(StatusActions.QuickScan, s.PrimaryActionId);
        Assert.Empty(s.Items);
    }

    [Fact]
    public void Built_in_signatures_only_do_not_lower_the_level()
    {
        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(Healthy() with { ContentSequence = 0, ContentExpiresUtc = null });

        Assert.Equal(ProtectionLevel.Protected, s.Level);
    }

    [Fact]
    public void An_unreachable_service_is_not_running_whatever_else_is_true()
    {
        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(Healthy() with { ServiceReachable = false, ServiceDescription = "installed service", AuditChainValid = false });

        Assert.Equal(ProtectionLevel.NotRunning, s.Level);
        Assert.Equal("Kshatriya is not running", s.Headline);
        Assert.Contains("installed service", s.Detail, StringComparison.Ordinal);
        Assert.Null(s.PrimaryActionId);
        Assert.Empty(s.Items);
    }

    [Fact]
    public void A_starting_service_says_so()
    {
        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(Healthy() with { ServiceReachable = false, ServiceStarting = true });

        Assert.Equal(ProtectionLevel.NotRunning, s.Level);
        Assert.Equal("Kshatriya is starting", s.Headline);
    }

    [Theory]
    [InlineData(DesktopStatusEvaluator.ConfirmedFindingsId)]
    [InlineData(DesktopStatusEvaluator.AuditLogId)]
    [InlineData(DesktopStatusEvaluator.WindowsAntivirusId)]
    public void Serious_problems_need_action(string id)
    {
        DesktopStatusInputs inputs = id switch
        {
            DesktopStatusEvaluator.ConfirmedFindingsId => Healthy() with { UnresolvedConfirmedFindings = 1 },
            DesktopStatusEvaluator.AuditLogId => Healthy() with { AuditChainValid = false },
            _ => Healthy() with { WindowsAntivirus = WindowsAntivirusState.NeedsAttention },
        };

        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(inputs);

        Assert.Equal(ProtectionLevel.ActionNeeded, s.Level);
        StatusItem item = Assert.Single(s.Items);
        Assert.Equal(id, item.Id);
        Assert.False(item.Dismissible);
        Assert.Equal(item.Title, s.Headline);
        Assert.Equal(item.ActionId, s.PrimaryActionId);
    }

    [Fact]
    public void Expired_signatures_and_suspicious_findings_are_recommendations()
    {
        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(Healthy() with { ContentExpired = true, UnresolvedSuspiciousFindings = 2 });

        Assert.Equal(ProtectionLevel.AttentionRecommended, s.Level);
        Assert.Equal("2 things to review", s.Headline);
        Assert.Equal(["findings.suspicious", "signatures.expired"], s.Items.Select(i => i.Id));
        Assert.Equal("2 suspicious items to review", s.Items[0].Title);
    }

    [Fact]
    public void The_most_serious_item_comes_first_and_sets_the_level_and_action()
    {
        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(Healthy() with
        {
            RealTimeEnabled = false,
            UnresolvedSuspiciousFindings = 1,
            WindowsAntivirus = WindowsAntivirusState.NeedsAttention,
        });

        Assert.Equal(ProtectionLevel.ActionNeeded, s.Level);
        Assert.Equal("3 problems need your action", s.Headline);
        Assert.Equal(DesktopStatusEvaluator.WindowsAntivirusId, s.Items[0].Id);
        Assert.Equal(StatusActions.OpenWindowsSecurity, s.PrimaryActionId);
        Assert.True(s.Items.Zip(s.Items.Skip(1)).All(p => p.First.Level >= p.Second.Level));
    }

    [Theory]
    [InlineData(10, false)]
    [InlineData(7, true)]
    [InlineData(0.5, true)]
    public void Signatures_close_to_expiry_get_a_reminder(double daysLeft, bool expected)
    {
        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(Healthy() with { ContentExpiresUtc = s_now.AddDays(daysLeft) });

        Assert.Equal(expected, s.Items.Any(i => i.Id == DesktopStatusEvaluator.SignaturesExpiringId));
    }

    [Fact]
    public void Dismissing_mutes_an_item_without_hiding_it()
    {
        DesktopStatusInputs inputs = Healthy() with
        {
            RealTimeEnabled = false,
            Dismissed = new HashSet<string> { DesktopStatusEvaluator.RealTimeOffId },
        };

        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(inputs);

        Assert.Equal(ProtectionLevel.Protected, s.Level);
        Assert.Empty(s.Items);
        Assert.Equal(DesktopStatusEvaluator.RealTimeOffId, Assert.Single(s.Muted).Id);
        Assert.DoesNotContain("Real-time monitoring is on", s.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Serious_items_cannot_be_dismissed()
    {
        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(Healthy() with
        {
            UnresolvedConfirmedFindings = 3,
            Dismissed = new HashSet<string> { DesktopStatusEvaluator.ConfirmedFindingsId },
        });

        Assert.Equal(ProtectionLevel.ActionNeeded, s.Level);
        Assert.Equal("3 threats need your decision", s.Headline);
        Assert.Empty(s.Muted);
    }

    [Fact]
    public void Access_denied_items_suggest_restarting_as_administrator()
    {
        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(Healthy() with { LastScanAccessDenied = 8 });

        StatusItem item = Assert.Single(s.Items);
        Assert.Equal("8 files could not be scanned", item.Title);
        Assert.Equal(StatusActions.RestartElevated, item.ActionId);
        Assert.True(item.Dismissible);
    }

    [Fact]
    public void Unknown_antivirus_health_says_your_antivirus_and_is_not_a_problem()
    {
        StatusSnapshot s = DesktopStatusEvaluator.Evaluate(Healthy() with { WindowsAntivirus = WindowsAntivirusState.Unknown });

        Assert.Equal(ProtectionLevel.Protected, s.Level);
        Assert.Contains("your antivirus", s.Detail, StringComparison.Ordinal);
    }
}
