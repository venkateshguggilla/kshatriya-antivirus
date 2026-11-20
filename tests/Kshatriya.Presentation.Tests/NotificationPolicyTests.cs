using Kshatriya.Presentation;

namespace Kshatriya.Presentation.Tests;

public class NotificationPolicyTests
{
    private static readonly NotificationPreferences s_allOff = new() { ScanResults = false, Updates = false, ExternalDrives = false };

    [Theory]
    [InlineData(NotificationCategory.BackgroundFinding)]
    [InlineData(NotificationCategory.ServiceStopped)]
    [InlineData(NotificationCategory.AuditFailure)]
    public void Critical_notifications_are_always_shown(NotificationCategory category)
    {
        Assert.Equal(NotificationImportance.Critical, NotificationPolicy.ImportanceOf(category));
        Assert.True(NotificationPolicy.ShouldNotify(category, s_allOff, appInForeground: true));
    }

    [Theory]
    [InlineData(NotificationCategory.ScanFinished)]
    [InlineData(NotificationCategory.UpdateInstalled)]
    [InlineData(NotificationCategory.ExternalDrive)]
    public void Informational_notifications_can_be_turned_off(NotificationCategory category)
    {
        Assert.Equal(NotificationImportance.Informational, NotificationPolicy.ImportanceOf(category));
        Assert.False(NotificationPolicy.ShouldNotify(category, s_allOff, appInForeground: false));
        Assert.True(NotificationPolicy.ShouldNotify(category, new NotificationPreferences(), appInForeground: false));
    }

    [Fact]
    public void A_finished_scan_is_not_notified_while_its_results_are_on_screen()
    {
        Assert.False(NotificationPolicy.ShouldNotify(NotificationCategory.ScanFinished, new NotificationPreferences(), appInForeground: true));
    }
}
