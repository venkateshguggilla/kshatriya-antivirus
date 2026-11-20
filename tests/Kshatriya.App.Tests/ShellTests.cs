using Kshatriya.App.ViewModels;

namespace Kshatriya.App.Tests;

/// <summary>The navigation and pages introduced by ADR 0021, slice 2.</summary>
public class ShellTests
{
    [Fact]
    public async Task Protection_lists_each_layer_and_the_windows_security_state()
    {
        var host = new FakeHost();
        var page = new ProtectionViewModel(new FakeGateway(), host)
        {
            AntivirusSource = () => Services.AntivirusHealth.Good,
            FolderAccessSource = () => 0,
        };

        await page.RefreshCommand.ExecuteAsync(null);

        Assert.Contains(page.Layers, r => r.Label == "Real-time file monitoring" && r.State == "On" && r.Tone == Tone.Success);
        Assert.Contains(page.Layers, r => r.Label == "Ransomware behaviour" && r.State == "Off" && r.Tone == Tone.Neutral);
        Assert.Contains(page.Layers, r => r.Label == "Scheduled scans" && r.State == "1 active");
        Assert.Contains(page.Windows, r => r.Label == "Windows antivirus" && r.State == "On");
        Assert.Contains(page.Windows, r => r.Label == "Controlled folder access" && r.State == "Off" && r.Tone == Tone.Neutral);

        page.OpenWindowsSecurityCommand.Execute(null);
        page.SetUpBrowserExtensionCommand.Execute(null);
        Assert.Equal(1, host.WindowsSecurityOpened);
        Assert.Equal(1, host.BrowserExtensionOpened);
    }

    [Theory]
    [InlineData("off", "Off", Tone.Neutral)]
    [InlineData("on", "On", Tone.Success)]
    [InlineData("unavailable: needs administrator rights", "Unavailable", Tone.Caution)]
    [InlineData("blocking 3 address range(s)", "On", Tone.Success)]
    public void Service_states_read_as_words_and_tones(string serviceState, string state, Tone tone)
    {
        ProtectionRow row = ProtectionViewModel.Layer(Glyphs.Sync, "Network protection", "Blocks listed addresses.", serviceState);

        Assert.Equal(state, row.State);
        Assert.Equal(tone, row.Tone);
    }

    [Fact]
    public async Task Updates_shows_the_installed_update_and_installs_a_chosen_package()
    {
        var gateway = new FakeGateway();
        var dialogs = new FakeDialogs { UpdatePackage = @"C:\Users\alice\Downloads\content-43.kstu" };
        var page = new UpdatesViewModel(gateway, dialogs);

        await page.RefreshCommand.ExecuteAsync(null);
        Assert.Equal("Update 7 (stable)", page.Installed);
        Assert.Equal(Tone.Caution, page.Tone); // the fake update has expired
        Assert.Single(page.Engines);

        await page.ImportCommand.ExecuteAsync(null);
        Assert.Equal(@"C:\Users\alice\Downloads\content-43.kstu", gateway.LastImport);
        Assert.False(page.IsError);
        Assert.StartsWith("Update 43 is installed", page.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cancelling_the_package_picker_installs_nothing()
    {
        var gateway = new FakeGateway();
        var page = new UpdatesViewModel(gateway, new FakeDialogs());

        await page.ImportCommand.ExecuteAsync(null);

        Assert.Null(gateway.LastImport);
    }

    [Fact]
    public void Settings_change_the_users_preferences()
    {
        var settings = new InMemorySettings();
        var main = new MainViewModel(new FakeGateway(), new FakeDialogs(), new FakeHost(), settings);
        var changed = new List<string?>();
        main.Settings.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        main.Settings.Notifications = false;
        main.Settings.ScanExternalDrives = false;

        Assert.False(settings.Notifications);
        Assert.False(settings.ScanExternalDrives);
        Assert.Equal(["Notifications", "ScanExternalDrives"], changed);
        Assert.Same(main.Exclusions, main.Settings.Exclusions);
    }

    [Fact]
    public void A_notification_click_opens_history_on_its_findings()
    {
        var main = new MainViewModel(new FakeGateway(), new FakeDialogs(), new FakeHost());
        main.History.Selected = main.Quarantine;

        main.ShowDetections();

        Assert.Same(main.History, main.Current);
        Assert.Same(main.Detections, main.History.Selected);
    }

    [Fact]
    public void A_footer_page_stays_current_when_the_top_list_reports_no_selection()
    {
        var main = new MainViewModel(new FakeGateway(), new FakeDialogs(), new FakeHost());

        main.Current = main.Settings;
        main.Current = null!; // what a navigation list does when the current page is not one of its items

        Assert.Same(main.Settings, main.Current);
    }

    [Fact]
    public async Task A_running_scan_marks_the_scan_page_as_active()
    {
        var gateway = new FakeGateway
        {
            ScanDelay = TimeSpan.FromMilliseconds(200),
            NextReport = new Core.ScanReport
            {
                Targets = [@"C:\Users\alice\Downloads"],
                StartedUtc = DateTimeOffset.UtcNow,
                FinishedUtc = DateTimeOffset.UtcNow,
                Engines = [],
                Summary = new Core.ScanSummary { ItemsSeen = 1, FilesScanned = 1 },
                Items = [],
            },
        };
        var scan = new ScanViewModel(gateway, new FakeDialogs());
        scan.AddTargets([@"C:\Users\alice\Downloads"]);

        Task running = scan.StartCommand.ExecuteAsync(null);
        Assert.True(scan.HasActivity);
        await running;

        Assert.False(scan.HasActivity);
    }
}
