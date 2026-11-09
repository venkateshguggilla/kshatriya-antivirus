using System.Diagnostics;
using System.Security.Cryptography;
using Kshatriya.Core;
using Kshatriya.Service.RealTime;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Service.Tests;

public class RansomwareTests
{
    private sealed class ManualClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 11, 8, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static RansomwareDetector Detector(ManualClock clock, Func<string, double?> entropy, int threshold = 10, IReadOnlyList<string>? canaries = null) =>
        new(new BehaviourOptions { Enabled = true, Threshold = threshold, Window = TimeSpan.FromSeconds(30), CanaryFolders = canaries ?? [] }, clock, entropy);

    [Fact]
    public void Mass_rewrites_of_existing_files_with_encrypted_looking_content_raise_one_alert()
    {
        var clock = new ManualClock();
        RansomwareDetector detector = Detector(clock, _ => 7.98);
        detector.OnProcessStart(@"C:\Users\alice\Downloads\invoice.exe", null);
        for (int i = 0; i < 12; i++)
        {
            detector.OnFileEvent($@"C:\Users\alice\Documents\file{i}.docx", FileEventKind.Changed);
        }

        BehaviourAlert alert = Assert.Single(detector.Collect());
        Assert.Equal(RansomwareDetector.MassModification, alert.Name);
        Assert.Equal(@"C:\Users\alice\Documents", alert.Path);
        Assert.Contains(@"invoice.exe", alert.Detail, StringComparison.Ordinal);
        Assert.Empty(detector.Collect());
    }

    [Fact]
    public void Renames_to_unfamiliar_extensions_confirm_without_reading_content()
    {
        var clock = new ManualClock();
        RansomwareDetector detector = Detector(clock, _ => null);
        for (int i = 0; i < 12; i++)
        {
            detector.OnFileEvent($@"D:\Photos\img{i}.jpg.locked9", FileEventKind.Renamed, $@"D:\Photos\img{i}.jpg");
        }

        Assert.Equal(RansomwareDetector.MassModification, Assert.Single(detector.Collect()).Name);
    }

    [Fact]
    public void Unzipping_downloading_or_editing_with_normal_content_raise_nothing()
    {
        var clock = new ManualClock();
        RansomwareDetector detector = Detector(clock, _ => 7.99);
        for (int i = 0; i < 50; i++)
        {
            // New files (an archive being extracted): created then written.
            string path = $@"C:\Users\alice\Downloads\archive\part{i}.jpg";
            detector.OnFileEvent(path, FileEventKind.Created);
            detector.OnFileEvent(path, FileEventKind.Changed);
        }

        Assert.Empty(detector.Collect());

        RansomwareDetector editing = Detector(clock, _ => 4.5);
        for (int i = 0; i < 50; i++)
        {
            editing.OnFileEvent($@"C:\src\project\file{i}.cs", FileEventKind.Changed);
        }

        Assert.Empty(editing.Collect());
    }

    [Fact]
    public void Events_outside_the_window_do_not_accumulate()
    {
        var clock = new ManualClock();
        RansomwareDetector detector = Detector(clock, _ => 7.99);
        for (int i = 0; i < 12; i++)
        {
            detector.OnFileEvent($@"C:\data\f{i}.txt", FileEventKind.Changed);
            clock.Now += TimeSpan.FromSeconds(5);
        }

        Assert.Empty(detector.Collect());
    }

    [Theory]
    [InlineData("README_TO_DECRYPT_FILES.txt", true)]
    [InlineData("HOW_TO_RECOVER_FILES.html", true)]
    [InlineData("restore-files-help.hta", true)]
    [InlineData("README.txt", false)]
    [InlineData("decrypt_tool.exe", false)]
    [InlineData("recovery-plan.docx", false)]
    public void Ransom_note_names(string name, bool expected) => Assert.Equal(expected, RansomwareDetector.LooksLikeRansomNote(name));

    [Theory]
    [InlineData("vssadmin.exe Delete Shadows /All /Quiet", true)]
    [InlineData("wmic shadowcopy delete", true)]
    [InlineData("bcdedit /set {default} recoveryenabled No", true)]
    [InlineData("wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0", true)]
    [InlineData("powershell -c \"Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }\"", true)]
    [InlineData("vssadmin list shadows", false)]
    [InlineData("bcdedit /enum", false)]
    public void Recovery_tampering_commands(string command, bool expected) => Assert.Equal(expected, RansomwareDetector.IsRecoveryTampering(command));

    [Fact]
    public void Ransom_notes_and_recovery_tampering_raise_alerts_once_per_cooldown()
    {
        var clock = new ManualClock();
        RansomwareDetector detector = Detector(clock, _ => null);
        detector.OnFileEvent(@"C:\Users\bob\Desktop\HOW_TO_DECRYPT_FILES.txt", FileEventKind.Created);
        detector.OnFileEvent(@"C:\Users\bob\Desktop\HOW_TO_DECRYPT_FILES (2).txt", FileEventKind.Created);
        detector.OnProcessStart(@"C:\Windows\System32\vssadmin.exe", "vssadmin delete shadows /all /quiet");

        var alerts = detector.Collect();
        Assert.Equal([RansomwareDetector.RansomNote, RansomwareDetector.RecoveryTampering], alerts.Select(a => a.Name));
    }

    [Fact]
    public void Entropy_separates_text_from_random_data()
    {
        Assert.True(RansomwareDetector.Entropy("hello hello hello hello "u8) < 3);
        Assert.True(RansomwareDetector.Entropy(RandomNumberGenerator.GetBytes(4096)) > 7.8);
    }

    [Fact]
    public async Task Touching_a_decoy_file_raises_an_alert_and_the_decoy_is_recreated()
    {
        using var watched = new TempDirectory();
        string docs = watched.Dir("Documents");
        var settings = new ServiceSettings
        {
            RealTime = new RealTimeOptions
            {
                Enabled = true,
                Paths = [watched.Path],
                Processes = false,
                RemovableMedia = false,
                Behaviour = new BehaviourOptions { Enabled = true, CanaryFolders = [docs] },
            },
        };
        await using RunningService service = await RunningService.StartAsync(settings);
        string canary = Path.Combine(docs, RansomwareDetector.CanaryFileName);
        var clock = Stopwatch.StartNew();
        while (!File.Exists(canary) && clock.Elapsed < TimeSpan.FromSeconds(10))
        {
            await Task.Delay(100);
        }

        Assert.True(File.Exists(canary), "The decoy was not created.");
        Assert.True(File.GetAttributes(canary).HasFlag(FileAttributes.Hidden));

        File.SetAttributes(canary, FileAttributes.Normal);
        File.WriteAllBytes(canary, RandomNumberGenerator.GetBytes(4096));

        DetectionRecord? alert = null;
        while (alert is null && clock.Elapsed < TimeSpan.FromSeconds(25))
        {
            alert = service.Core.History.Recent(20).FirstOrDefault(r => r.Names.Contains(RansomwareDetector.CanaryTouched));
            await Task.Delay(100);
        }

        Assert.NotNull(alert);
        Assert.Equal(ScanStatus.Suspicious, alert!.Status);
        Assert.Equal("behaviour", alert.Source);
        Assert.Contains("no automatic action", alert.Action, StringComparison.Ordinal);
        Assert.Equal(1, service.Core.RealTime!.Stats.BehaviourAlerts);

        File.Delete(canary);
        while (!File.Exists(canary) && clock.Elapsed < TimeSpan.FromSeconds(35))
        {
            await Task.Delay(100);
        }

        Assert.True(File.Exists(canary), "The decoy was not re-created after it was deleted.");
    }

    [Fact]
    public void Canary_folders_must_be_inside_watched_paths()
    {
        Assert.Throws<FormatException>(() => ServiceSettings.Parse("""{ "schemaVersion": 1, "realTime": { "paths": ["C:\\Users"], "ransomware": { "canaryFolders": ["D:\\Data"] } } }"""));
        Assert.Throws<FormatException>(() => ServiceSettings.Parse("""{ "schemaVersion": 1, "realTime": { "ransomware": { "threshold": 1 } } }"""));
        var options = ServiceSettings.Parse("""{ "schemaVersion": 1, "realTime": { "paths": ["C:\\Users"], "ransomware": { "canaryFolders": ["C:\\Users\\alice\\Documents"] } } }""").RealTime.Behaviour;
        Assert.True(options.Enabled);
        Assert.Single(options.CanaryFolders);
    }
}
