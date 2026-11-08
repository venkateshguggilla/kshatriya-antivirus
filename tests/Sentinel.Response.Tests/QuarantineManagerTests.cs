using System.Diagnostics;
using System.Runtime.InteropServices;
using Sentinel.Core;
using Sentinel.Engines.Hash;
using Sentinel.Response;
using Sentinel.Scanning;
using Sentinel.Tests.Shared;

namespace Sentinel.Response.Tests;

public sealed partial class QuarantineManagerTests : IDisposable
{
    private readonly TempDirectory _temp = new();
    private readonly QuarantineManager _manager;
    private readonly Actor _actor = Actor.Current();

    public QuarantineManagerTests()
    {
        _manager = new QuarantineManager(
            QuarantineVault.Open(Path.Combine(_temp.Path, "data", "quarantine"), StorageAccess.CurrentUser),
            AuditLog.Open(Path.Combine(_temp.Path, "data", "audit"), StorageAccess.CurrentUser));
    }

    public void Dispose() => _temp.Dispose();

    [Fact]
    public void Quarantine_removes_the_file_and_restore_brings_it_back_with_mark_of_the_web()
    {
        byte[] content = TestData.BenignBytes(1, 10_000);
        string file = _temp.File(@"files\sample.bin", content);

        QuarantineResult result = _manager.Quarantine(file, _actor, ["Test.Sample"], TestData.Sha256Hex(content), "scan");

        Assert.True(result.Succeeded, result.Message);
        Assert.False(File.Exists(file));
        QuarantineEntry entry = Assert.Single(_manager.List());
        Assert.Equal(file, entry.OriginalPath);
        Assert.Equal(_actor.Sid, entry.ActorSid);

        RestoreResult restore = _manager.Restore(entry.Id, null, _actor);

        Assert.True(restore.Succeeded, restore.Message);
        Assert.Equal(content, File.ReadAllBytes(file));
        Assert.True(restore.MarkOfTheWeb);
        Assert.Contains("ZoneId=3", File.ReadAllText(file + ":Zone.Identifier"), StringComparison.Ordinal);
        Assert.Empty(_manager.List());

        var audit = _manager.Audit.ReadRecent(10);
        Assert.Equal([AuditActions.Restore, AuditActions.Quarantine], audit.Select(a => a.Action));
        Assert.All(audit, a => Assert.Equal(AuditOutcomes.Succeeded, a.Outcome));
        Assert.True(_manager.Audit.Verify().Valid);
    }

    [Fact]
    public void A_file_that_changed_since_the_scan_is_left_alone()
    {
        string file = _temp.File("changed.bin", TestData.BenignBytes(2, 500));

        QuarantineResult result = _manager.Quarantine(file, _actor, ["Test.Sample"], new string('a', 64), "scan");

        Assert.Equal(ActionFailure.Changed, result.Failure);
        Assert.True(File.Exists(file));
        Assert.Empty(_manager.List());
        Assert.Equal(AuditOutcomes.Failed, Assert.Single(_manager.Audit.ReadRecent(10)).Outcome);
    }

    [Fact]
    public void A_file_open_for_writing_elsewhere_is_reported_locked()
    {
        string file = _temp.File("locked.bin", TestData.BenignBytes(3, 500));
        using var writer = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);

        QuarantineResult result = _manager.Quarantine(file, _actor, [], null, "manual");

        Assert.Equal(ActionFailure.Locked, result.Failure);
        Assert.Empty(_manager.List());
    }

    [Fact]
    public void A_running_program_is_left_in_place_and_the_vault_copy_discarded()
    {
        string exe = Path.Combine(_temp.Dir("bin"), "ping-copy.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "PING.EXE"), exe);
        using var process = Process.Start(new ProcessStartInfo(exe, "-n 30 127.0.0.1") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
        try
        {
            QuarantineResult result = _manager.Quarantine(exe, _actor, [], null, "manual");

            Assert.Equal(ActionFailure.InUse, result.Failure);
            Assert.True(File.Exists(exe));
            Assert.Empty(_manager.List());
        }
        finally
        {
            process.Kill();
            process.WaitForExit();
        }
    }

    [Fact]
    public void Read_only_files_can_be_quarantined()
    {
        string file = _temp.File("readonly.bin", TestData.BenignBytes(4, 100));
        File.SetAttributes(file, FileAttributes.ReadOnly);

        QuarantineResult result = _manager.Quarantine(file, _actor, [], null, "manual");

        Assert.True(result.Succeeded, result.Message);
        Assert.False(File.Exists(file));
    }

    [Fact]
    public void Hard_linked_files_are_refused()
    {
        string file = _temp.File("linked.bin", TestData.BenignBytes(5, 100));
        Assert.True(CreateHardLink(Path.Combine(_temp.Path, "second-name.bin"), file, IntPtr.Zero));

        QuarantineResult result = _manager.Quarantine(file, _actor, [], null, "manual");

        Assert.Equal(ActionFailure.HardLinked, result.Failure);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public void Links_and_folders_are_refused()
    {
        string target = _temp.Dir("real");
        string link = Path.Combine(_temp.Path, "junction");
        Assert.True(TempDirectory.TryCreateJunction(link, target));

        Assert.Equal(ActionFailure.NotRegularFile, _manager.Quarantine(link, _actor, [], null, "manual").Failure);
        Assert.Equal(ActionFailure.NotRegularFile, _manager.Quarantine(target, _actor, [], null, "manual").Failure);
        Assert.Equal(ActionFailure.NotRegularFile, _manager.Quarantine(@"\\server\share\x.exe", _actor, [], null, "manual").Failure);
        Assert.Equal(ActionFailure.NotFound, _manager.Quarantine(Path.Combine(_temp.Path, "missing.bin"), _actor, [], null, "manual").Failure);
        Assert.True(Directory.Exists(target));
    }

    [Fact]
    public void Files_over_the_limit_are_refused()
    {
        var small = new QuarantineManager(_manager.Vault, _manager.Audit, maxFileBytes: 10);
        string file = _temp.File("big.bin", new byte[11]);

        Assert.Equal(ActionFailure.TooLarge, small.Quarantine(file, _actor, [], null, "manual").Failure);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public void Restore_never_overwrites_and_can_use_another_location()
    {
        string file = _temp.File("again.bin", TestData.BenignBytes(6, 300));
        string id = _manager.Quarantine(file, _actor, [], null, "manual").Entry!.Id;
        File.WriteAllText(file, "a new file with the same name");

        RestoreResult blocked = _manager.Restore(id, null, _actor);
        string elsewhere = Path.Combine(_temp.Path, "restored.bin");
        RestoreResult moved = _manager.Restore(id, elsewhere, _actor);

        Assert.Equal(RestoreFailure.TargetExists, blocked.Failure);
        Assert.Equal("a new file with the same name", File.ReadAllText(file));
        Assert.True(moved.Succeeded, moved.Message);
        Assert.Equal(TestData.BenignBytes(6, 300), File.ReadAllBytes(elsewhere));
    }

    [Fact]
    public void A_corrupt_vault_item_is_not_restored_and_leaves_no_partial_file()
    {
        string file = _temp.File("corrupt.bin", TestData.BenignBytes(7, 3000));
        QuarantineEntry entry = _manager.Quarantine(file, _actor, [], null, "manual").Entry!;
        string blob = Path.Combine(_manager.Vault.Directory, entry.Id + ".bin");
        byte[] bytes = File.ReadAllBytes(blob);
        bytes[100] ^= 0xFF;
        File.WriteAllBytes(blob, bytes);

        RestoreResult result = _manager.Restore(entry.Id, null, _actor);

        Assert.Equal(RestoreFailure.IntegrityError, result.Failure);
        Assert.False(File.Exists(file));
        Assert.NotNull(_manager.Get(entry.Id));
    }

    [Fact]
    public void Delete_removes_an_item_permanently()
    {
        string file = _temp.File("delete.bin", TestData.BenignBytes(8, 300));
        string id = _manager.Quarantine(file, _actor, [], null, "manual").Entry!.Id;

        Assert.True(_manager.Delete(id, _actor));
        Assert.False(_manager.Delete(id, _actor));
        Assert.Empty(_manager.List());
        Assert.Equal(RestoreFailure.NotFound, _manager.Restore(id, null, _actor).Failure);
    }

    [Fact]
    public async Task Scan_with_responder_quarantines_high_confidence_detections_only()
    {
        byte[] bad = TestData.BenignBytes(9, 2048);
        byte[] pua = TestData.BenignBytes(10, 2048);
        var db = HashSignatureDatabase.Parse(TestData.HashDb((TestData.Sha256Hex(bad), "Test.Bad", "test"), (TestData.Sha256Hex(pua), "Test.Pua", "pua")));
        string badFile = _temp.File(@"scan\bad.bin", bad);
        string puaFile = _temp.File(@"scan\pua.bin", pua);
        _temp.File(@"scan\clean.bin", TestData.BenignBytes(11, 100));

        var runner = new ScanRunner([HashEngine.CreateDefault(db)], new ScanOptions { Responder = new QuarantineResponder(_manager, _actor) });
        ScanReport report = await runner.ScanPathsAsync([Path.Combine(_temp.Path, "scan")]);

        Assert.Equal(1, report.Summary.Quarantined);
        Assert.Equal(0, report.Summary.QuarantineFailed);
        ScanItemResult badItem = report.Items.Single(i => i.Path == badFile);
        Assert.True(badItem.Action!.Succeeded);
        Assert.Null(report.Items.Single(i => i.Path == puaFile).Action);
        Assert.False(File.Exists(badFile));
        Assert.True(File.Exists(puaFile));

        ScanReport roundTrip = ScanReportJson.Read(ScanReportJson.Write(report, "test"));
        Assert.Equal(badItem.Action, roundTrip.Items.Single(i => i.Path == badFile).Action);
        Assert.Equal(1, roundTrip.Summary.Quarantined);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateHardLinkW", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateHardLink(string newName, string existing, IntPtr reserved);
}
